// qck - type something, find something (quick)!
const c = @cImport({
    @cInclude("SDL2/SDL.h");
    @cInclude("SDL2/SDL_ttf.h");
});
const tracy = @import("./zig-tracy/src/lib.zig");
const std = @import("std");

// commands wishlist:
// - launch with logs (default launcher, use systemd-run --user --unit=name name?)
// - switch to window
// - open url
// - open shortcuts (logs -> ..., tickets)
// - history (could be another command + some special keybindings)
// - hex (and other decodes, terminal escapes?)

// TODO: implement suggestions by program
// TODO: implement choosing from suggestions
// TODO: implement searching through results
// TODO: only output if something was found (man page exists -> output, hex decodable -> output, search results -> output, ...)

const ProcessWithOutput = struct {
    process: *std.ChildProcess,
    stdout_buf: std.ArrayList(u8),
    stderr_buf: std.ArrayList(u8),

    poll_fds: [2]std.os.pollfd,
    dead_fds: usize = 0,
    max_output_bytes: usize,

    cleanup_done: bool = false,

    fn spawn(allocator: *std.mem.Allocator, argv: []const []const u8, max_output_bytes: usize) !ProcessWithOutput {
        const child = try std.ChildProcess.init(argv, allocator);
        child.expand_arg0 = std.ChildProcess.Arg0Expand.expand;
        child.stdin_behavior = std.ChildProcess.StdIo.Ignore;
        child.stdout_behavior = std.ChildProcess.StdIo.Pipe;
        child.stderr_behavior = std.ChildProcess.StdIo.Pipe;
        try child.spawn();

        return ProcessWithOutput{
            .process = child,
            .stdout_buf = std.ArrayList(u8).init(allocator),
            .stderr_buf = std.ArrayList(u8).init(allocator),
            .poll_fds = [_]std.os.pollfd{
                .{ .fd = child.stdout.?.handle, .events = std.os.POLL.IN, .revents = undefined },
                .{ .fd = child.stderr.?.handle, .events = std.os.POLL.IN, .revents = undefined },
            },
            .dead_fds = 0,
            .max_output_bytes = max_output_bytes,
        };
    }

    fn is_running(self: *ProcessWithOutput) bool {
        if (self.process.term) |_| {
            return false;
        } else {
            return true;
        }
    }

    fn stdout(self: *ProcessWithOutput) []u8 {
        return self.stdout_buf.items;
    }

    fn stderr(self: *ProcessWithOutput) []u8 {
        return self.stderr_buf.items;
    }

    // poll: https://github.com/ziglang/zig/blob/master/lib/std/child_process.zig#L206
    //   basically do one iteration with no blocking each time it runs and thus get the output incrementally?
    fn poll(self: *ProcessWithOutput) !void {
        if (!self.is_running()) {
            return;
        }

        // We ask for ensureTotalCapacity with this much extra space. This has more of an
        // effect on small reads because once the reads start to get larger the amount
        // of space an ArrayList will allocate grows exponentially.
        const bump_amt = 512;

        const err_mask = std.os.POLL.ERR | std.os.POLL.NVAL | std.os.POLL.HUP;

        if (self.dead_fds >= self.poll_fds.len) {
            return;
        }

        const events = try std.os.poll(&self.poll_fds, 0);
        if (events == 0) {
            return;
        }

        var remove_stdout = false;
        var remove_stderr = false;
        // Try reading whatever is available before checking the error
        // conditions.
        // It's still pstd.ossible to read after a POLL.HUP is received, always
        // check if there's some data waiting to be read first.
        if (self.poll_fds[0].revents & std.os.POLL.IN != 0) {
            // stdout is ready.
            const new_capacity = std.math.min(self.stdout_buf.items.len + bump_amt, self.max_output_bytes);
            try self.stdout_buf.ensureTotalCapacity(new_capacity);
            const buf = self.stdout_buf.unusedCapacitySlice();
            if (buf.len == 0) return error.StdoutStreamTooLong;
            const nread = try std.os.read(self.poll_fds[0].fd, buf);
            self.stdout_buf.items.len += nread;

            std.debug.print("read {d} bytes ({d} total, {d} max)\n", .{ nread, self.stdout_buf.items.len, self.max_output_bytes });

            // Remove the fd when the EOF condition is met.
            //remove_stdout = nread == 0;
        } else {
            remove_stdout = (self.poll_fds[0].revents & err_mask) != 0;
        }

        if (self.poll_fds[1].revents & std.os.POLL.IN != 0) {
            // stderr is ready.
            const new_capacity = std.math.min(self.stderr_buf.items.len + bump_amt, self.max_output_bytes);
            try self.stderr_buf.ensureTotalCapacity(new_capacity);
            const buf = self.stderr_buf.unusedCapacitySlice();
            if (buf.len == 0) return error.StderrStreamTooLong;
            const nread = try std.os.read(self.poll_fds[1].fd, buf);
            self.stderr_buf.items.len += nread;

            // Remove the fd when the EOF condition is met.
            //remove_stderr = nread == 0;
        } else {
            remove_stderr = self.poll_fds[1].revents & err_mask != 0;
        }

        // Exclude the fds that signaled an error.
        if (remove_stdout) {
            std.debug.print("remove stdout\n", .{});
            self.poll_fds[0].fd = -1;
            self.dead_fds += 1;
        }
        if (remove_stderr) {
            std.debug.print("remove stderr\n", .{});
            self.poll_fds[1].fd = -1;
            self.dead_fds += 1;
        }
    }

    fn deinit(self: *ProcessWithOutput) !void {
        self.stdout_buf.deinit();
        self.stderr_buf.deinit();
        if (self.is_running()) {
            _ = try self.process.kill();
        }
        self.process.deinit();
    }
};

const Runner = struct {
    name: []const u8,
    run_always: bool,
    select: bool = false,
    process: ?ProcessWithOutput = null,

    toArgv: fn (cmd: []const u8, is_confirmed: bool, selection: []const u8) []const []const u8,
    isActive: fn (cmd: []const u8) bool,

    fn run(self: *Runner, allocator: *std.mem.Allocator, cmd: []const u8, is_confirmed: bool, selection: []const u8) !bool {
        if (!self.run_always and !is_confirmed) {
            return false;
        }

        if (!self.isActive(cmd)) {
            return false;
        }

        tracy.message(self.name);

        // stop already running command, restart with new cmd
        if (self.process) |*process| {
            if (process.is_running()) {
                _ = process.process.kill() catch |err| switch (err) {
                    error.FileNotFound => {
                        // TODO: report error to user
                        std.debug.print("killing: {s}\n", .{err});
                    },
                    else => {
                        return err;
                    },
                };
                try process.deinit();
            }
        }

        const argv = self.toArgv(cmd, is_confirmed, selection);
        std.debug.print("{s} -> {s}\n", .{ cmd, argv });

        const trace_spawn = tracy.trace(@src(), "spawn");
        self.process = try ProcessWithOutput.spawn(allocator, argv, 1024 * 1024);
        trace_spawn.end();

        return true;
    }

    fn output(self: *Runner) ![]const u8 {
        if (self.process) |*process| {
            process.poll() catch |err| switch (err) {
                error.StdoutStreamTooLong => {
                    std.debug.print("too much output, killing\n", .{});
                    _ = try process.process.kill();
                },
                else => {
                    return err;
                },
            };
            //std.debug.print("{d} ({d})\n", .{ process.stdout_buf.items.len, process.stderr_buf.items.len });
            if (process.stdout_buf.items.len > 0) {
                return process.stdout();
            } else if (process.stderr_buf.items.len > 0) {
                return process.stderr();
            }
        }

        return "<no output>";
    }

    fn deinit(self: *Runner) !void {
        if (self.process) |*process| {
            try process.deinit();
        }
    }
};

const Config = struct {
    var searchDirectories: []const []const u8 = undefined;
    var searchDirectoriesString: []const u8 = undefined;
};

var cmd_buf: [1000]u8 = undefined;
var argv_buf: [100][]const u8 = undefined;

const GoDocRunner = struct {
    fn init() Runner {
        return Runner{ .name = "go doc", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > 3 and std.mem.startsWith(u8, cmd, "go ");
    }

    fn toArgv(cmd: []const u8, is_confirmed: bool, _: []const u8) []const []const u8 {
        if (is_confirmed) {
            const prefix = "xdg-open https://pkg.go.dev/";
            _ = std.fmt.bufPrint(&cmd_buf, "{s}{s} && swaymsg '[app_id=\"firefox\"]' focus\x00", .{ prefix, cmd["go ".len..] }) catch "???";
            if (std.mem.indexOf(u8, cmd_buf[prefix.len..], ".")) |pos| {
                cmd_buf[prefix.len + pos] = '#';
            }
            return &[_][]const u8{ "bash", "-c", &cmd_buf };
        } else {
            // NO idea why bufPrint is required, but without `cmd` will just be some random bit of memory, which is rude.
            _ = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{cmd["go ".len..]}) catch "???";
            return &[_][]const u8{ "go", "doc", &cmd_buf };
        }
    }
};

const PythonHelpRunner = struct {
    fn init() Runner {
        return Runner{ .name = "python docs", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > 3 and std.mem.startsWith(u8, cmd, "py ");
    }

    fn toArgv(cmd: []const u8, is_confirmed: bool, _: []const u8) []const []const u8 {
        if (is_confirmed) {
            const prefix = "xdg-open https://docs.python.org/3/library/";
            if (std.mem.containsAtLeast(u8, cmd, 1, ".")) {
                _ = std.fmt.bufPrint(&cmd_buf, "{s}{s}.html#{s} && swaymsg '[app_id=\"firefox\"]' focus\x00", .{ prefix, std.mem.sliceTo(cmd["py ".len..], '.'), cmd["py ".len..] }) catch "???";
            } else {
                _ = std.fmt.bufPrint(&cmd_buf, "{s}{s}.html && swaymsg '[app_id=\"firefox\"]' focus\x00", .{ prefix, cmd["py ".len..] }) catch "???";
            }
            return &[_][]const u8{ "bash", "-c", &cmd_buf };
        } else {
            _ = std.fmt.bufPrint(&cmd_buf, "import {s}; help({s});\x00", .{ std.mem.sliceTo(cmd["py ".len..], '.'), cmd["py ".len..] }) catch "???";
            return &[_][]const u8{ "python", "-c", &cmd_buf };
        }
    }
};

const PythonRunner = struct {
    fn init() Runner {
        return Runner{ .name = "python run", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > 3 and std.mem.startsWith(u8, cmd, "py! ");
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "print({s})\x00", .{cmd["py! ".len..]}) catch "???";
        return &[_][]const u8{ "python", "-c", &cmd_buf };
    }
};

const RubyHelpRunner = struct {
    fn init() Runner {
        return Runner{ .name = "ruby docs", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > 3 and std.mem.startsWith(u8, cmd, "rb ");
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{cmd["rb ".len..]}) catch "???";
        return &[_][]const u8{ "ri", &cmd_buf };
    }
};

const RubyRunner = struct {
    fn init() Runner {
        return Runner{ .name = "ruby run", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > 3 and std.mem.startsWith(u8, cmd, "rb! ");
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "puts({s})\x00", .{cmd["rb! ".len..]}) catch "???";
        return &[_][]const u8{ "ruby", "-e", &cmd_buf };
    }
};

const HelpRunner = struct {
    fn init() Runner {
        return Runner{ .name = "--help", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return std.mem.endsWith(u8, cmd, " --help");
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{cmd[0 .. cmd.len - " --help".len]}) catch "???";
        return &[_][]const u8{ &cmd_buf, "--help" };
    }
};

const ManPageRunner = struct {
    fn init() Runner {
        return Runner{ .name = "man page", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > "man ".len + 2 and std.mem.startsWith(u8, cmd, "man ");
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "MAN_KEEP_FORMATTING=yesplease man {s}\x00", .{cmd["man ".len..]}) catch "???";
        return &[_][]const u8{ "bash", "-c", &cmd_buf };
    }
};

const SearchRunner = struct {
    fn init() Runner {
        return Runner{ .name = "search", .run_always = true, .select = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > "s ".len and std.mem.startsWith(u8, cmd, "s ");
    }

    // TODO: confirm should open at position
    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{cmd["s ".len..]}) catch "???";
        argv_buf[0] = "ag";
        argv_buf[1] = "--color";
        argv_buf[2] = "--unrestricted";
        argv_buf[3] = &cmd_buf;
        for (Config.searchDirectories) |dir, i| {
            argv_buf[4 + i] = dir;
        }
        return argv_buf[0 .. 4 + Config.searchDirectories.len];
    }
};

// TODO: confirm should open
const FileRunner = struct {
    fn init() Runner {
        return Runner{ .name = "file", .run_always = true, .select = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > "file ".len and std.mem.startsWith(u8, cmd, "file ");
    }

    fn toArgv(cmd: []const u8, is_confirmed: bool, selection: []const u8) []const []const u8 {
        if (is_confirmed) {
            _ = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{selection}) catch "???";
            return &[_][]const u8{ "sushi", &cmd_buf };
        }
        // FIXME: replace with choice + selection whenever that is implemented
        _ = std.fmt.bufPrint(&cmd_buf, "find {s} -type f -path '*{s}*' -or -name '*{s}*'\x00", .{ Config.searchDirectoriesString, cmd["file ".len..], cmd["file ".len..] }) catch "???";
        return &[_][]const u8{ "bash", "-c", &cmd_buf };
    }
};

const FirefoxHistoryRunner = struct {
    fn init() Runner {
        return Runner{ .name = "ff", .run_always = true, .select = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > "ff ".len and std.mem.startsWith(u8, cmd, "ff ");
    }

    // TODO: confirm should open in browser
    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        // FIXME: replace with choice + selection whenever that is implemented
        const cmd_fmt =
            \\find ~/.mozilla -type f -name 'places.sqlite' -exec bash -c 'cp {{}} /tmp && sqlite3 /tmp/places.sqlite "select title, url from moz_places where url like \"%{s}%\" or url like \"%{s}%\" order by last_visit_date desc limit 100;" | tee /tmp/places-result; [ "$(wc -l < /tmp/places-result)" = "1" ] && xdg-open $(head -n1 /tmp/places-result | cut -d\| -f2) && test -f /usr/bin/swaymsg && swaymsg '[app_id="firefox"]' focus &> /dev/null; rm /tmp/places.sqlite;' \;
        ++ "\x00";

        _ = std.fmt.bufPrint(&cmd_buf, cmd_fmt, .{ cmd["ff ".len..], cmd["ff ".len..] }) catch "???";
        return &[_][]const u8{ "bash", "-c", &cmd_buf };
    }
};

// TODO: window switcher (do i even want that?)

const LaunchRunner = struct {
    fn init() Runner {
        return Runner{ .name = "launch", .run_always = true, .select = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return !std.mem.containsAtLeast(u8, cmd, 1, " ") and (cmd.len > 0 or std.mem.startsWith(u8, cmd, "launch "));
    }

    fn toArgv(cmd: []const u8, is_confirmed: bool, selection: []const u8) []const []const u8 {
        if (is_confirmed) {
            // TODO: run with bash and no logs if spaces in command
            _ = std.fmt.bufPrint(&cmd_buf, "systemctl --user stop app-$(basename $(echo '{s}' | sed 's/\\x1b\\[[0-9;]*[a-zA-Z]//g')); systemd-run --user --remain-after-exit --unit=app-$(basename $(echo '{s}' | sed 's/\\x1b\\[[0-9;]*[a-zA-Z]//g')) $(echo '{s}' | sed 's/\\x1b\\[[0-9;]*[a-zA-Z]//g')\x00", .{ selection, selection, selection }) catch "???";
            return &[_][]const u8{ "bash", "-c", &cmd_buf };
        }

        const match = if (std.mem.startsWith(u8, cmd, "launch"))
            cmd["launch".len..]
        else
            cmd;

        // NO idea why bufPrint is required, but without `cmd` will just be some random bit of memory, which is rude.
        _ = std.fmt.bufPrint(&cmd_buf, "find $(echo $PATH | tr ':' ' ') -type f | sort | grep --color=always '{s}'\x00", .{match}) catch "???";
        return &[_][]const u8{ "bash", "-c", &cmd_buf };
    }
};

const LogsRunner = struct {
    fn init() Runner {
        return Runner{ .name = "logs", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return std.mem.startsWith(u8, cmd, "logs");
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        if (cmd.len <= "logs ".len) {
            return &[_][]const u8{ "bash", "-c", "SYSTEMD_COLORS=yes journalctl -b" };
        }

        const service = cmd["logs ".len..];
        _ = std.fmt.bufPrint(&cmd_buf, "export SYSTEMD_COLORS=yes; (systemctl cat {s} &> /dev/null && journalctl -u {s} -f) || (systemctl cat --user app-{s} &> /dev/null && journalctl --user -u app-{s} -f) || (systemctl cat --user {s} &> /dev/null && journalctl --user -u {s} -f) || echo \"no logs for '{s}'\"\x00", .{ service, service, service, service, service, service, service }) catch "???";
        return &[_][]const u8{ "bash", "-c", &cmd_buf };
    }
};

const QalcRunner = struct {
    fn init() Runner {
        return Runner{ .name = "qalc", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len > 0 and std.ascii.isDigit(cmd[0]);
    }

    fn toArgv(cmd: []const u8, _: bool, _: []const u8) []const []const u8 {
        _ = std.fmt.bufPrint(&cmd_buf, "{s}\x00", .{cmd}) catch "???";
        return &[_][]const u8{ "qalc", "-terse", &cmd_buf };
    }
};

const SelfDocRunner = struct {
    fn init() Runner {
        return Runner{ .name = "usage", .run_always = true, .toArgv = toArgv, .isActive = isActive };
    }

    fn isActive(cmd: []const u8) bool {
        return cmd.len == 0;
    }

    fn toArgv(_: []const u8, _: bool, _: []const u8) []const []const u8 {
        const print_help =
            "cat <<EOF\n" ++
            "\x1b[37mqck - type something, find something (quick)!\x1b[0m\n" ++
            "\n" ++
            "\x1b[37mcommands:\x1b[0m\n" ++
            "\n" ++
            "  s\x1b[37m <search>       -- search for <search> in SEARCH_DIRS\x1b[0m\n" ++
            "  file \x1b[37m<name>      -- search for file matching <name> and preview it\x1b[0m\n" ++
            "\n" ++
            "  man\x1b[37m <name>       -- display man page for <name>\x1b[0m\n" ++
            "  \x1b[37mcommand\x1b[0m --help \x1b[37m  -- display --help output for <command>\x1b[0m\n" ++
            "  go\x1b[37m <name>        -- display go doc for <name>\x1b[0m\n" ++
            "  py\x1b[37m <name>        -- display python doc for <name>\x1b[0m\n" ++
            "  py!\x1b[37m\x1b[0m\n" ++
            "  rb\x1b[37m <name>        -- display ruby doc for <name>\x1b[0m\n" ++
            "  rb!\x1b[37m\x1b[0m\n" ++
            "\n" ++
            "  <math expr>\x1b[37m      -- run <math expr> using qalc\x1b[0m\n" ++
            "\n" ++
            "  logs\x1b[37m [<service>] -- display logs of <service> or all logs by default\x1b[0m\n" ++
            "EOF\n";
        return &[_][]const u8{ "bash", "-c", print_help };
    }
};

pub fn main() !void {
    var frame = tracy.frame(null);
    const init = tracy.trace(@src(), "init");

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = general_purpose_allocator.detectLeaks();
    }
    const gpa = &general_purpose_allocator.allocator;
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    var dirsList = std.ArrayList([]const u8).init(gpa);
    var dirsString = std.ArrayList(u8).init(gpa);
    const downloadsDir = try std.fs.path.join(gpa, &[_][]const u8{ std.os.getenv("HOME").?, "Downloads" });
    if (std.os.getenv("SEARCH_DIRS")) |dirsEnv| {
        var dirs = std.mem.split(u8, dirsEnv, ":");
        var dir = dirs.next();
        while (dir != null) : (dir = dirs.next()) {
            try dirsList.append(dir.?);
        }
    } else {
        try dirsList.append(downloadsDir);
        try dirsList.append("/usr/include");
    }
    Config.searchDirectories = dirsList.toOwnedSlice();
    for (Config.searchDirectories) |dir| {
        try dirsString.appendSlice(dir);
        try dirsString.append(' ');
    }
    Config.searchDirectoriesString = dirsString.toOwnedSlice();
    defer gpa.free(Config.searchDirectories);
    defer gpa.free(Config.searchDirectoriesString);
    defer gpa.free(downloadsDir);

    if (c.SDL_Init(c.SDL_INIT_VIDEO) != 0) {
        c.SDL_Log("Unable to initialize SDL: %s", c.SDL_GetError());
        return error.SDLInitializationFailed;
    }
    defer c.SDL_Quit();

    if (c.TTF_Init() != 0) {
        c.SDL_Log("Unable to initialize SDL_ttf: %s", c.TTF_GetError());
        return error.TTFInitializationFailed;
    }
    defer c.TTF_Quit();

    const init_fonts = tracy.trace(@src(), "init_fonts");
    var font_file = if (args.len > 1) args[1] else "/usr/share/fonts/TTF/FantasqueSansMono-Regular.ttf";
    const font = c.TTF_OpenFont(font_file, 16) orelse {
        c.SDL_Log("Unable to load font: %s", c.TTF_GetError());
        return error.TTFInitializationFailed;
    };
    defer c.TTF_CloseFont(font);
    c.SDL_Log("Using font %s", font_file.ptr);

    var bold_font_file = if (args.len > 2) args[2] else "/usr/share/fonts/TTF/FantasqueSansMono-Bold.ttf";
    const bold_font = c.TTF_OpenFont(bold_font_file, 16) orelse {
        c.SDL_Log("Unable to load font: %s", c.TTF_GetError());
        return error.TTFInitializationFailed;
    };
    defer c.TTF_CloseFont(bold_font);
    init_fonts.end();

    // assume monospace font
    var glyph_width: c_int = 0;
    if (c.TTF_GlyphMetrics(font, 'g', null, null, null, null, &glyph_width) != 0) {
        c.SDL_Log("Unable to measure glyph: %s", c.TTF_GetError());
        return error.TTFInitializationFailed;
    }
    var glyph_height = c.TTF_FontLineSkip(font);

    const init_window = tracy.trace(@src(), "init_window");
    var window_width = glyph_width * 100;
    var window_height = glyph_height * 20;
    const window = c.SDL_CreateWindow("qck", c.SDL_WINDOWPOS_CENTERED, c.SDL_WINDOWPOS_CENTERED, window_width, window_height, c.SDL_WINDOW_BORDERLESS | c.SDL_WINDOW_OPENGL) orelse {
        c.SDL_Log("Unable to create window: %s", c.SDL_GetError());
        return error.SDLInitializationFailed;
    };
    defer c.SDL_DestroyWindow(window);

    var screen = c.SDL_CreateRGBSurface(0, window_width, window_height, 32, 0, 0, 0, 0) orelse {
        c.SDL_Log("Unable to create screen surface: %s", c.SDL_GetError());
        return error.SDLInitializationFailed;
    };
    defer c.SDL_FreeSurface(screen);

    const op: f32 = 0.5;
    if (c.SDL_SetWindowOpacity(window, op) != 0) {
        c.SDL_Log("Unable to make window transparent: %s", c.SDL_GetError());
    }
    var opacity: f32 = 10.0;
    _ = c.SDL_GetWindowOpacity(window, &opacity);
    c.SDL_Log("opacity: %f", opacity);

    const renderer = c.SDL_CreateRenderer(window, -1, c.SDL_RENDERER_ACCELERATED) orelse {
        c.SDL_Log("Unable to create renderer: %s", c.SDL_GetError());
        return error.SDLInitializationFailed;
    };
    var renderer_info: c.SDL_RendererInfo = undefined;
    if (c.SDL_GetRendererInfo(renderer, &renderer_info) != 0) {
        c.SDL_Log("Unable to get renderer info: %s", c.SDL_GetError());
        return error.SDLInitializationFailed;
    }
    c.SDL_Log("Renderer: %s", renderer_info.name);
    init_window.end();

    var msg = "                                                                                                    ".*;
    var msg_overlay = "                                                                                                    ".*;
    var pos: usize = 0;
    var max_chars = std.math.min(@divTrunc(@intCast(usize, window_width), @intCast(usize, glyph_width)), msg.len);

    var result: []const u8 = try gpa.alloc(u8, 0);
    defer gpa.free(result);

    const keyboardState = c.SDL_GetKeyboardState(null);

    var self_doc_runner = SelfDocRunner.init();
    _ = try self_doc_runner.run(gpa, "", false, "");

    c.SDL_StartTextInput();
    var commands = [_]Runner{
        GoDocRunner.init(),
        PythonHelpRunner.init(),
        PythonRunner.init(),
        RubyHelpRunner.init(),
        RubyRunner.init(),
        HelpRunner.init(),
        ManPageRunner.init(),
        SearchRunner.init(),
        FileRunner.init(),
        FirefoxHistoryRunner.init(),
        LogsRunner.init(),
        LaunchRunner.init(),
        QalcRunner.init(),
        self_doc_runner,
    };

    var quit = false;
    var skip: i32 = 0;
    var skip_horizontal: usize = 0;
    var num_lines: i32 = 0;
    var output_length: usize = 0;

    var commandChanged = false;

    var hasChanged = false;
    var lastChange: u32 = 0;

    init.end();
    frame.end();

    while (!quit) {
        frame = tracy.frame(null);
        defer frame.end();

        const loop = tracy.trace(@src(), "loop");
        defer loop.end();

        var frame_start = c.SDL_GetPerformanceCounter();
        defer waitFrame(frame_start);

        const input = tracy.trace(@src(), "input");

        var confirmed = false;
        var inputChanged = false;
        var event: c.SDL_Event = undefined;
        while (c.SDL_PollEvent(&event) != 0) {
            const ctrlPressed = (keyboardState[c.SDL_SCANCODE_LCTRL] != 0);
            switch (event.@"type") {
                c.SDL_QUIT => {
                    quit = true;
                },
                c.SDL_WINDOWEVENT => {
                    switch (event.window.event) {
                        c.SDL_WINDOWEVENT_SIZE_CHANGED => {
                            window_width = event.window.data1;
                            window_height = event.window.data2;

                            c.SDL_FreeSurface(screen);
                            screen = c.SDL_CreateRGBSurface(0, window_width, window_height, 32, 0, 0, 0, 0) orelse {
                                c.SDL_Log("Unable to create screen surface: %s", c.SDL_GetError());
                                return error.SDLInitializationFailed;
                            };
                        },
                        else => {},
                    }
                },
                c.SDL_KEYDOWN => {
                    if (ctrlPressed) {
                        switch (event.key.keysym.sym) {
                            c.SDLK_a => {
                                if (msg_overlay[pos] == '_') {
                                    msg_overlay[pos] = ' ';
                                }
                                pos = 0;
                                msg_overlay[pos] = '_';
                                inputChanged = true;
                            },
                            c.SDLK_k => {
                                var i: usize = 0;
                                while (i < max_chars) : (i += 1) {
                                    msg[i] = ' ';
                                }
                                msg[max_chars] = 0;
                                pos = 0;
                                inputChanged = true;
                            },
                            c.SDLK_c => {
                                const clipboard_text = try gpa.dupeZ(u8, result);
                                if (c.SDL_SetClipboardText(clipboard_text) != 0) {
                                    c.SDL_Log("Could not set clipboard text: %s", c.SDL_GetError());
                                }
                                gpa.free(clipboard_text);
                            },
                            c.SDLK_v => {
                                const clipboard_text = c.SDL_GetClipboardText();
                                if (std.mem.len(clipboard_text) == 0) {
                                    c.SDL_Log("Could not get clipboard: %s", c.SDL_GetError());
                                } else {
                                    const initial_pos = pos;
                                    while (pos < max_chars and pos - initial_pos < std.mem.len(clipboard_text)) : (pos += 1) {
                                        msg[pos] = clipboard_text[pos - initial_pos];
                                    }
                                    msg[pos] = ' ';
                                    msg[max_chars] = 0;
                                }
                                c.SDL_free(clipboard_text);

                                commandChanged = true;
                            },
                            else => {},
                        }
                    } else {
                        switch (event.key.keysym.sym) {
                            c.SDLK_ESCAPE => {
                                quit = true;
                            },
                            c.SDLK_BACKSPACE => {
                                if (msg_overlay[pos] == '_') {
                                    msg_overlay[pos] = ' ';
                                }
                                if (pos > 0) {
                                    msg[pos - 1] = ' ';
                                }
                                pos = if (pos == 0) max_chars - 1 else (pos - 1) % (max_chars - 1);
                                msg_overlay[pos] = '_';
                                commandChanged = true;
                            },
                            c.SDLK_RETURN => {
                                confirmed = true;
                            },
                            c.SDLK_UP => {
                                if (skip > 0) {
                                    skip -= 1;
                                    inputChanged = true;
                                }
                            },
                            c.SDLK_PAGEUP => {
                                if (skip < 10) {
                                    skip = 0;
                                } else {
                                    skip -= 10;
                                }
                                inputChanged = true;
                            },
                            c.SDLK_DOWN => {
                                skip += 1;
                                inputChanged = true;
                            },
                            c.SDLK_PAGEDOWN => {
                                skip += 10;
                                inputChanged = true;
                            },
                            c.SDLK_HOME => {
                                skip = 0;
                                inputChanged = true;
                            },
                            c.SDLK_END => {
                                if (num_lines > 10) {
                                    skip = num_lines - 10;
                                    inputChanged = true;
                                }
                            },
                            c.SDLK_LEFT => {
                                if (skip_horizontal < 10) {
                                    skip_horizontal = 0;
                                } else {
                                    skip_horizontal -= 10;
                                }
                                inputChanged = true;
                            },
                            c.SDLK_RIGHT => {
                                skip_horizontal += 10;
                                inputChanged = true;
                            },
                            else => {},
                        }
                    }
                },
                c.SDL_TEXTINPUT => {
                    if (!ctrlPressed and event.text.text.len > 0) {
                        c.SDL_Log("input: '%s' at %d", event.text.text, pos);
                        msg[pos] = event.text.text[0];
                        msg_overlay[pos] = ' ';
                        pos = (pos + 1) % (max_chars - 1);

                        commandChanged = true;
                    }
                },
                else => {},
            }
        }
        input.end();

        const cmd = std.mem.trim(u8, std.mem.sliceTo(&msg, 0), &std.ascii.spaces);

        if (confirmed or (commandChanged and c.SDL_GetTicks() - lastChange > 200)) {
            const run = tracy.trace(@src(), "run");
            for (commands) |*command| {
                const is_active = command.isActive(cmd);
                if (!is_active) {
                    continue;
                }

                var line: ?[]const u8 = null;
                if (confirmed) {
                    if (command.select) {
                        const output = try command.output();
                        var lines = std.mem.split(u8, output, "\n");
                        line = lines.next();
                        var skipped: i32 = 0;
                        while (skipped < skip and line != null) : (skipped += 1) {
                            line = lines.next();
                        }
                        if (line != null) {
                            std.debug.print("line {d} '{s}' ({d} chars) selected\n", .{ skip, line.?, line.?.len });
                        }
                    }

                    const selection = try gpa.dupe(u8, line orelse "");
                    defer gpa.free(selection);

                    _ = try command.run(gpa, cmd, confirmed, selection);
                    std.debug.print("running...\n", .{});

                    // FIXME: don't wait here, print output until done?
                    if (command.process) |*process| {
                        _ = try process.process.wait();
                    }
                    quit = true;
                } else {
                    _ = try command.run(gpa, cmd, confirmed, "");
                }
            }
            run.end();

            commandChanged = false;
            lastChange = c.SDL_GetTicks();
            confirmed = false;

            hasChanged = true;

            skip = 0;
            skip_horizontal = 0;
        }

        const is_active = tracy.trace(@src(), "is_active");
        var rerender = true;
        // do not render if nothing has changed
        for (commands) |*command| {
            if (command.isActive(cmd)) {
                const out = try command.output();
                if (!hasChanged and out.len == output_length) {
                    rerender = false;
                } else {
                    hasChanged = false;
                }
            }
        }
        is_active.end();

        if (!inputChanged and !rerender) {
            continue;
        }

        const render = tracy.trace(@src(), "render");
        defer render.end();

        const render_init = tracy.trace(@src(), "render_init");
        _ = c.SDL_SetRenderDrawColor(renderer, 0, 0, 0, 100);
        //_ = c.SDL_SetRenderDrawBlendMode(renderer, c.SDL_BlendMode.SDL_BLENDMODE_BLEND);
        _ = c.SDL_RenderClear(renderer);

        _ = c.SDL_FillRect(screen, null, 0);

        // thanks to https://stackoverflow.com/questions/22886500/how-to-render-text-in-sdl2 for some actually useful code here
        const white: c.SDL_Color = c.SDL_Color{ .r = 255, .g = 255, .b = 255, .a = 255 };
        const gray: c.SDL_Color = c.SDL_Color{ .r = 150, .g = 150, .b = 150, .a = 255 };
        const black: c.SDL_Color = c.SDL_Color{ .r = 0, .g = 0, .b = 0, .a = 255 };

        {
            // Shaded vs Solid gives a nicer output, with solid the output
            // was squiggly and not aligned with a baseline.
            const text = c.TTF_RenderUTF8_Shaded(font, &msg, white, black);
            defer c.SDL_FreeSurface(text);
            _ = c.SDL_BlitSurface(text, null, screen, &c.SDL_Rect{ .x = 0, .y = 0, .w = @intCast(c_int, msg.len) * glyph_width, .h = glyph_height });
        }
        {
            const text = c.TTF_RenderUTF8_Shaded(font, &msg_overlay, white, c.SDL_Color{ .r = 0, .g = 0, .b = 0, .a = 0 });
            defer c.SDL_FreeSurface(text);
            if (c.SDL_SetSurfaceBlendMode(text, c.SDL_BLENDMODE_ADD) != 0) {
                c.SDL_Log("Unable set surface blend mode: %s", c.SDL_GetError());
            }
            _ = c.SDL_BlitSurface(text, null, screen, &c.SDL_Rect{ .x = 0, .y = 0, .w = @intCast(c_int, msg.len) * glyph_width, .h = glyph_height });
        }
        render_init.end();

        var i: c_int = 1;
        var line_buf = [_]u8{0} ** 10000;
        var part_buf = [_]u8{0} ** 10000;
        for (commands) |*command| {
            const trace_command = tracy.trace(@src(), "command");
            defer trace_command.end();

            if (!command.isActive(cmd)) {
                continue;
            }

            const output = try command.output();
            output_length = output.len;

            // TODO: indicate if command is still running

            {
                const result_text = c.TTF_RenderUTF8_Shaded(font, command.name.ptr, gray, c.SDL_Color{ .r = 0, .g = 0, .b = 0, .a = 255 });
                _ = c.SDL_BlitSurface(result_text, null, screen, &c.SDL_Rect{ .x = window_width - @intCast(c_int, command.name.len) * glyph_width, .y = 0, .w = @intCast(c_int, command.name.len) * glyph_width, .h = glyph_height });
                c.SDL_FreeSurface(result_text);
            }

            //std.debug.print("{s} {d} {d}\n", .{ command.process.is_running(), command.process.stdout_buf.items.len, command.process.stdout_buf.capacity });
            var lines = std.mem.split(u8, output, "\n");
            var line = lines.next();
            {
                var skipped: i32 = 0;
                while (skipped < skip and line != null) : (skipped += 1) {
                    line = lines.next();
                }
            }
            while (line != null and i * glyph_height < window_height) {
                const render_line = tracy.trace(@src(), "render_line");
                defer render_line.end();

                var skipped_line = line.?[std.math.min(skip_horizontal, line.?.len)..];
                if (skipped_line.len > line_buf.len) {
                    skipped_line = skipped_line[0 .. line_buf.len - 1];
                }

                // fix tabs
                const repl_size = std.mem.replacementSize(u8, skipped_line, "\t", " " ** 8);
                _ = std.mem.replace(u8, skipped_line, "\t", " " ** 8, &line_buf);
                line_buf[repl_size] = 0;

                var j: c_int = 0;

                var fnt = font;
                var fg_color = white;
                var bg_color = black;

                // TODO: implement some terminal colors
                var parts = std.mem.split(u8, line_buf[0..repl_size], "\x1B[");
                var part = parts.next();
                while (part != null) : (part = parts.next()) {
                    if (command.select and i == 1) {
                        bg_color = gray;
                    }

                    var part_text = part.?;
                    if (std.mem.startsWith(u8, part_text, "m")) {
                        part_text = part_text[1..];
                    } else if (std.mem.startsWith(u8, part_text, "0m")) {
                        part_text = part_text[2..];
                    } else if (std.mem.startsWith(u8, part_text, "37m")) {
                        part_text = part_text[3..];
                        fg_color = c.SDL_Color{ .r = 200, .g = 200, .b = 200, .a = 255 };
                    } else if (std.mem.startsWith(u8, part_text, "1;32m")) {
                        fnt = bold_font;
                        part_text = part_text[5..];
                        fg_color = c.SDL_Color{ .r = 0, .g = 205, .b = 0, .a = 255 };
                    } else if (std.mem.startsWith(u8, part_text, "1;33m")) {
                        fnt = bold_font;
                        part_text = part_text[5..];
                        fg_color = c.SDL_Color{ .r = 205, .g = 205, .b = 0, .a = 255 };
                    } else if (std.mem.startsWith(u8, part_text, "01;31m")) {
                        fnt = bold_font;
                        part_text = part_text[6..];
                        fg_color = c.SDL_Color{ .r = 205, .g = 0, .b = 0, .a = 255 };
                    } else if (std.mem.startsWith(u8, part_text, "30;43m")) {
                        part_text = part_text[6..];
                        bg_color = c.SDL_Color{ .r = 205, .g = 205, .b = 0, .a = 255 };
                    } else if (std.mem.startsWith(u8, part_text, "0;1;31m")) {
                        part_text = part_text[7..];
                        fnt = bold_font;
                        fg_color = c.SDL_Color{ .r = 205, .g = 0, .b = 0, .a = 255 };
                    } else if (std.mem.startsWith(u8, part_text, "0;1;39m")) { // Default foreground color
                        part_text = part_text[7..];
                        fnt = bold_font;
                        fg_color = white;
                    } else if (std.mem.startsWith(u8, part_text, "0;38;5;245m")) {
                        part_text = part_text[11..];
                        // TODO: calculate color correctly
                        fg_color = gray;
                    } else if (std.mem.startsWith(u8, part_text, "K")) {
                        // no idea what this is, skipping it
                        part_text = part_text[1..];
                    } else {
                        if (part.?.len > 0) {
                            //std.debug.print("unhandled escape char: {d} {s}\n", .{ part.?[0], part.?[0..] });
                        }
                    }

                    if (part_text.len == 0) {
                        continue;
                    }

                    var k = j;
                    var l: usize = 0;
                    var skip_next = false;
                    var was_overdraw = false;
                    for (part_text) |ch, p| {
                        if (skip_next) {
                            skip_next = false;
                            continue;
                        }
                        if (ch == 8 and p + 1 < part_text.len) {
                            const render_overdraw = tracy.trace(@src(), "render_overdraw");
                            defer render_overdraw.end();

                            //std.debug.print("overdraw '{c}'\n", .{part_text[p + 1]});
                            const result_text = c.TTF_RenderUTF8_Shaded(font, &[_]u8{ part_text[p + 1], 0 }, fg_color, bg_color);

                            _ = c.SDL_BlitSurface(result_text, null, screen, &c.SDL_Rect{ .x = (k - 1) * glyph_width, .y = i * glyph_height, .w = @intCast(c_int, 1) * glyph_width, .h = glyph_height });
                            c.SDL_FreeSurface(result_text);

                            skip_next = true;
                            was_overdraw = true;
                        } else {
                            part_buf[l] = ch;
                            l += 1;
                            k += 1;
                        }
                    }
                    part_buf[l] = 0;

                    const render_part = tracy.trace(@src(), "render_part");

                    const r1 = tracy.trace(@src(), "TTF_RenderUTF8_Shaded");
                    const result_text = c.TTF_RenderUTF8_Shaded(fnt, &part_buf, fg_color, bg_color);
                    r1.end();

                    // TODO: fix overdraw
                    if (c.SDL_SetSurfaceBlendMode(result_text, if (was_overdraw) c.SDL_BLENDMODE_ADD else c.SDL_BLENDMODE_NONE) != 0) {
                        c.SDL_Log("Unable set surface blend mode: %s", c.SDL_GetError());
                    }

                    _ = c.SDL_BlitSurface(result_text, null, screen, &c.SDL_Rect{ .x = j * glyph_width, .y = i * glyph_height, .w = @intCast(c_int, l) * glyph_width, .h = glyph_height });

                    const r5 = tracy.trace(@src(), "SDL_FreeSurface");
                    c.SDL_FreeSurface(result_text);
                    r5.end();

                    j += @intCast(c_int, part_text.len);
                    render_part.end();
                }

                i += 1;
                line = lines.next();
            }

            // only allow one command
            break;
        }

        const trace_st = tracy.trace(@src(), "screen texture");
        const screen_texture = c.SDL_CreateTextureFromSurface(renderer, screen);
        trace_st.end();

        const trace_render_copy = tracy.trace(@src(), "SDL_RenderCopy");
        _ = c.SDL_RenderCopy(renderer, screen_texture, null, null);
        trace_render_copy.end();

        defer c.SDL_DestroyTexture(screen_texture);

        const trace_render_present = tracy.trace(@src(), "SDL_RenderPresent");
        _ = c.SDL_RenderPresent(renderer);
        trace_render_present.end();
    }

    // clean up memory and processes
    for (commands) |*command| {
        try command.deinit();
    }
}

fn waitFrame(frame_start: u64) void {
    const frame_duration = c.SDL_GetPerformanceCounter() - frame_start;
    const elapsed_ms = @intToFloat(f64, frame_duration) / @intToFloat(f64, c.SDL_GetPerformanceFrequency()) * 1000.0;
    const frame_time = 1000.0 / 60.0;
    if (elapsed_ms > frame_time) {
        return;
    }
    c.SDL_Delay(@floatToInt(u32, std.math.floor(frame_time - elapsed_ms)));
}

// tests

test "trim []const u8" {
    const untrimmed: []const u8 = "   hey there   ";
    const trimmed = std.mem.trim(u8, untrimmed, &std.ascii.spaces);
    try std.testing.expect(trimmed.len < untrimmed.len);
    try std.testing.expect(trimmed.len == 9);
    try std.testing.expect(std.mem.eql(u8, trimmed, "hey there"));
}

test "trim [*:0]const u8" {
    const untrimmed: [*:0]const u8 = "   hey there   ";
    const to_trim: [*:0]const u8 = " ";
    const trimmed = std.mem.trim(u8, std.mem.sliceTo(untrimmed, 0), std.mem.sliceTo(to_trim, 0));
    try std.testing.expect(std.mem.len(trimmed) < std.mem.len(untrimmed));
    try std.testing.expect(trimmed.len == 9);
    try std.testing.expect(std.mem.eql(u8, trimmed, "hey there"));
}
