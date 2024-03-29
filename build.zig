const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const mode = b.standardReleaseOptions();
    const exe = b.addExecutable("qck", "./qck.zig");
    exe.setBuildMode(mode);

    exe.addIncludeDir("tracy");
    exe.addCSourceFile("tracy/TracyClient.cpp", &[_][]const u8{"-DTRACY_ENABLE"});
    exe.linkSystemLibrary("c++");

    exe.linkSystemLibrary("SDL2");
    exe.linkSystemLibrary("SDL2_ttf");
    exe.linkSystemLibrary("c");

    b.default_step.dependOn(&exe.step);
    b.installArtifact(exe);

    const run = b.step("run", "Run the binary");
    const run_cmd = exe.run();
    run.dependOn(&run_cmd.step);
}
