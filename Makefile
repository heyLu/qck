hello_sdl: Makefile build.zig hello_sdl.zig
	zig build
	cp zig-out/bin/hello_sdl .
