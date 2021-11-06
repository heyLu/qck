qck: Makefile build.zig qck.zig
	zig build -Drelease-safe
	cp zig-out/bin/qck .
