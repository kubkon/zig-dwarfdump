const std = @import("std");
const clap = @import("clap");
const process = std.process;

const DwarfDump = @import("DwarfDump.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const stderr = std.io.getStdErr().writer();
    const stdout = std.io.getStdOut().writer();

    const params = comptime [_]clap.Param(clap.Help){
        clap.parseParam("--help                 Display this help and exit.") catch unreachable,
        clap.parseParam("--eh-frame             Display .eh_frame section contents.") catch unreachable,
        clap.parseParam("--llvm-compatibility   Output is formatted exactly like llvm-dwarfdump, with no extra information.") catch unreachable,
        clap.parseParam("<FILE>") catch unreachable,
    };

    const parsers = comptime .{
        .FILE = clap.parsers.string,
    };

    var res = try clap.parse(clap.Help, &params, parsers, .{
        .allocator = gpa.allocator(),
        .diagnostic = null,
    });
    defer res.deinit();

    if (res.args.help != 0) {
        return printUsageWithHelp(stderr, params[0..]);
    }

    if (res.positionals.len == 0) {
        return stderr.print("missing positional argument <FILE>...\n", .{});
    }

    const filename = res.positionals[0];
    const file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    var dd = try DwarfDump.parse(gpa.allocator(), file);
    defer dd.deinit();

    if (res.args.@"eh-frame" != 0) {
        try stdout.print("{s}:\tfile format {s}-{s}\n\n", .{ filename, switch (dd.ctx.tag) {
            .elf => "elf64",
            .macho => "Mach-O 64-bit",
        }, if (dd.ctx.getArch()) |arch| @tagName(arch) else "unknown" });

        try dd.printEhFrames(stdout, res.args.@"llvm-compatibility" != 0);
    } else try dd.printCompileUnits(stdout);
}

fn printUsageWithHelp(stream: anytype, comptime params: []const clap.Param(clap.Help)) !void {
    try stream.print("dwarfdump ", .{});
    try clap.usage(stream, clap.Help, params);
    try stream.print("\n", .{});
    try clap.help(stream, clap.Help, params, .{});
}
