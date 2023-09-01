const std = @import("std");
const process = std.process;

const DwarfDump = @import("DwarfDump.zig");

const usage =
    \\Usage: zig-dwarfdump [options] file
    \\
    \\General options:
    \\--debug-info          Display .debug_info section contents (default)
    \\--eh-frame            Display .eh_frame section contents
    \\--llvm-compatibility  Output is formatted exactly like llvm-dwarfdump, with no extra information
    \\--all, -a             Display all debug info sections
    \\--help                Display this help and exit
    \\
;

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    ret: {
        const msg = std.fmt.allocPrint(gpa, format ++ "\n", args) catch break :ret;
        std.io.getStdErr().writeAll(msg) catch {};
    }
    std.process.exit(1);
}

const ArgsIterator = struct {
    args: []const []const u8,
    i: usize = 0,

    fn next(it: *@This()) ?[]const u8 {
        if (it.i >= it.args.len) {
            return null;
        }
        defer it.i += 1;
        return it.args[it.i];
    }

    fn nextOrFatal(it: *@This()) []const u8 {
        return it.next() orelse fatal("expected parameter after {s}", .{it.args[it.i - 1]});
    }
};

var global_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = global_alloc.allocator();

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const all_args = try std.process.argsAlloc(arena);
    const args = all_args[1..];

    if (args.len == 0) fatal(usage, .{});

    var filename: ?[]const u8 = null;
    var llvm_compat: bool = false;

    const PrintMatrix = packed struct {
        debug_info: bool = true,
        eh_frame: bool = false,

        const Int = blk: {
            const bits = @typeInfo(@This()).Struct.fields.len;
            break :blk @Type(.{
                .Int = .{
                    .signedness = .unsigned,
                    .bits = bits,
                },
            });
        };

        fn enableAll() @This() {
            return @as(@This(), @bitCast(~@as(Int, 0)));
        }

        fn isSet(pm: @This()) bool {
            return @as(Int, @bitCast(pm)) != 0;
        }

        fn add(pm: *@This(), other: @This()) void {
            pm.* = @as(@This(), @bitCast(@as(Int, @bitCast(pm.*)) | @as(Int, @bitCast(other))));
        }
    };
    var print_matrix: PrintMatrix = .{};

    var it = ArgsIterator{ .args = args };
    while (it.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "-")) blk: {
            var i: usize = 1;
            var tmp = PrintMatrix{};
            while (i < arg.len) : (i += 1) switch (arg[i]) {
                '-' => break :blk,
                'a' => tmp = PrintMatrix.enableAll(),
                else => break :blk,
            };
            print_matrix.add(tmp);
            continue;
        }

        if (std.mem.eql(u8, arg, "--help")) {
            fatal(usage, .{});
        } else if (std.mem.eql(u8, arg, "--all")) {
            print_matrix = PrintMatrix.enableAll();
        } else if (std.mem.eql(u8, arg, "--debug-info")) {
            // Do nothing
        } else if (std.mem.eql(u8, arg, "--eh-frame")) {
            print_matrix.eh_frame = true;
        } else if (std.mem.eql(u8, arg, "--llvm-compatibility")) {
            llvm_compat = true;
        } else {
            if (filename != null) fatal("too many positional arguments specified", .{});
            filename = arg;
        }
    }

    const fname = filename orelse fatal("no input file specified", .{});
    const file = try std.fs.cwd().openFile(fname, .{});
    defer file.close();

    var dd = try DwarfDump.parse(gpa, file);
    defer dd.deinit();

    const stdout = std.io.getStdOut().writer();

    if (print_matrix.debug_info) {
        try dd.printCompileUnits(stdout);
        try stdout.writeAll("\n");
    }
    if (print_matrix.eh_frame) {
        try stdout.print("{s}:\tfile format {s}{s}\n", .{ fname, switch (dd.ctx.tag) {
            .elf => "elf64-",
            .macho => "Mach-O ",
        }, if (dd.ctx.getArch()) |arch| switch (arch) {
            .x86_64 => "x86_64",
            .aarch64 => "arm64",
            else => @tagName(arch),
        } else "unknown" });

        try dd.printEhFrames(stdout, llvm_compat);
        try stdout.writeAll("\n");
    }
}
