header: Header,
loc: Loc,
dies: std.ArrayListUnmanaged(DebugInfoEntry) = .{},
children: std.ArrayListUnmanaged(usize) = .{},

pub fn deinit(cu: *CompileUnit, gpa: Allocator) void {
    for (cu.dies.items) |*die| {
        die.deinit(gpa);
    }
    cu.dies.deinit(gpa);
    cu.children.deinit(gpa);
}

pub fn addDie(cu: *CompileUnit, gpa: Allocator) !usize {
    const index = cu.dies.items.len;
    _ = try cu.dies.addOne(gpa);
    return index;
}

pub fn diePtr(cu: *CompileUnit, index: usize) *DebugInfoEntry {
    return &cu.dies.items[index];
}

pub fn nextCompileUnitOffset(cu: CompileUnit) u64 {
    return cu.loc.pos + switch (cu.header.dw_format) {
        .dwarf32 => @as(u64, 4),
        .dwarf64 => 12,
    } + cu.header.length;
}

pub fn format(
    cu: CompileUnit,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    try writer.print("{}: Compile Unit: {} (next unit at {})\n", .{
        cu.header.dw_format.fmtOffset(cu.loc.pos),
        cu.header,
        cu.header.dw_format.fmtOffset(cu.nextCompileUnitOffset()),
    });
}

pub const Header = struct {
    dw_format: DwarfDump.Format,
    length: u64,
    version: u16,
    debug_abbrev_offset: u64,
    address_size: u8,

    pub fn format(
        header: Header,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print(
            "length = {}, " ++
                "format = {s}, " ++
                "version = 0x{x:0>4}, " ++
                "abbr_offset = {}, " ++
                "address_size = 0x{x:0>2}",
            .{
                header.dw_format.fmtOffset(header.length),
                @tagName(header.dw_format),
                header.version,
                header.dw_format.fmtOffset(header.debug_abbrev_offset),
                header.address_size,
            },
        );
    }
};

pub const DebugInfoEntry = struct {
    data: []const u8,
    loc: Loc,
    children: std.ArrayListUnmanaged(usize) = .{},

    pub fn deinit(die: *DebugInfoEntry, gpa: Allocator) void {
        die.children.deinit(gpa);
    }

    pub fn format(
        die: DebugInfoEntry,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = die;
        _ = unused_fmt_string;
        _ = options;
        _ = writer;
        @compileError("do not format DebugInfoEntry directly; use fmtDie instead");
    }

    pub fn fmtDie(die: DebugInfoEntry, decl: AbbrevTable.Decl, cu: CompileUnit) std.fmt.Formatter(formatDie) {
        return .{ .data = .{
            .die = die,
            .decl = decl,
            .cu = cu,
        } };
    }

    const FormatDieCtx = struct {
        die: DebugInfoEntry,
        decl: AbbrevTable.Decl,
        cu: CompileUnit,
    };

    fn formatDie(
        ctx: FormatDieCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.print("{}: {}\n", .{
            ctx.cu.header.dw_format.fmtOffset(ctx.die.loc.pos),
            AbbrevTable.fmtTag(ctx.decl.tag),
        });
    }
};

const std = @import("std");
const AbbrevTable = @import("AbbrevTable.zig");
const Allocator = std.mem.Allocator;
const CompileUnit = @This();
const DwarfDump = @import("DwarfDump.zig");
const Loc = DwarfDump.Loc;
