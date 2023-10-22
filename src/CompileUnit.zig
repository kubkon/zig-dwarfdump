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
    _ = cu;
    _ = unused_fmt_string;
    _ = options;
    _ = writer;
    @compileError("do not format CompileUnit directly; use fmtCompileUnit");
}

pub fn fmtCompileUnit(
    cu: *CompileUnit,
    table: AbbrevTable,
    ctx: *const Context,
) std.fmt.Formatter(formatCompileUnit) {
    return .{ .data = .{
        .cu = cu,
        .table = table,
        .ctx = ctx,
    } };
}

const FormatCompileUnitCtx = struct {
    cu: *CompileUnit,
    table: AbbrevTable,
    ctx: *const Context,
};

pub fn formatCompileUnit(
    ctx: FormatCompileUnitCtx,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const cu = ctx.cu;
    try writer.print("{}: Compile Unit: {} (next unit at {})\n", .{
        cu.header.dw_format.fmtOffset(cu.loc.pos),
        cu.header,
        cu.header.dw_format.fmtOffset(cu.nextCompileUnitOffset()),
    });
    for (cu.children.items) |die_index| {
        const die = cu.diePtr(die_index);
        try writer.print("{}\n", .{die.fmtDie(ctx.table, cu, ctx.ctx)});
    }
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
    code: u64,
    loc: Loc,
    values: std.ArrayListUnmanaged([]const u8) = .{},
    children: std.ArrayListUnmanaged(usize) = .{},

    pub fn deinit(die: *DebugInfoEntry, gpa: Allocator) void {
        die.values.deinit(gpa);
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

    pub fn fmtDie(
        die: DebugInfoEntry,
        table: AbbrevTable,
        cu: *CompileUnit,
        ctx: *const Context,
    ) std.fmt.Formatter(formatDie) {
        return .{ .data = .{
            .die = die,
            .table = table,
            .cu = cu,
            .ctx = ctx,
        } };
    }

    const FormatDieCtx = struct {
        die: DebugInfoEntry,
        table: AbbrevTable,
        cu: *CompileUnit,
        ctx: *const Context,
    };

    fn formatDie(
        ctx: FormatDieCtx,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const decl = ctx.table.getDecl(ctx.die.code).?;
        try writer.print("{}: {}\n", .{
            ctx.cu.header.dw_format.fmtOffset(ctx.die.loc.pos),
            AbbrevTable.fmtTag(decl.tag),
        });
        for (decl.attrs.items, ctx.die.values.items) |attr, value| {
            try writer.print("  {} (", .{AbbrevTable.fmtAt(attr.at)});
            switch (attr.form) {
                dwarf.FORM.flag,
                dwarf.FORM.flag_present,
                => try writer.print("{}", .{attr.getFlag(value)}),

                dwarf.FORM.string,
                dwarf.FORM.strp,
                => try writer.print("{s}", .{attr.getString(value, ctx.cu.header.dw_format, ctx.ctx)}),

                else => {},
            }
            try writer.writeAll(")\n");
        }
        // TODO indents
        for (ctx.die.children.items) |child_index| {
            const child = ctx.cu.diePtr(child_index);
            try writer.print("  {}\n", .{child.fmtDie(ctx.table, ctx.cu, ctx.ctx)});
        }
    }
};

const dwarf = std.dwarf;
const std = @import("std");
const AbbrevTable = @import("AbbrevTable.zig");
const Attr = AbbrevTable.Attr;
const Allocator = std.mem.Allocator;
const CompileUnit = @This();
const Context = @import("Context.zig");
const DwarfDump = @import("DwarfDump.zig");
const Loc = DwarfDump.Loc;
