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
        try writer.print("{}\n", .{die.fmtDie(ctx.table, cu, ctx.ctx, null)});
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
        low_pc: ?u64,
    ) std.fmt.Formatter(formatDie) {
        return .{ .data = .{
            .die = die,
            .table = table,
            .cu = cu,
            .ctx = ctx,
            .low_pc = low_pc,
        } };
    }

    const FormatDieCtx = struct {
        die: DebugInfoEntry,
        table: AbbrevTable,
        cu: *CompileUnit,
        ctx: *const Context,
        low_pc: ?u64 = null,
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
        var low_pc: ?u64 = ctx.low_pc;
        for (decl.attrs.items, ctx.die.values.items) |attr, value| {
            try writer.print("  {} (", .{AbbrevTable.fmtAt(attr.at)});
            formatAtFormInner(attr, value, ctx.cu, &low_pc, ctx.ctx, writer) catch |err| switch (err) {
                error.UnhandledForm => try writer.print("error: unhandled form 0x{x} for attribute\n", .{attr.form}),
                error.UnexpectedForm => try writer.print("error: unexpected FORM value: {x}", .{attr.form}),
                error.MalformedDwarf => try writer.print("error: malformed DWARF while parsing FORM {x}", .{attr.form}),
                error.Overflow, error.EndOfStream => unreachable,
                else => |e| return e,
            };
            try writer.writeAll(")\n");
        }
        // TODO indents
        for (ctx.die.children.items) |child_index| {
            const child = ctx.cu.diePtr(child_index);
            try writer.print("  {}\n", .{child.fmtDie(ctx.table, ctx.cu, ctx.ctx, low_pc)});
        }
    }

    fn formatAtFormInner(
        attr: Attr,
        value: []const u8,
        cu: *CompileUnit,
        low_pc: *?u64,
        ctx: *const Context,
        writer: anytype,
    ) !void {
        switch (attr.at) {
            dwarf.AT.stmt_list,
            dwarf.AT.ranges,
            => {
                const sec_offset = attr.getSecOffset(value, cu.header.dw_format) orelse
                    return error.MalformedDwarf;
                try writer.print("{x:0>16}", .{sec_offset});
            },

            dwarf.AT.low_pc => {
                const addr = attr.getAddr(value, cu.header) orelse
                    return error.MalformedDwarf;
                low_pc.* = addr;
                try writer.print("{x:0>16}", .{addr});
            },

            dwarf.AT.high_pc => {
                if (try attr.getConstant(value)) |offset| {
                    try writer.print("{x:0>16}", .{offset + low_pc.*.?});
                } else if (attr.getAddr(value, cu.header)) |addr| {
                    try writer.print("{x:0>16}", .{addr});
                } else return error.MalformedDwarf;
            },

            dwarf.AT.type,
            dwarf.AT.abstract_origin,
            => {
                const off = (try attr.getReference(value, cu.header.dw_format)) orelse
                    return error.MalformedDwarf;
                try writer.print("{x}", .{off});
            },

            dwarf.AT.comp_dir,
            dwarf.AT.producer,
            dwarf.AT.name,
            dwarf.AT.linkage_name,
            => {
                const str = attr.getString(value, cu.header.dw_format, ctx) orelse
                    return error.MalformedDwarf;
                try writer.print("\"{s}\"", .{str});
            },

            dwarf.AT.language,
            dwarf.AT.calling_convention,
            dwarf.AT.encoding,
            dwarf.AT.decl_column,
            dwarf.AT.decl_file,
            dwarf.AT.decl_line,
            dwarf.AT.alignment,
            dwarf.AT.data_bit_offset,
            dwarf.AT.call_file,
            dwarf.AT.call_line,
            dwarf.AT.call_column,
            dwarf.AT.@"inline",
            => {
                const x = (try attr.getConstant(value)) orelse return error.MalformedDwarf;
                try writer.print("{x:0>16}", .{x});
            },

            dwarf.AT.location,
            dwarf.AT.frame_base,
            => {
                if (try attr.getExprloc(value)) |list| {
                    try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                } else {
                    try writer.print("error: TODO check and parse loclist", .{});
                }
            },

            dwarf.AT.data_member_location => {
                if (try attr.getConstant(value)) |x| {
                    try writer.print("{x:0>16}", .{x});
                } else if (try attr.getExprloc(value)) |list| {
                    try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                } else {
                    try writer.print("error: TODO check and parse loclist", .{});
                }
            },

            dwarf.AT.const_value => {
                if (try attr.getConstant(value)) |x| {
                    try writer.print("{x:0>16}", .{x});
                } else if (attr.getString(value, cu.header.dw_format, ctx)) |str| {
                    try writer.print("\"{s}\"", .{str});
                } else {
                    try writer.print("error: TODO check and parse block", .{});
                }
            },

            dwarf.AT.count => {
                if (try attr.getConstant(value)) |x| {
                    try writer.print("{x:0>16}", .{x});
                } else if (try attr.getExprloc(value)) |list| {
                    try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                } else if (try attr.getReference(value, cu.header.dw_format)) |off| {
                    try writer.print("{x:0>16}", .{off});
                } else return error.MalformedDwarf;
            },

            dwarf.AT.byte_size,
            dwarf.AT.bit_size,
            => {
                if (try attr.getConstant(value)) |x| {
                    try writer.print("{x}", .{x});
                } else if (try attr.getReference(value, cu.header.dw_format)) |off| {
                    try writer.print("{x}", .{off});
                } else if (try attr.getExprloc(value)) |list| {
                    try writer.print("<0x{x}> {x}", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                } else return error.MalformedDwarf;
            },

            dwarf.AT.noreturn,
            dwarf.AT.external,
            dwarf.AT.variable_parameter,
            dwarf.AT.trampoline,
            => {
                const flag = attr.getFlag(value) orelse return error.MalformedDwarf;
                try writer.print("{}", .{flag});
            },

            else => {
                if (dwarf.AT.lo_user <= attr.at and attr.at <= dwarf.AT.hi_user) {
                    if (try attr.getConstant(value)) |x| {
                        try writer.print("{x}", .{x});
                    } else if (attr.getString(value, cu.header.dw_format, ctx)) |string| {
                        try writer.print("\"{s}\"", .{string});
                    } else return error.UnhandledForm;
                } else return error.UnexpectedForm;
            },
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
