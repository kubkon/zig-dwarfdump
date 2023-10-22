decls: std.ArrayListUnmanaged(Decl) = .{},
loc: Loc,

pub fn deinit(table: *AbbrevTable, gpa: Allocator) void {
    for (table.decls.items) |*decl| {
        decl.deinit(gpa);
    }
    table.decls.deinit(gpa);
}

pub fn getDecl(table: AbbrevTable, code: u64) ?Decl {
    for (table.decls.items) |decl| {
        if (decl.code == code) return decl;
    }
    return null;
}

pub fn format(
    table: AbbrevTable,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    for (table.decls.items) |decl| {
        try writer.print("{}\n", .{decl});
    }
}

pub const Decl = struct {
    code: u64,
    tag: u64,
    children: bool,
    attrs: std.ArrayListUnmanaged(Attr) = .{},
    loc: Loc,

    pub fn deinit(decl: *Decl, gpa: Allocator) void {
        decl.attrs.deinit(gpa);
    }

    pub fn isNull(decl: Decl) bool {
        return decl.code == 0;
    }

    pub fn format(
        decl: Decl,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;

        try writer.print("[{d}]  ", .{decl.code});
        if (decl.isNull()) return;

        try writer.print("{}", .{fmtTag(decl.tag)});
        try writer.print("  DW_CHILDREN_{s}\n", .{if (decl.children) "yes" else "no"});

        const nattrs = decl.attrs.items.len;
        if (nattrs == 0) return;

        for (decl.attrs.items[0 .. nattrs - 1]) |attr| {
            try writer.print("{}\n", .{attr});
        }
        try writer.print("{}", .{decl.attrs.items[nattrs - 1]});
    }
};

pub fn fmtTag(tag: u64) std.fmt.Formatter(formatTag) {
    return .{ .data = tag };
}

fn formatTag(
    tag: u64,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const is_tag_known = switch (tag) {
        dwarf.TAG.lo_user...dwarf.TAG.hi_user => switch (tag) {
            0x4109, 0x410a => true,
            else => false,
        },
        else => inline for (@typeInfo(dwarf.TAG).Struct.decls) |x| {
            if (@field(dwarf.TAG, x.name) == tag) break true;
        } else false,
    };
    if (is_tag_known) {
        const tag_s = switch (tag) {
            dwarf.TAG.lo_user...dwarf.TAG.hi_user => switch (tag) {
                0x4109 => "DW_TAG_GNU_call_site",
                0x410a => "DW_TAG_GNU_call_site_parameter",
                else => unreachable, // sync'd with is_tag_known check above
            },
            else => inline for (@typeInfo(dwarf.TAG).Struct.decls) |x| {
                if (@field(dwarf.TAG, x.name) == tag) {
                    break "DW_TAG_" ++ x.name;
                }
            } else unreachable, // sync'd with is_tag_known check above
        };
        try writer.print("{s}", .{tag_s});
    } else {
        try writer.print("DW_TAG_unknown_{x}", .{tag});
    }
}

pub const Attr = struct {
    at: u64,
    form: u64,
    loc: Loc,

    pub fn isNull(attr: Attr) bool {
        return attr.at == 0 and attr.form == 0;
    }

    pub fn getFlag(attr: Attr, value: []const u8) bool {
        switch (attr.form) {
            dwarf.FORM.flag => return value[0] == 1,
            dwarf.FORM.flag_present => return true,
            else => unreachable,
        }
    }

    pub fn getString(attr: Attr, value: []const u8, dwf: DwarfDump.Format, ctx: *const Context) []const u8 {
        switch (attr.form) {
            dwarf.FORM.string => {
                return mem.sliceTo(@as([*:0]const u8, @ptrCast(value.ptr)), 0);
            },
            dwarf.FORM.strp => {
                const off = switch (dwf) {
                    .dwarf64 => mem.readIntLittle(u64, value[0..8]),
                    .dwarf32 => mem.readIntLittle(u32, value[0..4]),
                };
                return ctx.getDwarfString(off);
            },
            else => unreachable,
        }
    }

    pub fn format(
        attr: Attr,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        try writer.writeAll("        ");
        try writer.print("{}", .{fmtAt(attr.at)});
        try writer.writeAll("  ");
        inline for (@typeInfo(dwarf.FORM).Struct.decls) |x| {
            if (@field(dwarf.FORM, x.name) == attr.form) {
                try writer.print("DW_FORM_{s}", .{x.name});
                break;
            }
        } else try writer.print("DW_FORM_unknown_{x}", .{attr.form});
    }
};

pub fn fmtAt(at: u64) std.fmt.Formatter(formatAt) {
    return .{ .data = at };
}

fn formatAt(
    at: u64,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    const is_at_known = switch (at) {
        dwarf.AT.lo_user...dwarf.AT.hi_user => switch (at) {
            0x2111, 0x2113, 0x2115, 0x2117, 0x3e02, 0x3fef => true,
            else => false,
        },
        else => inline for (@typeInfo(dwarf.AT).Struct.decls) |x| {
            if (@field(dwarf.AT, x.name) == at) break true;
        } else false,
    };
    if (is_at_known) {
        const name = switch (at) {
            dwarf.AT.lo_user...dwarf.AT.hi_user => switch (at) {
                0x2111 => "DW_AT_GNU_call_site_value",
                0x2113 => "DW_AT_GNU_call_site_target",
                0x2115 => "DW_AT_GNU_tail_cail",
                0x2117 => "DW_AT_GNU_all_call_sites",
                0x3e02 => "DW_AT_LLVM_sysroot",
                0x3fef => "DW_AT_APPLE_sdk",
                else => unreachable,
            },
            else => inline for (@typeInfo(dwarf.AT).Struct.decls) |x| {
                if (@field(dwarf.AT, x.name) == at) {
                    break "DW_AT_" ++ x.name;
                }
            } else unreachable,
        };
        try writer.print("{s}", .{name});
    } else {
        try writer.print("DW_AT_unknown_{x}", .{at});
    }
}

const AbbrevTable = @This();

const std = @import("std");
const dwarf = std.dwarf;
const mem = std.mem;

const Allocator = mem.Allocator;
const Context = @import("Context.zig");
const DwarfDump = @import("DwarfDump.zig");
const Loc = DwarfDump.Loc;
