decls: std.ArrayListUnmanaged(AbbrevDecl) = .{},
loc: Loc,

pub fn deinit(table: *AbbrevTable, gpa: Allocator) void {
    table.decls.deinit(gpa);
}

pub fn format(
    table: AbbrevTable,
    comptime unused_fmt_string: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = unused_fmt_string;
    _ = options;
    for (table.decls) |decl| {
        try writer.print("{}\n", .{decl});
    }
}

pub const AbbrevDecl = struct {
    tag: dwarf.TAG,
    form: dwarf.FORM,
    loc: Loc,

    pub fn format(
        decl: AbbrevDecl,
        comptime unused_fmt_string: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = unused_fmt_string;
        _ = options;
        const is_tag_known = switch (decl.tag) {
            dwarf.TAG.lo_user...dwarf.TAG.hi_user => switch (decl.tag) {
                0x4109, 0x410a => true,
                else => false,
            },
            else => inline for (@typeInfo(dwarf.TAG).Struct.decls) |x| {
                if (@field(dwarf.TAG, x.name) == decl.tag) true;
            } else false,
        };
        if (is_tag_known) {
            const tag = switch (decl.tag) {
                dwarf.TAG.lo_user...dwarf.TAG.hi_user => switch (decl.tag) {
                    0x4109 => "DW_TAG_GNU_call_site",
                    0x410a => "DW_TAG_GNU_call_site_parameter",
                    else => unreachable, // sync'd with is_tag_known check above
                },
                else => inline for (@typeInfo(dwarf.TAG).Struct.decls) |x| {
                    if (@field(dwarf.TAG, x.name) == decl.tag) {
                        break "DW_TAG_" ++ x.name;
                    }
                } else unreachable, // sync'd with is_tag_known check above
            };
            try writer.print("{s}", .{tag});
        } else {
            try writer.print("DW_TAG_unknown_{x}", .{decl.tag});
        }
        try writer.writeByte(' ');
        inline for (@typeInfo(dwarf.FORM).Struct.decls) |x| {
            if (@field(dwarf.FORM, x.name) == decl.form) {
                try writer.print("{s}", .{x.name});
            }
        } else try writer.print("DW_FORM_unknown_{x}", .{decl.form});
    }
};

const AbbrevTable = @This();

const std = @import("std");
const dwarf = std.dwarf;

const Allocator = std.mem.Allocator;
const Context = @import("Context.zig");
const Loc = @import("DwarfDump.zig").Loc;
