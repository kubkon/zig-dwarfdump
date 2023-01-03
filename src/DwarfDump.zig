const DwarfDump = @This();

const std = @import("std");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const leb = std.leb;
const log = std.log;
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;
const AbbrevLookupTable = std.AutoHashMap(u64, struct { pos: usize, len: usize });
const Context = @import("Context.zig");

gpa: Allocator,
ctx: *Context,

pub fn deinit(self: DwarfDump) void {
    self.ctx.destroy(self.gpa);
}

pub fn parse(gpa: Allocator, file: fs.File) !DwarfDump {
    const file_size = try file.getEndPos();
    const data = try file.readToEndAlloc(gpa, file_size);
    errdefer gpa.free(data);

    var self = DwarfDump{
        .gpa = gpa,
        .ctx = undefined,
    };

    self.ctx = try Context.parse(gpa, data);

    return self;
}

const DIContext = struct {
    debug_info: []const u8,
    debug_abbrev: []const u8,
    debug_str: []const u8,
};

pub fn printCompileUnits(self: DwarfDump, writer: anytype) !void {
    const ctx = DIContext{
        .debug_info = try self.ctx.getDebugInfoData(),
        .debug_abbrev = try self.ctx.getDebugAbbrevData(),
        .debug_str = try self.ctx.getDebugStringData(),
    };
    var cu_it = getCompileUnitIterator(ctx);
    while (try cu_it.next()) |cu| {
        const cuh = cu.value.cuh;

        var lookup = AbbrevLookupTable.init(self.gpa);
        defer lookup.deinit();
        try lookup.ensureUnusedCapacity(std.math.maxInt(u8));
        try genAbbrevLookupByKind(ctx, cuh.debug_abbrev_offset, &lookup);

        const next_unit_offset = cuh.header.length + @as(u64, if (cuh.header.is64Bit())
            @sizeOf(u64)
        else
            @sizeOf(u32));

        try writer.writeAll("__debug_info contents:\n");
        try writer.print("0x{x:0>16}: Compile Unit: length = 0x{x:0>16}, format = {s}, version = 0x{x:0>4}, abbr_offset = 0x{x:0>16}, addr_size = 0x{x:0>2} (next unit at 0x{x:0>16})\n", .{
            cu.off,
            cuh.header.length,
            if (cuh.header.is64Bit()) "DWARF64" else "DWARF32",
            cuh.version,
            cuh.debug_abbrev_offset,
            cuh.address_size,
            next_unit_offset,
        });
        try writer.writeByte('\n');

        if (cuh.version != 4) {
            log.err("TODO: handle DWARFv5", .{});
            return error.TODODwarfv5;
        }

        var children: usize = 0;
        const max_indent: usize = 20; // TODO: this needs reworking

        var abbrev_it = cu.value.getAbbrevEntryIterator(ctx);
        while (try abbrev_it.next(lookup)) |entry| {
            if (entry.value.tag == 0) {
                try writer.print("0x{x:0>16}: ", .{entry.off});
                try formatIndent(children * 2, writer);
                try writer.writeAll("NULL\n\n");
                children -= 1;
                continue;
            }

            try writer.print("0x{x:0>16}: ", .{entry.off});
            try formatIndent(children * 2, writer);
            try writer.print("{s}\n", .{formatDIETag(entry.value.tag)});

            var low_pc: ?u64 = null;
            var attr_it = entry.value.getAttributeIterator(ctx, cuh);
            while (try attr_it.next()) |attr| {
                try formatIndent(children * 2, writer);
                try writer.print("{s: <22}{s: <30}", .{ "", formatATName(attr.value.name) });
                try formatIndent(max_indent - children * 2, writer);

                switch (attr.value.name) {
                    dwarf.AT.stmt_list,
                    dwarf.AT.ranges,
                    => {
                        const sec_offset = attr.value.getSecOffset(ctx, cuh) orelse return error.MalformedDwarf;
                        try writer.print("({x:0>16})\n", .{sec_offset});
                    },

                    dwarf.AT.low_pc => {
                        const addr = attr.value.getAddr(ctx, cuh) orelse return error.MalformedDwarf;
                        low_pc = addr;
                        try writer.print("({x:0>16})\n", .{addr});
                    },

                    dwarf.AT.high_pc => {
                        if (try attr.value.getConstant(ctx)) |offset| {
                            try writer.print("({x:0>16})\n", .{offset + low_pc.?});
                        } else if (attr.value.getAddr(ctx, cuh)) |addr| {
                            try writer.print("({x:0>16})\n", .{addr});
                        } else return error.MalformedDwarf;
                    },

                    dwarf.AT.type,
                    dwarf.AT.abstract_origin,
                    => {
                        const off = (try attr.value.getReference(ctx)) orelse return error.MalformedDwarf;
                        try writer.print("({x})\n", .{off});
                    },

                    dwarf.AT.comp_dir,
                    dwarf.AT.producer,
                    dwarf.AT.name,
                    dwarf.AT.linkage_name,
                    => {
                        const str = attr.value.getString(ctx, cuh) orelse return error.MalformedDwarf;
                        try writer.print("(\"{s}\")\n", .{str});
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
                        const value = try attr.value.getConstant(ctx) orelse return error.MalformedDwarf;
                        try writer.print("({x:0>16})\n", .{value});
                    },

                    dwarf.AT.location,
                    dwarf.AT.frame_base,
                    => {
                        if (try attr.value.getExprloc(ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else {
                            try writer.print("error: TODO check and parse loclist\n", .{});
                        }
                    },

                    dwarf.AT.data_member_location => {
                        if (try attr.value.getConstant(ctx)) |value| {
                            try writer.print("({x:0>16})\n", .{value});
                        } else if (try attr.value.getExprloc(ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else {
                            try writer.print("error: TODO check and parse loclist\n", .{});
                        }
                    },

                    dwarf.AT.const_value => {
                        if (try attr.value.getConstant(ctx)) |value| {
                            try writer.print("({x:0>16})\n", .{value});
                        } else if (attr.value.getString(ctx, cuh)) |str| {
                            try writer.print("(\"{s}\")\n", .{str});
                        } else {
                            try writer.print("error: TODO check and parse block\n", .{});
                        }
                    },

                    dwarf.AT.count => {
                        if (try attr.value.getConstant(ctx)) |value| {
                            try writer.print("({x:0>16})\n", .{value});
                        } else if (try attr.value.getExprloc(ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else if (try attr.value.getReference(ctx)) |off| {
                            try writer.print("({x:0>16})\n", .{off});
                        } else return error.MalformedDwarf;
                    },

                    dwarf.AT.byte_size,
                    dwarf.AT.bit_size,
                    => {
                        if (try attr.value.getConstant(ctx)) |value| {
                            try writer.print("({x})\n", .{value});
                        } else if (try attr.value.getReference(ctx)) |off| {
                            try writer.print("({x})\n", .{off});
                        } else if (try attr.value.getExprloc(ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else return error.MalformedDwarf;
                    },

                    dwarf.AT.noreturn,
                    dwarf.AT.external,
                    => {
                        const flag = attr.value.getFlag(ctx) orelse return error.MalformedDwarf;
                        try writer.print("{}\n", .{flag});
                    },

                    else => {
                        try writer.print("error: unhandled form 0x{x} for attribute\n", .{attr.value.form});
                    },
                }
            }
            try writer.writeByte('\n');

            if (entry.value.hasChildren()) {
                children += 1;
            }
        }
    }
}

fn formatIndent(len: usize, writer: anytype) !void {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        try writer.writeByte(' ');
    }
}

fn formatLang(value: u16) []const u8 {
    return switch (value) {
        std.dwarf.LANG.C99 => "DW_LANG_C99",
        else => "DW_LANG_unknown",
    };
}

fn formatDIETag(tag: u64) []const u8 {
    return switch (tag) {
        std.dwarf.TAG.compile_unit => "DW_TAG_compile_unit",
        std.dwarf.TAG.variable => "DW_TAG_variable",
        std.dwarf.TAG.subprogram => "DW_TAG_subprogram",
        std.dwarf.TAG.formal_parameter => "DW_TAG_formal_parameter",
        std.dwarf.TAG.enumeration_type => "DW_TAG_enumeration_type",
        std.dwarf.TAG.enumerator => "DW_TAG_enumerator",
        std.dwarf.TAG.structure_type => "DW_TAG_structure_type",
        std.dwarf.TAG.union_type => "DW_TAG_union_type",
        std.dwarf.TAG.member => "DW_TAG_member",
        std.dwarf.TAG.array_type => "DW_TAG_array_type",
        std.dwarf.TAG.subrange_type => "DW_TAG_subrange_type",
        std.dwarf.TAG.base_type => "DW_TAG_base_type",
        std.dwarf.TAG.const_type => "DW_TAG_const_type",
        std.dwarf.TAG.packed_type => "DW_TAG_packed_type",
        std.dwarf.TAG.pointer_type => "DW_TAG_pointer_type",
        std.dwarf.TAG.reference_type => "DW_TAG_reference_type",
        std.dwarf.TAG.restrict_type => "DW_TAG_restrict_type",
        std.dwarf.TAG.rvalue_reference_type => "DW_TAG_rvalue_reference_type",
        std.dwarf.TAG.shared_type => "DW_TAG_shared_type",
        std.dwarf.TAG.volatile_type => "DW_TAG_volatile_type",
        std.dwarf.TAG.typedef => "DW_TAG_typedef",
        std.dwarf.TAG.lexical_block => "DW_TAG_lexical_block",
        std.dwarf.TAG.subroutine_type => "DW_TAG_subroutine_type",
        std.dwarf.TAG.inlined_subroutine => "DW_TAG_inlined_subroutine",
        std.dwarf.TAG.unspecified_parameters => "DW_TAG_unspecified_parameters",
        std.dwarf.TAG.label => "DW_TAG_label",
        std.dwarf.TAG.unspecified_type => "DW_TAG_unspecified_type",

        0x4109 => "DW_TAG_GNU_call_site",
        0x410a => "DW_TAG_GNU_call_site_parameter",

        else => blk: {
            log.debug("TODO: unhandled TAG value: {x}", .{tag});
            break :blk "DW_TAG_unknown";
        },
    };
}

fn formatATName(at: u64) []const u8 {
    return switch (at) {
        std.dwarf.AT.name => "DW_AT_name",
        std.dwarf.AT.producer => "DW_AT_producer",
        std.dwarf.AT.language => "DW_AT_language",
        std.dwarf.AT.stmt_list => "DW_AT_stmt_list",
        std.dwarf.AT.comp_dir => "DW_AT_comp_dir",
        std.dwarf.AT.low_pc => "DW_AT_low_pc",
        std.dwarf.AT.high_pc => "DW_AT_high_pc",
        std.dwarf.AT.type => "DW_AT_type",
        std.dwarf.AT.decl_file => "DW_AT_decl_file",
        std.dwarf.AT.decl_line => "DW_AT_decl_line",
        std.dwarf.AT.location => "DW_AT_location",
        std.dwarf.AT.count => "DW_AT_count",
        std.dwarf.AT.encoding => "DW_AT_encoding",
        std.dwarf.AT.byte_size => "DW_AT_byte_size",
        std.dwarf.AT.bit_size => "DW_AT_bit_size",
        std.dwarf.AT.bit_offset => "DW_AT_bit_offset",
        std.dwarf.AT.prototyped => "DW_AT_prototyped",
        std.dwarf.AT.frame_base => "DW_AT_frame_base",
        std.dwarf.AT.external => "DW_AT_external",
        std.dwarf.AT.data_member_location => "DW_AT_data_member_location",
        std.dwarf.AT.const_value => "DW_AT_const_value",
        std.dwarf.AT.declaration => "DW_AT_declaration",
        std.dwarf.AT.abstract_origin => "DW_AT_abstract_origin",
        std.dwarf.AT.ranges => "DW_AT_ranges",
        std.dwarf.AT.@"inline" => "DW_AT_inline",
        std.dwarf.AT.call_file => "DW_AT_call_file",
        std.dwarf.AT.call_line => "DW_AT_call_line",
        std.dwarf.AT.call_column => "DW_AT_call_column",
        std.dwarf.AT.linkage_name => "DW_AT_linkage_name",
        std.dwarf.AT.artificial => "DW_AT_artificial",
        std.dwarf.AT.data_bit_offset => "DW_AT_data_bit_offset",
        std.dwarf.AT.noreturn => "DW_AT_noreturn",
        std.dwarf.AT.alignment => "DW_AT_alignment",

        0x2111 => "DW_AT_GNU_call_site_value",
        0x2113 => "DW_AT_GNU_call_site_target",
        0x2115 => "DW_AT_GNU_tail_cail",
        0x2117 => "DW_AT_GNU_all_call_sites",
        0x3e02 => "DW_AT_LLVM_sysroot",
        0x3fef => "DW_AT_APPLE_sdk",

        else => blk: {
            log.debug("TODO: unhandled AT value: {x}", .{at});
            break :blk "DW_AT_unknown";
        },
    };
}

fn Result(comptime T: type) type {
    return struct { off: usize, value: T };
}

fn result(off: usize, value: anytype) Result(@TypeOf(value)) {
    return .{ .off = off, .value = value };
}

fn getCompileUnitIterator(ctx: DIContext) CompileUnitIterator {
    return .{ .ctx = ctx };
}

const CompileUnitIterator = struct {
    ctx: DIContext,
    pos: usize = 0,

    fn next(self: *CompileUnitIterator) !?Result(CompileUnit) {
        if (self.pos >= self.ctx.debug_info.len) return null;

        var stream = std.io.fixedBufferStream(self.ctx.debug_info);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const cuh = try CompileUnit.Header.read(reader);
        const total_length = cuh.header.length + @as(u64, if (cuh.header.is64Bit())
            @sizeOf(u64)
        else
            @sizeOf(u32));

        const cu = CompileUnit{
            .cuh = cuh,
            .debug_info_off = creader.bytes_read,
        };
        const res = result(self.pos, cu);

        self.pos += total_length;

        return res;
    }
};

fn genAbbrevLookupByKind(ctx: DIContext, off: usize, lookup: *AbbrevLookupTable) !void {
    const data = ctx.debug_abbrev[off..];
    var stream = std.io.fixedBufferStream(data);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    while (true) {
        const kind = try leb.readULEB128(u64, reader);

        if (kind == 0) break;

        const pos = creader.bytes_read;
        _ = try leb.readULEB128(u64, reader); // TAG
        _ = try reader.readByte(); // CHILDREN

        while (true) {
            const name = try leb.readULEB128(u64, reader);
            const form = try leb.readULEB128(u64, reader);

            if (name == 0 and form == 0) break;
        }

        try lookup.putNoClobber(kind, .{
            .pos = pos,
            .len = creader.bytes_read - pos - 2,
        });
    }
}

const CompileUnit = struct {
    cuh: Header,
    debug_info_off: usize,

    const Header = struct {
        header: DwarfHeader,
        version: u16,
        debug_abbrev_offset: u64,
        address_size: u8,

        fn read(reader: anytype) !Header {
            const header = try DwarfHeader.parseReader(reader);
            const version = try reader.readIntLittle(u16);
            const debug_abbrev_offset = if (header.is64Bit())
                try reader.readIntLittle(u64)
            else
                try reader.readIntLittle(u32);
            const address_size = try reader.readIntLittle(u8);

            return Header{
                .header = header,
                .version = version,
                .debug_abbrev_offset = debug_abbrev_offset,
                .address_size = address_size,
            };
        }
    };

    inline fn getDebugInfo(self: CompileUnit, ctx: DIContext) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.cuh.header.length];
    }

    fn getAbbrevEntryIterator(self: CompileUnit, ctx: DIContext) AbbrevEntryIterator {
        return .{ .ctx = ctx, .cu = self };
    }
};

const DwarfHeader = struct {
    length: u64,
    format: enum {
        @"32bit",
        @"64bit",
    },

    fn is64Bit(header: DwarfHeader) bool {
        return header.format == .@"64bit";
    }

    fn size(header: DwarfHeader) usize {
        return if (header.is64Bit()) 12 else 4;
    }

    fn parse(buffer: []const u8) !DwarfHeader {
        var stream = std.io.fixedBufferStream(buffer);
        return parseReader(stream.reader());
    }

    fn parseReader(reader: anytype) !DwarfHeader {
        var length: u64 = try reader.readIntLittle(u32);
        const is_64bit = length == 0xffffffff;
        if (is_64bit) {
            length = try reader.readIntLittle(u64);
        }
        return DwarfHeader{
            .length = length,
            .format = if (is_64bit) .@"64bit" else .@"32bit",
        };
    }
};

const AbbrevEntryIterator = struct {
    ctx: DIContext,
    cu: CompileUnit,
    pos: usize = 0,

    fn next(self: *AbbrevEntryIterator, lookup: AbbrevLookupTable) !?Result(AbbrevEntry) {
        if (self.pos + self.cu.debug_info_off >= self.ctx.debug_info.len) return null;

        const debug_info = self.ctx.debug_info[self.pos + self.cu.debug_info_off ..];
        var stream = std.io.fixedBufferStream(debug_info);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const kind = try leb.readULEB128(u64, reader);
        self.pos += creader.bytes_read;

        if (kind == 0) {
            return result(self.pos + self.cu.debug_info_off - creader.bytes_read, AbbrevEntry.null());
        }

        const abbrev_pos = lookup.get(kind) orelse return error.MalformedDwarf;
        const len = try findAbbrevEntrySize(
            self.ctx,
            abbrev_pos.pos,
            abbrev_pos.len,
            self.pos + self.cu.debug_info_off,
            self.cu.cuh,
        );
        const entry = try getAbbrevEntry(
            self.ctx,
            abbrev_pos.pos,
            abbrev_pos.len,
            self.pos + self.cu.debug_info_off,
            len,
        );

        self.pos += len;

        return result(self.pos + self.cu.debug_info_off - len - creader.bytes_read, entry);
    }
};

const AbbrevEntry = struct {
    tag: u64,
    children: u8,
    debug_abbrev_off: usize,
    debug_abbrev_len: usize,
    debug_info_off: usize,
    debug_info_len: usize,

    fn @"null"() AbbrevEntry {
        return .{
            .tag = 0,
            .children = dwarf.CHILDREN.no,
            .debug_abbrev_off = 0,
            .debug_abbrev_len = 0,
            .debug_info_off = 0,
            .debug_info_len = 0,
        };
    }

    fn hasChildren(self: AbbrevEntry) bool {
        return self.children == dwarf.CHILDREN.yes;
    }

    inline fn getDebugInfo(self: AbbrevEntry, ctx: DIContext) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.debug_info_len];
    }

    inline fn getDebugAbbrev(self: AbbrevEntry, ctx: DIContext) []const u8 {
        return ctx.debug_abbrev[self.debug_abbrev_off..][0..self.debug_abbrev_len];
    }

    fn getAttributeIterator(self: AbbrevEntry, ctx: DIContext, cuh: CompileUnit.Header) AttributeIterator {
        return .{ .entry = self, .ctx = ctx, .cuh = cuh };
    }
};

const Attribute = struct {
    name: u64,
    form: u64,
    debug_info_off: usize,
    debug_info_len: usize,

    inline fn getDebugInfo(self: Attribute, ctx: DIContext) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.debug_info_len];
    }

    fn getFlag(self: Attribute, ctx: DIContext) ?bool {
        const debug_info = self.getDebugInfo(ctx);

        switch (self.form) {
            dwarf.FORM.flag => return debug_info[0] == 1,
            dwarf.FORM.flag_present => return true,
            else => return null,
        }
    }

    fn getString(self: Attribute, ctx: DIContext, cuh: CompileUnit.Header) ?[]const u8 {
        const debug_info = self.getDebugInfo(ctx);

        switch (self.form) {
            dwarf.FORM.string => {
                return mem.sliceTo(@ptrCast([*:0]const u8, debug_info.ptr), 0);
            },
            dwarf.FORM.strp => {
                const off = if (cuh.header.is64Bit())
                    mem.readIntLittle(u64, debug_info[0..8])
                else
                    mem.readIntLittle(u32, debug_info[0..4]);
                return getDwarfString(ctx.debug_str, off);
            },
            else => return null,
        }
    }

    fn getSecOffset(self: Attribute, ctx: DIContext, cuh: CompileUnit.Header) ?u64 {
        if (self.form != dwarf.FORM.sec_offset) return null;
        const debug_info = self.getDebugInfo(ctx);
        const value = if (cuh.header.is64Bit())
            mem.readIntLittle(u64, debug_info[0..8])
        else
            mem.readIntLittle(u32, debug_info[0..4]);
        return value;
    }

    fn getConstant(self: Attribute, ctx: DIContext) !?i128 {
        const debug_info = self.getDebugInfo(ctx);
        var stream = std.io.fixedBufferStream(debug_info);
        const reader = stream.reader();

        return switch (self.form) {
            dwarf.FORM.data1 => debug_info[0],
            dwarf.FORM.data2 => mem.readIntLittle(u16, debug_info[0..2]),
            dwarf.FORM.data4 => mem.readIntLittle(u32, debug_info[0..4]),
            dwarf.FORM.data8 => mem.readIntLittle(u64, debug_info[0..8]),
            dwarf.FORM.udata => try leb.readULEB128(u64, reader),
            dwarf.FORM.sdata => try leb.readILEB128(i64, reader),
            else => null,
        };
    }

    fn getReference(self: Attribute, ctx: DIContext) !?u64 {
        const debug_info = self.getDebugInfo(ctx);
        var stream = std.io.fixedBufferStream(debug_info);
        const reader = stream.reader();

        return switch (self.form) {
            dwarf.FORM.ref1 => debug_info[0],
            dwarf.FORM.ref2 => mem.readIntLittle(u16, debug_info[0..2]),
            dwarf.FORM.ref4 => mem.readIntLittle(u32, debug_info[0..4]),
            dwarf.FORM.ref8 => mem.readIntLittle(u64, debug_info[0..8]),
            dwarf.FORM.ref_udata => try leb.readULEB128(u64, reader),
            else => null,
        };
    }

    fn getAddr(self: Attribute, ctx: DIContext, cuh: CompileUnit.Header) ?u64 {
        if (self.form != dwarf.FORM.addr) return null;
        const debug_info = self.getDebugInfo(ctx);
        return switch (cuh.address_size) {
            1 => debug_info[0],
            2 => mem.readIntLittle(u16, debug_info[0..2]),
            4 => mem.readIntLittle(u32, debug_info[0..4]),
            8 => mem.readIntLittle(u64, debug_info[0..8]),
            else => unreachable,
        };
    }

    fn getExprloc(self: Attribute, ctx: DIContext) !?[]const u8 {
        if (self.form != dwarf.FORM.exprloc) return null;
        const debug_info = self.getDebugInfo(ctx);
        var stream = std.io.fixedBufferStream(debug_info);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();
        const expr_len = try leb.readULEB128(u64, reader);
        return debug_info[creader.bytes_read..][0..expr_len];
    }

    // fn getBlock(self: Attribute, ctx: Context) ?[]const u8 {
    //     const debug_info = self.get
    // }
};

const AttributeIterator = struct {
    entry: AbbrevEntry,
    ctx: DIContext,
    cuh: CompileUnit.Header,
    debug_abbrev_pos: usize = 0,
    debug_info_pos: usize = 0,

    fn next(self: *AttributeIterator) !?Result(Attribute) {
        const debug_abbrev = self.entry.getDebugAbbrev(self.ctx);
        if (self.debug_abbrev_pos >= debug_abbrev.len) return null;

        var stream = std.io.fixedBufferStream(debug_abbrev[self.debug_abbrev_pos..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const name = try leb.readULEB128(u64, reader);
        const form = try leb.readULEB128(u64, reader);

        self.debug_abbrev_pos += creader.bytes_read;

        const len = try findFormSize(
            self.ctx,
            form,
            self.debug_info_pos + self.entry.debug_info_off,
            self.cuh,
        );
        const attr = Attribute{
            .name = name,
            .form = form,
            .debug_info_off = self.debug_info_pos + self.entry.debug_info_off,
            .debug_info_len = len,
        };

        self.debug_info_pos += len;

        return result(attr.debug_info_off, attr);
    }
};

fn getAbbrevEntry(ctx: DIContext, da_off: usize, da_len: usize, di_off: usize, di_len: usize) !AbbrevEntry {
    const debug_abbrev = ctx.debug_abbrev[da_off..][0..da_len];
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    const tag = try leb.readULEB128(u64, reader);
    const children = switch (tag) {
        std.dwarf.TAG.const_type,
        std.dwarf.TAG.packed_type,
        std.dwarf.TAG.pointer_type,
        std.dwarf.TAG.reference_type,
        std.dwarf.TAG.restrict_type,
        std.dwarf.TAG.rvalue_reference_type,
        std.dwarf.TAG.shared_type,
        std.dwarf.TAG.volatile_type,
        => if (creader.bytes_read == da_len) std.dwarf.CHILDREN.no else try reader.readByte(),
        else => try reader.readByte(),
    };

    return AbbrevEntry{
        .tag = tag,
        .children = children,
        .debug_abbrev_off = creader.bytes_read + da_off,
        .debug_abbrev_len = da_len - creader.bytes_read,
        .debug_info_off = di_off,
        .debug_info_len = di_len,
    };
}

fn findFormSize(ctx: DIContext, form: u64, di_off: usize, cuh: CompileUnit.Header) !usize {
    const debug_info = ctx.debug_info[di_off..];
    var stream = std.io.fixedBufferStream(debug_info);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    return switch (form) {
        dwarf.FORM.strp,
        dwarf.FORM.sec_offset,
        dwarf.FORM.ref_addr,
        => if (cuh.header.is64Bit()) @sizeOf(u64) else @sizeOf(u32),

        dwarf.FORM.addr => cuh.address_size,

        dwarf.FORM.block1,
        dwarf.FORM.block2,
        dwarf.FORM.block4,
        dwarf.FORM.block,
        => blk: {
            const len: u64 = switch (form) {
                dwarf.FORM.block1 => try reader.readIntLittle(u8),
                dwarf.FORM.block2 => try reader.readIntLittle(u16),
                dwarf.FORM.block4 => try reader.readIntLittle(u32),
                dwarf.FORM.block => try leb.readULEB128(u64, reader),
                else => unreachable,
            };
            var i: u64 = 0;
            while (i < len) : (i += 1) {
                _ = try reader.readByte();
            }
            break :blk creader.bytes_read;
        },

        dwarf.FORM.exprloc => blk: {
            const len = try leb.readULEB128(u64, reader);
            var i: u64 = 0;
            while (i < len) : (i += 1) {
                _ = try reader.readByte();
            }
            break :blk creader.bytes_read;
        },
        dwarf.FORM.flag_present => 0,

        dwarf.FORM.data1,
        dwarf.FORM.ref1,
        dwarf.FORM.flag,
        => @sizeOf(u8),

        dwarf.FORM.data2,
        dwarf.FORM.ref2,
        => @sizeOf(u16),

        dwarf.FORM.data4,
        dwarf.FORM.ref4,
        => @sizeOf(u32),

        dwarf.FORM.data8,
        dwarf.FORM.ref8,
        dwarf.FORM.ref_sig8,
        => @sizeOf(u64),

        dwarf.FORM.udata,
        dwarf.FORM.ref_udata,
        => blk: {
            _ = try leb.readULEB128(u64, reader);
            break :blk creader.bytes_read;
        },

        dwarf.FORM.sdata => blk: {
            _ = try leb.readILEB128(i64, reader);
            break :blk creader.bytes_read;
        },

        dwarf.FORM.string => blk: {
            var count: usize = 0;
            while (true) {
                const byte = try reader.readByte();
                count += 1;
                if (byte == 0x0) break;
            }
            break :blk count;
        },

        else => {
            log.err("unhandled DW_FORM_* value with identifier {x}", .{form});
            return error.UnhandledDwFormValue;
        },
    };
}

fn findAbbrevEntrySize(ctx: DIContext, da_off: usize, da_len: usize, di_off: usize, cuh: CompileUnit.Header) !usize {
    const debug_abbrev = ctx.debug_abbrev[da_off..][0..da_len];
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    const tag = try leb.readULEB128(u64, reader);
    _ = switch (tag) {
        std.dwarf.TAG.const_type,
        std.dwarf.TAG.packed_type,
        std.dwarf.TAG.pointer_type,
        std.dwarf.TAG.reference_type,
        std.dwarf.TAG.restrict_type,
        std.dwarf.TAG.rvalue_reference_type,
        std.dwarf.TAG.shared_type,
        std.dwarf.TAG.volatile_type,
        => if (creader.bytes_read != da_len) try reader.readByte(),
        else => try reader.readByte(),
    };

    var len: usize = 0;
    while (creader.bytes_read < debug_abbrev.len) {
        _ = try leb.readULEB128(u64, reader);
        const form = try leb.readULEB128(u64, reader);
        const form_len = try findFormSize(ctx, form, di_off + len, cuh);
        len += form_len;
    }

    return len;
}

fn getDwarfString(debug_str: []const u8, off: u64) []const u8 {
    assert(off < debug_str.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, debug_str.ptr + off), 0);
}

pub fn printEhFrame(self: DwarfDump, writer: anytype) !void {
    switch (self.ctx.tag) {
        .elf => return error.Unimplemented,
        .macho => {},
    }

    const macho = self.ctx.cast(Context.MachO).?;
    const addr_size: u8 = 8;
    const sect = macho.getSectionByName("__TEXT", "__eh_frame") orelse {
        try writer.print("No __TEXT,__eh_frame section.\n", .{});
        return;
    };

    var cies = std.AutoArrayHashMap(u64, CommonInformationEntry).init(self.gpa);
    defer cies.deinit();

    var fdes = std.ArrayList(struct { fde: FrameDescriptionEntry, offset: u64 }).init(self.gpa);
    defer fdes.deinit();

    const data = macho.getSectionData(sect);
    var offset: u64 = 0;

    while (true) {
        if (offset >= data.len) break;

        const header = try DwarfHeader.parse(data[offset..]);
        var tmp_offset = header.size();

        const id = if (header.is64Bit())
            mem.readIntLittle(u64, data[offset + tmp_offset ..][0..8])
        else
            mem.readIntLittle(u32, data[offset + tmp_offset ..][0..4]);
        tmp_offset += if (header.is64Bit()) 8 else 4;

        if (id == 0) { // TODO hard-coding for now
            // CIE
            const cie = try CommonInformationEntry.parse(header, id, addr_size, data[offset + tmp_offset ..]);
            try cies.putNoClobber(offset, cie);
            offset += cie.header.length + cie.header.size();
        } else {
            // FDE
            const fde = try FrameDescriptionEntry.parse(header, id, addr_size, data[offset + tmp_offset ..]);
            try fdes.append(.{ .fde = fde, .offset = offset });
            offset += fde.header.length + fde.header.size();
        }
    }

    try writer.writeAll("__TEXT,__eh_frame contents:\n");

    for (cies.keys()) |cie_offset| {
        const cie = cies.get(cie_offset).?;

        try writer.writeAll("\nCIE:\n");
        try writer.print("  {s: <30}: {d}\n", .{ "Length", cie.header.length });
        try writer.print("  {s: <30}: {d}\n", .{ "Id", cie.id });
        try writer.print("  {s: <30}: {d}\n", .{ "Version", cie.version });
        try writer.print("  {s: <30}: {s}\n", .{ "Augmentation", cie.augmentation_str });
        try writer.print("  {s: <30}: {d}\n", .{ "Code Alignment Factor", cie.code_alignment_factor });
        try writer.print("  {s: <30}: {d}\n", .{ "Data Alignment Factor", cie.data_alignment_factor });
        try writer.print("  {s: <30}: {d}\n", .{ "Return Address Register", cie.return_address_register });
        try writer.print("  {s: <30}: {d}\n", .{ "Augmentation Length", cie.augmentation_data.len });
        try writer.print("  {s: <30}: 0x{x}\n", .{ "FDE Pointer Encoding", cie.fde_pointer_encoding });
        try writer.print("  {s: <30}: 0x{x}\n", .{ "LSDA Pointer Encoding", cie.lsda_pointer_encoding });

        if (cie.personality) |_| {
            try writer.print("  {s: <30}: 0x{x}\n", .{ "Personality", cie.personality.? });
            try writer.print("  {s: <30}: 0x{x}\n", .{ "Personality Encoding", cie.personality_encoding.? });
        }

        try writer.print("  {s: <30}: 0x{x}\n", .{ "Augmentation Data", std.fmt.fmtSliceHexLower(cie.augmentation_data) });
        try writer.print("  {s: <30}: 0x{x}\n", .{
            "Initial Instructions",
            std.fmt.fmtSliceHexLower(cie.initial_instructions),
        });

        for (fdes.items) |fde_with_offset| {
            const fde = fde_with_offset.fde;
            if (fde_with_offset.offset + fde.header.size() - fde.cie_pointer != cie_offset) continue;

            try writer.writeAll("\nFDE:\n");
            try writer.print("  {s: <30}: {d}\n", .{ "Length", fde.header.length });
            try writer.print("  {s: <30}: 0x{x}\n", .{ "CIE Pointer", fde.cie_pointer });
            try writer.print("  {s: <30}: 0x{x}\n", .{ "PC Begin", fde.pc_begin });
            try writer.print("  {s: <30}: {d}\n", .{ "PC Range", fde.pc_range });
            try writer.print("  {s: <30}: {d}\n", .{ "Augmentation Length", fde.augmentation_data.len });
            try writer.print("  {s: <30}: 0x{x}\n", .{ "Instructions", std.fmt.fmtSliceHexLower(fde.instructions) });
        }
    }
}

const CommonInformationEntry = struct {
    header: DwarfHeader,
    id: u64,
    version: u8,
    augmentation_str: []const u8,
    code_alignment_factor: u64,
    data_alignment_factor: i64,
    return_address_register: u64,
    augmentation_data: []const u8,
    fde_pointer_encoding: u32,
    lsda_pointer_encoding: u32,
    personality: ?u64,
    personality_encoding: ?u8,
    initial_instructions: []const u8,

    fn parse(header: DwarfHeader, id: u64, addr_size: u8, buffer: []const u8) !CommonInformationEntry {
        var stream = std.io.fixedBufferStream(buffer);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const version = try reader.readByte();
        const augmentation_str = blk: {
            const augmentation = mem.sliceTo(@ptrCast([*:0]const u8, buffer.ptr + creader.bytes_read), 0);
            stream.pos += augmentation.len + 1;
            creader.bytes_read += augmentation.len + 1;
            break :blk augmentation;
        };

        const code_alignment_factor = try leb.readULEB128(u64, reader);
        const data_alignment_factor = try leb.readILEB128(i64, reader);
        const return_address_register = try leb.readULEB128(u64, reader);

        var augmentation_start: usize = 0;
        var augmentation_length: usize = 0;
        var augmentation_data: []const u8 = &[0]u8{};
        var fde_pointer_encoding: u32 = 0;
        var lsda_pointer_encoding: u32 = 0;
        var personality: ?u64 = null;
        var personality_encoding: ?u8 = null;

        for (augmentation_str) |ch, i| switch (ch) {
            'z' => if (i > 0) {
                return error.MalformedAugmentationString;
            } else {
                augmentation_length = try leb.readULEB128(u64, reader);
                augmentation_start = creader.bytes_read;
            },
            'R' => {
                fde_pointer_encoding = try reader.readByte();
            },
            'P' => {
                personality_encoding = try reader.readByte();
                personality = try getEncodedPointer(personality_encoding.?, addr_size, 0, reader); // TODO resolve relocs
            },
            'L' => {
                lsda_pointer_encoding = try reader.readByte();
            },
            'S', 'B', 'G' => {},
            else => return error.UnknownAugmentationStringValue,
        };

        if (augmentation_length > 0) {
            augmentation_data = buffer[augmentation_start..][0..augmentation_length];
        }

        const nread = creader.bytes_read + header.size() + (if (header.is64Bit()) @as(u64, 8) else 4);
        const initial_instructions = buffer[creader.bytes_read..][0 .. header.length + header.size() - nread];

        return CommonInformationEntry{
            .header = header,
            .id = id,
            .version = version,
            .augmentation_str = augmentation_str,
            .code_alignment_factor = code_alignment_factor,
            .data_alignment_factor = data_alignment_factor,
            .return_address_register = return_address_register,
            .augmentation_data = augmentation_data,
            .fde_pointer_encoding = fde_pointer_encoding,
            .lsda_pointer_encoding = lsda_pointer_encoding,
            .personality = personality,
            .personality_encoding = personality_encoding,
            .initial_instructions = initial_instructions,
        };
    }
};

const FrameDescriptionEntry = struct {
    header: DwarfHeader,
    cie_pointer: u64,
    pc_begin: u64,
    pc_range: u64,
    augmentation_data: []const u8,
    instructions: []const u8,

    fn parse(header: DwarfHeader, cie_pointer: u64, addr_size: u16, buffer: []const u8) !FrameDescriptionEntry {
        var stream = std.io.fixedBufferStream(buffer);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const pc_begin = if (addr_size == 8) try reader.readIntLittle(u64) else try reader.readIntLittle(u32);
        const pc_range = if (addr_size == 8) try reader.readIntLittle(u64) else try reader.readIntLittle(u32);

        const augmentation_length = try leb.readULEB128(u64, reader);
        const augmentation_data = buffer[creader.bytes_read..][0..augmentation_length];
        creader.bytes_read += augmentation_length;
        stream.pos += augmentation_length;

        const nread = creader.bytes_read + header.size() + (if (header.is64Bit()) @as(u64, 8) else 4);
        const instructions = buffer[creader.bytes_read..][0 .. header.length + header.size() - nread];

        return FrameDescriptionEntry{
            .header = header,
            .cie_pointer = cie_pointer,
            .pc_begin = pc_begin,
            .pc_range = pc_range,
            .augmentation_data = augmentation_data,
            .instructions = instructions,
        };
    }
};

const EH_PE = struct {
    const absptr = 0x00;
    const uleb128 = 0x01;
    const udata2 = 0x02;
    const udata4 = 0x03;
    const udata8 = 0x04;
    const sleb128 = 0x09;
    const sdata2 = 0x0A;
    const sdata4 = 0x0B;
    const sdata8 = 0x0C;
    const pcrel = 0x10;
    const textrel = 0x20;
    const datarel = 0x30;
    const funcrel = 0x40;
    const aligned = 0x50;
    const indirect = 0x80;
    const omit = 0xFF;
};

fn getEncodedPointer(enc: u8, addr_size: u8, pcrel_offset: i64, reader: anytype) !?u64 {
    if (enc == EH_PE.omit) return null;

    var ptr: i64 = switch (enc & 0x0F) {
        EH_PE.absptr => switch (addr_size) {
            2 => @bitCast(i16, try reader.readIntLittle(u16)),
            4 => @bitCast(i32, try reader.readIntLittle(u32)),
            8 => @bitCast(i64, try reader.readIntLittle(u64)),
            else => return null,
        },
        EH_PE.udata2 => @bitCast(i16, try reader.readIntLittle(u16)),
        EH_PE.udata4 => @bitCast(i32, try reader.readIntLittle(u32)),
        EH_PE.udata8 => @bitCast(i64, try reader.readIntLittle(u64)),
        EH_PE.uleb128 => @bitCast(i64, try leb.readULEB128(u64, reader)),
        EH_PE.sdata2 => try reader.readIntLittle(i16),
        EH_PE.sdata4 => try reader.readIntLittle(i32),
        EH_PE.sdata8 => try reader.readIntLittle(i64),
        EH_PE.sleb128 => try leb.readILEB128(i64, reader),
        else => return null,
    };

    switch (enc & 0x70) {
        EH_PE.absptr => {},
        EH_PE.pcrel => ptr += pcrel_offset,
        EH_PE.datarel,
        EH_PE.textrel,
        EH_PE.funcrel,
        EH_PE.aligned,
        => return null,
        else => return null,
    }

    return @bitCast(u64, ptr);
}
