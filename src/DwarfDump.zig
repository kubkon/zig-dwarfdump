const DwarfDump = @This();

const std = @import("std");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const abi = dwarf.abi;
const leb = std.leb;
const log = std.log;
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;
const AbbrevLookupTable = std.AutoHashMap(u64, struct { pos: usize, len: usize });
const Context = @import("Context.zig");
const VirtualMachine = dwarf.call_frame.VirtualMachine;

gpa: Allocator,
ctx: *Context,

pub fn deinit(self: DwarfDump) void {
    self.ctx.destroy(self.gpa);
}

pub fn parse(gpa: Allocator, file: fs.File) !DwarfDump {
    const file_size = try file.getEndPos();
    const data = try file.readToEndAlloc(gpa, @intCast(file_size));
    errdefer gpa.free(data);

    var self = DwarfDump{
        .gpa = gpa,
        .ctx = undefined,
    };

    self.ctx = try Context.parse(gpa, data);

    return self;
}

pub fn printCompileUnits(self: DwarfDump, writer: anytype) !void {
    var cu_it = getCompileUnitIterator(self.ctx);
    while (try cu_it.next()) |cu| {
        const cuh = cu.value.cuh;

        var lookup = AbbrevLookupTable.init(self.gpa);
        defer lookup.deinit();
        try lookup.ensureUnusedCapacity(std.math.maxInt(u8));
        try genAbbrevLookupByKind(self.ctx, cuh.debug_abbrev_offset, &lookup);

        const next_unit_offset = cu.off + cu.value.size();

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

        var abbrev_it = cu.value.getAbbrevEntryIterator(self.ctx);
        while (try abbrev_it.next(lookup)) |entry| {
            if (entry.value.tag == 0) {
                try writer.print("0x{x:0>16}: ", .{entry.off});
                try formatIndent(children * 2, writer);
                try writer.writeAll("NULL\n\n");
                children -= 1;
                if (children == 0) break;
                continue;
            }

            var buffer: [256]u8 = undefined;

            try writer.print("0x{x:0>16}: ", .{entry.off});
            try formatIndent(children * 2, writer);
            try writer.print("{s}\n", .{try formatDIETag(entry.value.tag, &buffer)});

            var low_pc: ?u64 = null;
            var attr_it = entry.value.getAttributeIterator(self.ctx, cuh);
            while (try attr_it.next()) |attr| {
                try formatIndent(children * 2, writer);
                try writer.print("{s: <22}{s: <30}", .{ "", try formatATName(attr.value.name, &buffer) });
                try formatIndent(max_indent - children * 2, writer);

                switch (attr.value.name) {
                    dwarf.AT.stmt_list,
                    dwarf.AT.ranges,
                    => {
                        const sec_offset = attr.value.getSecOffset(self.ctx, cuh) orelse return error.MalformedDwarf;
                        try writer.print("({x:0>16})\n", .{sec_offset});
                    },

                    dwarf.AT.low_pc => {
                        const addr = attr.value.getAddr(self.ctx, cuh) orelse return error.MalformedDwarf;
                        low_pc = addr;
                        try writer.print("({x:0>16})\n", .{addr});
                    },

                    dwarf.AT.high_pc => {
                        if (try attr.value.getConstant(self.ctx)) |offset| {
                            try writer.print("({x:0>16})\n", .{offset + low_pc.?});
                        } else if (attr.value.getAddr(self.ctx, cuh)) |addr| {
                            try writer.print("({x:0>16})\n", .{addr});
                        } else return error.MalformedDwarf;
                    },

                    dwarf.AT.type,
                    dwarf.AT.abstract_origin,
                    => {
                        const off = (try attr.value.getReference(self.ctx, cuh)) orelse return error.MalformedDwarf;
                        try writer.print("({x})\n", .{off});
                    },

                    dwarf.AT.comp_dir,
                    dwarf.AT.producer,
                    dwarf.AT.name,
                    dwarf.AT.linkage_name,
                    => {
                        const str = attr.value.getString(self.ctx, cuh) orelse return error.MalformedDwarf;
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
                        const value = try attr.value.getConstant(self.ctx) orelse return error.MalformedDwarf;
                        try writer.print("({x:0>16})\n", .{value});
                    },

                    dwarf.AT.location,
                    dwarf.AT.frame_base,
                    => {
                        if (try attr.value.getExprloc(self.ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else {
                            try writer.print("error: TODO check and parse loclist\n", .{});
                        }
                    },

                    dwarf.AT.data_member_location => {
                        if (try attr.value.getConstant(self.ctx)) |value| {
                            try writer.print("({x:0>16})\n", .{value});
                        } else if (try attr.value.getExprloc(self.ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else {
                            try writer.print("error: TODO check and parse loclist\n", .{});
                        }
                    },

                    dwarf.AT.const_value => {
                        if (try attr.value.getConstant(self.ctx)) |value| {
                            try writer.print("({x:0>16})\n", .{value});
                        } else if (attr.value.getString(self.ctx, cuh)) |str| {
                            try writer.print("(\"{s}\")\n", .{str});
                        } else {
                            try writer.print("error: TODO check and parse block\n", .{});
                        }
                    },

                    dwarf.AT.count => {
                        if (try attr.value.getConstant(self.ctx)) |value| {
                            try writer.print("({x:0>16})\n", .{value});
                        } else if (try attr.value.getExprloc(self.ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else if (try attr.value.getReference(self.ctx, cuh)) |off| {
                            try writer.print("({x:0>16})\n", .{off});
                        } else return error.MalformedDwarf;
                    },

                    dwarf.AT.byte_size,
                    dwarf.AT.bit_size,
                    => {
                        if (try attr.value.getConstant(self.ctx)) |value| {
                            try writer.print("({x})\n", .{value});
                        } else if (try attr.value.getReference(self.ctx, cuh)) |off| {
                            try writer.print("({x})\n", .{off});
                        } else if (try attr.value.getExprloc(self.ctx)) |list| {
                            try writer.print("(<0x{x}> {x})\n", .{ list.len, std.fmt.fmtSliceHexLower(list) });
                        } else return error.MalformedDwarf;
                    },

                    dwarf.AT.noreturn,
                    dwarf.AT.external,
                    dwarf.AT.variable_parameter,
                    dwarf.AT.trampoline,
                    => {
                        const flag = attr.value.getFlag(self.ctx) orelse return error.MalformedDwarf;
                        try writer.print("{}\n", .{flag});
                    },

                    else => {
                        if (dwarf.AT.lo_user <= attr.value.name and attr.value.name <= dwarf.AT.hi_user) {
                            if (try attr.value.getConstant(self.ctx)) |value| {
                                try writer.print("({x})\n", .{value});
                            } else if (attr.value.getString(self.ctx, cuh)) |string| {
                                try writer.print("(\"{s}\")\n", .{string});
                            } else {
                                try writer.print("error: unhandled form 0x{x} for attribute\n", .{attr.value.form});
                            }
                        } else {
                            log.err("unexpected FORM value: {x}", .{attr.value.form});
                            return error.UnknownForm;
                        }
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

fn formatDIETag(tag: u64, buffer: *[256]u8) ![]const u8 {
    switch (tag) {
        dwarf.TAG.lo_user...dwarf.TAG.hi_user => {
            const string: []const u8 = switch (tag) {
                0x4109 => "DW_TAG_GNU_call_site",
                0x410a => "DW_TAG_GNU_call_site_parameter",
                else => return std.fmt.bufPrint(buffer, "DW_TAG_unknown_{x}", .{tag}),
            };
            return std.fmt.bufPrint(buffer, "{s}", .{string});
        },

        else => {
            const ti = @typeInfo(std.dwarf.TAG);
            inline for (ti.Struct.decls) |decl| {
                if (@field(std.dwarf.TAG, decl.name) == tag) {
                    return std.fmt.bufPrint(buffer, "DW_TAG_" ++ decl.name, .{});
                }
            }
            log.err("unexpected TAG value: {x}", .{tag});
            return error.UnexpectedTag;
        },
    }
}

fn formatATName(at: u64, buffer: *[256]u8) ![]const u8 {
    switch (at) {
        dwarf.AT.lo_user...dwarf.AT.hi_user => {
            const string: []const u8 = switch (at) {
                0x2111 => "DW_AT_GNU_call_site_value",
                0x2113 => "DW_AT_GNU_call_site_target",
                0x2115 => "DW_AT_GNU_tail_cail",
                0x2117 => "DW_AT_GNU_all_call_sites",
                0x3e02 => "DW_AT_LLVM_sysroot",
                0x3fef => "DW_AT_APPLE_sdk",
                else => return std.fmt.bufPrint(buffer, "DW_AT_unknown_{x}", .{at}),
            };
            return std.fmt.bufPrint(buffer, "{s}", .{string});
        },

        else => {
            const ti = @typeInfo(std.dwarf.AT);
            inline for (ti.Struct.decls) |decl| {
                if (@field(std.dwarf.AT, decl.name) == at) {
                    return std.fmt.bufPrint(buffer, "DW_AT_" ++ decl.name, .{});
                }
            }
            log.err("unexpected AT value: {x}", .{at});
            return error.UnexpectedAttribute;
        },
    }
}

fn Result(comptime T: type) type {
    return struct { off: usize, value: T };
}

fn result(off: usize, value: anytype) Result(@TypeOf(value)) {
    return .{ .off = off, .value = value };
}

fn getCompileUnitIterator(ctx: *const Context) CompileUnitIterator {
    return .{ .ctx = ctx };
}

const CompileUnitIterator = struct {
    ctx: *const Context,
    pos: usize = 0,

    fn next(self: *CompileUnitIterator) !?Result(CompileUnit) {
        const di = self.ctx.getDebugInfoData() orelse return null;
        if (self.pos >= di.len) return null;

        var stream = std.io.fixedBufferStream(di[self.pos..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const cuh = try CompileUnit.Header.read(reader);
        const total_length = cuh.header.length + @as(u64, if (cuh.header.is64Bit())
            @sizeOf(u64)
        else
            @sizeOf(u32));

        const cu = CompileUnit{
            .cuh = cuh,
            .debug_info_off = self.pos + creader.bytes_read,
        };
        const res = result(self.pos, cu);

        self.pos += total_length;

        return res;
    }
};

fn genAbbrevLookupByKind(ctx: *const Context, off: usize, lookup: *AbbrevLookupTable) !void {
    const da = ctx.getDebugAbbrevData().?;
    const data = da[off..];
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

    fn size(self: CompileUnit) usize {
        return if (self.cuh.header.is64Bit()) @as(usize, 8) else 4 + self.cuh.header.length;
    }

    fn getDebugInfo(self: CompileUnit, ctx: *const Context) []const u8 {
        const di = ctx.getDebugInfoData().?;
        return di[self.debug_info_off..][0..self.cuh.header.length];
    }

    fn getAbbrevEntryIterator(self: CompileUnit, ctx: *const Context) AbbrevEntryIterator {
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
    ctx: *const Context,
    cu: CompileUnit,
    pos: usize = 0,

    fn next(self: *AbbrevEntryIterator, lookup: AbbrevLookupTable) !?Result(AbbrevEntry) {
        const di = self.ctx.getDebugInfoData() orelse return null;
        if (self.pos + self.cu.debug_info_off >= di.len) return null;

        const data = di[self.pos + self.cu.debug_info_off ..];
        var stream = std.io.fixedBufferStream(data);
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

    fn getDebugInfo(self: AbbrevEntry, ctx: *const Context) []const u8 {
        const di = ctx.getDebugInfoData().?;
        return di[self.debug_info_off..][0..self.debug_info_len];
    }

    inline fn getDebugAbbrev(self: AbbrevEntry, ctx: *const Context) []const u8 {
        const da = ctx.getDebugAbbrevData().?;
        return da[self.debug_abbrev_off..][0..self.debug_abbrev_len];
    }

    fn getAttributeIterator(self: AbbrevEntry, ctx: *const Context, cuh: CompileUnit.Header) AttributeIterator {
        return .{ .entry = self, .ctx = ctx, .cuh = cuh };
    }
};

const Attribute = struct {
    name: u64,
    form: u64,
    debug_info_off: usize,
    debug_info_len: usize,

    inline fn getDebugInfo(self: Attribute, ctx: *const Context) []const u8 {
        const di = ctx.getDebugInfoData().?;
        return di[self.debug_info_off..][0..self.debug_info_len];
    }

    fn getFlag(self: Attribute, ctx: *const Context) ?bool {
        const debug_info = self.getDebugInfo(ctx);

        switch (self.form) {
            dwarf.FORM.flag => return debug_info[0] == 1,
            dwarf.FORM.flag_present => return true,
            else => return null,
        }
    }

    fn getString(self: Attribute, ctx: *const Context, cuh: CompileUnit.Header) ?[]const u8 {
        const debug_info = self.getDebugInfo(ctx);

        switch (self.form) {
            dwarf.FORM.string => {
                return mem.sliceTo(@as([*:0]const u8, @ptrCast(debug_info.ptr)), 0);
            },
            dwarf.FORM.strp => {
                const off = if (cuh.header.is64Bit())
                    mem.readIntLittle(u64, debug_info[0..8])
                else
                    mem.readIntLittle(u32, debug_info[0..4]);
                return getDwarfString(ctx, off);
            },
            else => return null,
        }
    }

    fn getSecOffset(self: Attribute, ctx: *const Context, cuh: CompileUnit.Header) ?u64 {
        if (self.form != dwarf.FORM.sec_offset) return null;
        const debug_info = self.getDebugInfo(ctx);
        const value = if (cuh.header.is64Bit())
            mem.readIntLittle(u64, debug_info[0..8])
        else
            mem.readIntLittle(u32, debug_info[0..4]);
        return value;
    }

    fn getConstant(self: Attribute, ctx: *const Context) !?i128 {
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

    fn getReference(self: Attribute, ctx: *const Context, cuh: CompileUnit.Header) !?u64 {
        const debug_info = self.getDebugInfo(ctx);
        var stream = std.io.fixedBufferStream(debug_info);
        const reader = stream.reader();

        return switch (self.form) {
            dwarf.FORM.ref1 => debug_info[0],
            dwarf.FORM.ref2 => mem.readIntLittle(u16, debug_info[0..2]),
            dwarf.FORM.ref4 => mem.readIntLittle(u32, debug_info[0..4]),
            dwarf.FORM.ref8 => mem.readIntLittle(u64, debug_info[0..8]),
            dwarf.FORM.ref_udata => try leb.readULEB128(u64, reader),
            dwarf.FORM.ref_addr => if (cuh.header.is64Bit())
                mem.readIntLittle(u64, debug_info[0..8])
            else
                mem.readIntLittle(u32, debug_info[0..4]),
            else => null,
        };
    }

    fn getAddr(self: Attribute, ctx: *const Context, cuh: CompileUnit.Header) ?u64 {
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

    fn getExprloc(self: Attribute, ctx: *const Context) !?[]const u8 {
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
    ctx: *const Context,
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

fn getAbbrevEntry(ctx: *const Context, da_off: usize, da_len: usize, di_off: usize, di_len: usize) !AbbrevEntry {
    const data = ctx.getDebugAbbrevData().?;
    const debug_abbrev = data[da_off..][0..da_len];
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

fn findFormSize(ctx: *const Context, form: u64, di_off: usize, cuh: CompileUnit.Header) !usize {
    const data = ctx.getDebugInfoData().?;
    const debug_info = data[di_off..];
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

fn findAbbrevEntrySize(ctx: *const Context, da_off: usize, da_len: usize, di_off: usize, cuh: CompileUnit.Header) !usize {
    const data = ctx.getDebugAbbrevData().?;
    const debug_abbrev = data[da_off..][0..da_len];
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

fn getDwarfString(ctx: *const Context, off: u64) []const u8 {
    const debug_str = ctx.getDebugStringData().?;
    assert(off < debug_str.len);
    return mem.sliceTo(@as([*:0]const u8, @ptrCast(debug_str.ptr + off)), 0);
}

const CieWithHeader = struct {
    cie: dwarf.CommonInformationEntry,
    header: dwarf.EntryHeader,

    vm: VirtualMachine = .{},

    // Instead of re-running the CIE instructions to print each FDE, the vm state
    // is restored to the post-CIE state instead.
    vm_snapshot_columns: usize = undefined,
    vm_snapshot_row: VirtualMachine.Row = undefined,

    pub fn deinit(self: *CieWithHeader, allocator: mem.Allocator) void {
        self.vm.deinit(allocator);
    }
};

const WriteOptions = struct {
    llvm_compatibility: bool,
    frame_type: dwarf.DwarfSection,
    reg_ctx: abi.RegisterContext,
    addr_size: u8,
    endian: std.builtin.Endian,
};

const Section = struct {
    data: []const u8,
    offset: u64,
    frame_type: dwarf.DwarfSection,
};

pub fn printEhFrames(self: DwarfDump, writer: anytype, llvm_compatibility: bool) !void {
    switch (self.ctx.tag) {
        .elf => {
            const elf = self.ctx.cast(Context.Elf).?;
            const sections = [_]struct {
                name: []const u8,
                section: ?std.elf.Elf64_Shdr,
                data: ?[]const u8,
                frame_type: dwarf.DwarfSection,
            }{
                .{
                    .name = ".debug_frame",
                    .section = elf.debug_frame,
                    .data = elf.getDebugFrameData(),
                    .frame_type = .debug_frame,
                },
                .{
                    .name = ".eh_frame",
                    .section = elf.eh_frame,
                    .data = elf.getEhFrameData(),
                    .frame_type = .eh_frame,
                },
            };

            for (sections, 0..) |section, i| {
                if (i > 0) try writer.writeByte('\n');
                try writer.print("{s} contents:\n\n", .{section.name});
                if (section.section) |s| {
                    if (s.sh_type != std.elf.SHT_NULL and s.sh_type != std.elf.SHT_NOBITS) {
                        try self.printEhFrame(
                            writer,
                            llvm_compatibility,
                            .{
                                .data = section.data.?,
                                .offset = s.sh_addr,
                                .frame_type = section.frame_type,
                            },
                            false,
                        );
                    }
                }
            }
        },
        .macho => {
            const macho = self.ctx.cast(Context.MachO).?;
            const sections = [_]struct {
                name: []const u8,
                frame_type: dwarf.DwarfSection,
            }{
                .{
                    .name = "__debug_frame",
                    .frame_type = .debug_frame,
                },
                .{
                    .name = "__eh_frame",
                    .frame_type = .eh_frame,
                },
            };

            for (sections) |section| {
                try writer.print("\n.{s} contents:\n\n", .{@tagName(section.frame_type)});
                if (macho.getSectionByName("__TEXT", section.name)) |s| {
                    try self.printEhFrame(
                        writer,
                        llvm_compatibility,
                        .{
                            .data = macho.getSectionData(s),
                            .offset = s.addr,
                            .frame_type = section.frame_type,
                        },
                        true,
                    );
                }
            }
        },
    }
}

pub fn printEhFrame(self: DwarfDump, writer: anytype, llvm_compatibility: bool, section: Section, is_macho: bool) !void {
    const write_options = WriteOptions{
        .llvm_compatibility = llvm_compatibility,
        .frame_type = section.frame_type,

        .reg_ctx = .{
            .eh_frame = section.frame_type == .eh_frame,
            .is_macho = is_macho,
        },

        // TODO: Use the addr size / endianness of the file, provide in section
        .addr_size = @sizeOf(usize),
        .endian = .Little,
    };

    var cies = std.AutoArrayHashMap(u64, CieWithHeader).init(self.gpa);
    defer {
        for (cies.keys()) |cie_offset| cies.getPtr(cie_offset).?.deinit(self.gpa);
        cies.deinit();
    }

    var stream = std.io.fixedBufferStream(section.data);
    while (stream.pos < stream.buffer.len) {
        const entry_header = try dwarf.EntryHeader.read(&stream, section.frame_type, write_options.endian);
        switch (entry_header.type) {
            .cie => {
                const cie = try dwarf.CommonInformationEntry.parse(
                    entry_header.entry_bytes,
                    @as(i64, @intCast(section.offset)) - @as(i64, @intCast(@intFromPtr(section.data.ptr))),
                    false,
                    entry_header.is_64,
                    section.frame_type,
                    entry_header.length_offset,
                    write_options.addr_size,
                    write_options.endian,
                );

                const entry = try cies.getOrPut(entry_header.length_offset);
                assert(!entry.found_existing);
                entry.value_ptr.* = .{ .cie = cie, .header = entry_header };

                try self.writeCie(writer, write_options, entry.value_ptr);
            },
            .fde => |cie_offset| {
                const cie_with_header = cies.getPtr(cie_offset) orelse return error.InvalidFDE;
                const fde = try dwarf.FrameDescriptionEntry.parse(
                    entry_header.entry_bytes,
                    @as(i64, @intCast(section.offset)) - @as(i64, @intCast(@intFromPtr(section.data.ptr))),
                    false,
                    cie_with_header.cie,
                    write_options.addr_size,
                    write_options.endian,
                );

                try self.writeFde(writer, write_options, cie_with_header, entry_header, fde);
            },
            .terminator => {
                try writer.print("{x:0>8} ZERO terminator\n", .{entry_header.length_offset});
                break;
            },
        }
    }
}

fn headerFormat(is_64: bool) []const u8 {
    return if (is_64) "{x:0>16}" else "{x:0>8}";
}

fn writeCie(
    self: DwarfDump,
    writer: anytype,
    options: WriteOptions,
    cie_with_header: *CieWithHeader,
) !void {
    const expression_context = dwarf.expressions.ExpressionContext{
        .is_64 = cie_with_header.header.is_64,
    };

    switch (cie_with_header.header.is_64) {
        inline else => |is_64| {
            const length_fmt = comptime headerFormat(is_64);
            try writer.print("{x:0>8} " ++ length_fmt ++ " " ++ length_fmt ++ " CIE\n", .{
                cie_with_header.cie.length_offset,
                cie_with_header.header.entryLength(),
                @as(u64, switch (options.frame_type) {
                    .eh_frame => dwarf.CommonInformationEntry.eh_id,
                    .debug_frame => if (is_64) dwarf.CommonInformationEntry.dwarf64_id else dwarf.CommonInformationEntry.dwarf32_id,
                    else => unreachable,
                }),
            });
        },
    }

    const cie = &cie_with_header.cie;
    try writeFormat(writer, cie_with_header.header.is_64, true);
    try writer.print("  {s: <23}{}\n", .{ "Version:", cie.version });
    try writer.print("  {s: <23}\"{s}\"\n", .{ "Augmentation:", cie.aug_str });
    if (cie_with_header.cie.version == 4) {
        try writer.print("  {s: <23}{}\n", .{ "Address size:", cie.address_size });
        try writer.print("  {s: <23}{}\n", .{ "Segment desc size:", cie.segment_selector_size.? });
    }
    try writer.print("  {s: <23}{}\n", .{ "Code alignment factor:", cie.code_alignment_factor });
    try writer.print("  {s: <23}{}\n", .{ "Data alignment factor:", cie.data_alignment_factor });
    try writer.print("  {s: <23}{}\n", .{ "Return address column:", cie.return_address_register });

    // Oddly llvm-dwarfdump does not align this field with the rest
    if (cie.personality_routine_pointer) |p| try writer.print("  {s: <21}{x:0>16}\n", .{ "Personality Address:", p });

    if (cie.aug_data.len > 0) {
        try writer.print("  {s: <22}", .{"Augmentation data:"});
        for (cie.aug_data) |byte| {
            try writer.print(" {X:0>2}", .{byte});
        }
        try writer.writeByte('\n');
    }

    if (!options.llvm_compatibility) {
        try writer.writeAll("\n");
        if (cie.personality_enc) |p| try writer.print("  {s: <23}{X}\n", .{ "Personality Pointer Encoding:", p });
        try writer.print("  {s: <23}{X}\n", .{ "LSDA Pointer Encoding:", cie.lsda_pointer_enc });
        try writer.print("  {s: <23}{X}\n", .{ "FDE Pointer Encoding:", cie.fde_pointer_enc });
    }

    try writer.writeAll("\n");

    {
        var instruction_stream = std.io.fixedBufferStream(cie.initial_instructions);
        while (instruction_stream.pos < instruction_stream.buffer.len) {
            const instruction = try dwarf.call_frame.Instruction.read(&instruction_stream, options.addr_size, options.endian);
            const opcode = std.meta.activeTag(instruction);
            try writer.print("  DW_CFA_{s}:", .{@tagName(opcode)});
            try writeOperands(
                instruction,
                writer,
                cie.*,
                self.ctx.getArch(),
                expression_context,
                options.reg_ctx,
                options.addr_size,
                options.endian,
            );
            _ = try cie_with_header.vm.step(self.gpa, cie.*, true, instruction);
            try writer.writeByte('\n');
        }
    }

    try writer.writeAll("\n");
    if (cie_with_header.vm.current_row.cfa.rule != .default) try writer.writeAll("  ");
    try self.writeRow(
        writer,
        cie_with_header.vm,
        cie_with_header.vm.current_row,
        expression_context,
        options.reg_ctx,
        options.addr_size,
        options.endian,
    );
    try writer.writeByte('\n');

    cie_with_header.vm_snapshot_columns = cie_with_header.vm.columns.items.len;
    cie_with_header.vm_snapshot_row = cie_with_header.vm.current_row;
}

fn writeFde(
    self: DwarfDump,
    writer: anytype,
    options: WriteOptions,
    cie_with_header: *CieWithHeader,
    header: dwarf.EntryHeader,
    fde: dwarf.FrameDescriptionEntry,
) !void {
    const cie = &cie_with_header.cie;
    const expression_context = dwarf.expressions.ExpressionContext{
        .is_64 = cie.is_64,
    };

    // TODO: Print <invalid offset> for cie if it didn't point to an actual CIE
    switch (cie_with_header.header.is_64) {
        inline else => |is_64| {
            const length_fmt = comptime headerFormat(is_64);
            try writer.print("{x:0>8} " ++ length_fmt ++ " " ++ length_fmt ++ " FDE cie={x:0>8} pc={x:0>8}...{x:0>8}\n", .{
                header.length_offset,
                header.entryLength(),
                switch (options.frame_type) {
                    .eh_frame => (header.length_offset + @as(u8, if (header.is_64) 12 else 4)) - fde.cie_length_offset,
                    .debug_frame => fde.cie_length_offset,
                    else => unreachable,
                },
                fde.cie_length_offset,
                fde.pc_begin,
                fde.pc_begin + fde.pc_range,
            });
        },
    }

    try writeFormat(writer, cie_with_header.header.is_64, false);
    if (fde.lsda_pointer) |p| try writer.print("  LSDA Address: {x:0>16}\n", .{p});

    if (!options.llvm_compatibility) {
        if (fde.aug_data.len > 0) try writer.print("  {s: <23}{}\n", .{ "Augmentation data:", std.fmt.fmtSliceHexUpper(cie.aug_data) });
    }

    var instruction_stream = std.io.fixedBufferStream(fde.instructions);

    // First pass to print instructions and their operands
    while (instruction_stream.pos < instruction_stream.buffer.len) {
        const instruction = try dwarf.call_frame.Instruction.read(&instruction_stream, options.addr_size, options.endian);
        const opcode = std.meta.activeTag(instruction);
        try writer.print("  DW_CFA_{s}:", .{@tagName(opcode)});
        try writeOperands(
            instruction,
            writer,
            cie.*,
            self.ctx.getArch(),
            expression_context,
            options.reg_ctx,
            options.addr_size,
            options.endian,
        );
        try writer.writeByte('\n');
    }

    try writer.writeByte('\n');

    // Second pass to run them and print the generated table
    instruction_stream.pos = 0;
    while (instruction_stream.pos < instruction_stream.buffer.len) {
        const instruction = try dwarf.call_frame.Instruction.read(&instruction_stream, options.addr_size, options.endian);
        var prev_row = try cie_with_header.vm.step(self.gpa, cie.*, false, instruction);
        if (cie_with_header.vm.current_row.offset != prev_row.offset) {
            try writer.print("  0x{x}: ", .{fde.pc_begin + prev_row.offset});
            try self.writeRow(
                writer,
                cie_with_header.vm,
                prev_row,
                expression_context,
                options.reg_ctx,
                options.addr_size,
                options.endian,
            );
        }
    }

    try writer.print("  0x{x}: ", .{fde.pc_begin + cie_with_header.vm.current_row.offset});
    try self.writeRow(
        writer,
        cie_with_header.vm,
        cie_with_header.vm.current_row,
        expression_context,
        options.reg_ctx,
        options.addr_size,
        options.endian,
    );

    // Restore the VM state to the result of the initial CIE instructions
    cie_with_header.vm.columns.items.len = cie_with_header.vm_snapshot_columns;
    cie_with_header.vm.current_row = cie_with_header.vm_snapshot_row;
    cie_with_header.vm.cie_row = null;

    try writer.writeByte('\n');
}

fn writeRow(
    self: DwarfDump,
    writer: anytype,
    vm: VirtualMachine,
    row: VirtualMachine.Row,
    expression_context: dwarf.expressions.ExpressionContext,
    reg_ctx: abi.RegisterContext,
    addr_size: u8,
    endian: std.builtin.Endian,
) !void {
    const columns = vm.rowColumns(row);

    var wrote_anything = false;
    var wrote_separator = false;
    if (try writeColumnRule(
        row.cfa,
        writer,
        true,
        self.ctx.getArch(),
        expression_context,
        reg_ctx,
        addr_size,
        endian,
    )) {
        wrote_anything = true;
    }

    // llvm-dwarfdump prints columns sorted by register number
    var num_printed: usize = 0;
    for (0..256) |register| {
        for (columns) |column| {
            if (column.register == @as(u8, @intCast(register))) {
                if (column.rule != .default and !wrote_separator) {
                    try writer.writeAll(": ");
                    wrote_separator = true;
                }

                if (try writeColumnRule(
                    column,
                    writer,
                    false,
                    self.ctx.getArch(),
                    expression_context,
                    reg_ctx,
                    addr_size,
                    endian,
                )) {
                    if (num_printed != columns.len - 1) {
                        try writer.writeAll(", ");
                    }
                    wrote_anything = true;
                }

                num_printed += 1;
            }
        }

        if (num_printed == columns.len) break;
    }

    if (wrote_anything) try writer.writeByte('\n');
}

pub fn writeColumnRule(
    column: VirtualMachine.Column,
    writer: anytype,
    is_cfa: bool,
    arch: ?std.Target.Cpu.Arch,
    expression_context: dwarf.expressions.ExpressionContext,
    reg_ctx: abi.RegisterContext,
    addr_size_bytes: u8,
    endian: std.builtin.Endian,
) !bool {
    if (column.rule == .default) return false;

    if (is_cfa) {
        try writer.writeAll("CFA");
    } else {
        try writeRegisterName(writer, arch, column.register.?, reg_ctx);
    }

    try writer.writeByte('=');
    switch (column.rule) {
        .default => {},
        .undefined => try writer.writeAll("undefined"),
        .same_value => try writer.writeAll("S"),
        .offset, .val_offset => |offset| {
            if (offset == 0) {
                if (is_cfa) {
                    if (column.register) |cfa_register| {
                        try writer.print("{}", .{fmtRegister(cfa_register, reg_ctx, arch)});
                    } else {
                        try writer.writeAll("undefined");
                    }
                } else {
                    try writer.writeAll("[CFA]");
                }
            } else {
                if (is_cfa) {
                    if (column.register) |cfa_register| {
                        try writer.print("{}{d:<1}", .{ fmtRegister(cfa_register, reg_ctx, arch), offset });
                    } else {
                        try writer.print("undefined{d:<1}", .{offset});
                    }
                } else {
                    try writer.print("[CFA{d:<1}]", .{offset});
                }
            }
        },
        .register => |register| try writeRegisterName(writer, arch, register, reg_ctx),
        .expression => |expression| {
            if (!is_cfa) try writer.writeByte('[');
            try writeExpression(writer, expression, arch, expression_context, reg_ctx, addr_size_bytes, endian);
            if (!is_cfa) try writer.writeByte(']');
        },
        .val_expression => try writer.writeAll("TODO(val_expression)"),
        .architectural => try writer.writeAll("TODO(architectural)"),
    }

    return true;
}

fn writeExpression(
    writer: anytype,
    block: []const u8,
    arch: ?std.Target.Cpu.Arch,
    expression_context: dwarf.expressions.ExpressionContext,
    reg_ctx: abi.RegisterContext,
    addr_size_bytes: u8,
    endian: std.builtin.Endian,
) !void {
    var stream = std.io.fixedBufferStream(block);

    // Generate a lookup table from opcode value to name
    const opcode_lut_len = 256;
    const opcode_lut: [opcode_lut_len]?[]const u8 = comptime blk: {
        var lut: [opcode_lut_len]?[]const u8 = [_]?[]const u8{null} ** opcode_lut_len;
        for (@typeInfo(dwarf.OP).Struct.decls) |decl| {
            lut[@as(u8, @field(dwarf.OP, decl.name))] = decl.name;
        }

        break :blk lut;
    };

    switch (endian) {
        inline .Little, .Big => |e| {
            switch (addr_size_bytes) {
                inline 2, 4, 8 => |size| {
                    const StackMachine = dwarf.expressions.StackMachine(.{
                        .addr_size = size,
                        .endian = e,
                        .call_frame_context = true,
                    });

                    const reader = stream.reader();
                    while (stream.pos < stream.buffer.len) {
                        if (stream.pos > 0) try writer.writeAll(", ");

                        const opcode = try reader.readByte();
                        if (opcode_lut[opcode]) |opcode_name| {
                            try writer.print("DW_OP_{s}", .{opcode_name});
                        } else {
                            // TODO: See how llvm-dwarfdump prints these?
                            if (opcode >= dwarf.OP.lo_user and opcode <= dwarf.OP.hi_user) {
                                try writer.print("<unknown vendor opcode: 0x{x}>", .{opcode});
                            } else {
                                try writer.print("<invalid opcode: 0x{x}>", .{opcode});
                            }
                        }

                        if (try StackMachine.readOperand(&stream, opcode, expression_context)) |value| {
                            switch (value) {
                                .generic => {}, // Constant values are implied by the opcode name
                                .register => |v| try writer.print(" {}", .{fmtRegister(v, reg_ctx, arch)}),
                                .base_register => |v| try writer.print(" {}{d:<1}", .{ fmtRegister(v.base_register, reg_ctx, arch), v.offset }),
                                else => try writer.print(" TODO({s})", .{@tagName(value)}),
                            }
                        }
                    }
                },
                else => return error.InvalidAddrSize,
            }
        },
    }
}

fn writeOperands(
    instruction: dwarf.call_frame.Instruction,
    writer: anytype,
    cie: dwarf.CommonInformationEntry,
    arch: ?std.Target.Cpu.Arch,
    expression_context: dwarf.expressions.ExpressionContext,
    reg_ctx: abi.RegisterContext,
    addr_size_bytes: u8,
    endian: std.builtin.Endian,
) !void {
    switch (instruction) {
        .set_loc => |i| try writer.print(" 0x{x}", .{i.address}),
        inline .advance_loc,
        .advance_loc1,
        .advance_loc2,
        .advance_loc4,
        => |i| try writer.print(" {}", .{i.delta * cie.code_alignment_factor}),
        inline .offset,
        .offset_extended,
        .offset_extended_sf,
        => |i| try writer.print(" {} {d}", .{
            fmtRegister(i.register, reg_ctx, arch),
            @as(i64, @intCast(i.offset)) * cie.data_alignment_factor,
        }),
        inline .restore,
        .restore_extended,
        .undefined,
        .same_value,
        => |i| try writer.print(" {}", .{fmtRegister(i.register, reg_ctx, arch)}),
        .nop => {},
        .register => |i| try writer.print(" {} {}", .{ fmtRegister(i.register, reg_ctx, arch), fmtRegister(i.target_register, reg_ctx, arch) }),
        .remember_state => {},
        .restore_state => {},
        .def_cfa => |i| try writer.print(" {} {d:<1}", .{ fmtRegister(i.register, reg_ctx, arch), @as(i64, @intCast(i.offset)) }),
        .def_cfa_sf => |i| try writer.print(" {} {d:<1}", .{ fmtRegister(i.register, reg_ctx, arch), i.offset * cie.data_alignment_factor }),
        .def_cfa_register => |i| try writer.print(" {}", .{fmtRegister(i.register, reg_ctx, arch)}),
        .def_cfa_offset => |i| try writer.print(" {d:<1}", .{@as(i64, @intCast(i.offset))}),
        .def_cfa_offset_sf => |i| try writer.print(" {d:<1}", .{i.offset * cie.data_alignment_factor}),
        .def_cfa_expression => |i| {
            try writer.writeByte(' ');
            try writeExpression(writer, i.block, arch, expression_context, reg_ctx, addr_size_bytes, endian);
        },
        .expression => |i| {
            try writer.print(" {} ", .{fmtRegister(i.register, reg_ctx, arch)});
            try writeExpression(writer, i.block, arch, expression_context, reg_ctx, addr_size_bytes, endian);
        },
        .val_offset => {},
        .val_offset_sf => {},
        .val_expression => {},
    }
}

fn writeFormat(writer: anytype, is_64: bool, comptime is_cie: bool) !void {
    try writer.print("  {s: <" ++ (if (is_cie) "23" else "14") ++ "}{s}\n", .{ "Format:", if (is_64) "DWARF64" else "DWARF32" });
}

fn writeUnknownReg(writer: anytype, reg_number: u8) !void {
    try writer.print("reg{}", .{reg_number});
}

pub fn writeRegisterName(
    writer: anytype,
    arch: ?std.Target.Cpu.Arch,
    reg_number: u8,
    reg_ctx: abi.RegisterContext,
) !void {
    if (arch) |a| {
        switch (a) {
            .x86 => {
                switch (reg_number) {
                    0 => try writer.writeAll("EAX"),
                    1 => try writer.writeAll("EDX"),
                    2 => try writer.writeAll("ECX"),
                    3 => try writer.writeAll("EBX"),
                    4 => if (reg_ctx.eh_frame and reg_ctx.is_macho) try writer.writeAll("EBP") else try writer.writeAll("ESP"),
                    5 => if (reg_ctx.eh_frame and reg_ctx.is_macho) try writer.writeAll("ESP") else try writer.writeAll("EBP"),
                    6 => try writer.writeAll("ESI"),
                    7 => try writer.writeAll("EDI"),
                    8 => try writer.writeAll("EIP"),
                    9 => try writer.writeAll("EFL"),
                    10 => try writer.writeAll("CS"),
                    11 => try writer.writeAll("SS"),
                    12 => try writer.writeAll("DS"),
                    13 => try writer.writeAll("ES"),
                    14 => try writer.writeAll("FS"),
                    15 => try writer.writeAll("GS"),
                    16...23 => try writer.print("ST{}", .{reg_number - 16}),
                    32...39 => try writer.print("XMM{}", .{reg_number - 32}),
                    else => try writeUnknownReg(writer, reg_number),
                }
            },
            .x86_64 => {
                switch (reg_number) {
                    0 => try writer.writeAll("RAX"),
                    1 => try writer.writeAll("RDX"),
                    2 => try writer.writeAll("RCX"),
                    3 => try writer.writeAll("RBX"),
                    4 => try writer.writeAll("RSI"),
                    5 => try writer.writeAll("RDI"),
                    6 => try writer.writeAll("RBP"),
                    7 => try writer.writeAll("RSP"),
                    8...15 => try writer.print("R{}", .{reg_number}),
                    16 => try writer.writeAll("RIP"),
                    17...32 => try writer.print("XMM{}", .{reg_number - 17}),
                    33...40 => try writer.print("ST{}", .{reg_number - 33}),
                    41...48 => try writer.print("MM{}", .{reg_number - 41}),
                    49 => try writer.writeAll("RFLAGS"),
                    50 => try writer.writeAll("ES"),
                    51 => try writer.writeAll("CS"),
                    52 => try writer.writeAll("SS"),
                    53 => try writer.writeAll("DS"),
                    54 => try writer.writeAll("FS"),
                    55 => try writer.writeAll("GS"),
                    // 56-57 Reserved
                    58 => try writer.writeAll("FS.BASE"),
                    59 => try writer.writeAll("GS.BASE"),
                    // 60-61 Reserved
                    62 => try writer.writeAll("TR"),
                    63 => try writer.writeAll("LDTR"),
                    64 => try writer.writeAll("MXCSR"),
                    65 => try writer.writeAll("FCW"),
                    66 => try writer.writeAll("FSW"),
                    67...82 => try writer.print("XMM{}", .{reg_number - 51}),
                    // 83-117 Reserved
                    118...125 => try writer.print("K{}", .{reg_number - 118}),
                    // 126-129 Reserved
                    else => try writeUnknownReg(writer, reg_number),
                }
            },
            .arm => {
                switch (reg_number) {
                    0...15 => try writer.print("R{}", .{reg_number}),
                    // 16-63 None
                    64...95 => try writer.print("S{}", .{reg_number - 64}),
                    96...103 => try writer.print("F{}", .{reg_number - 96}),

                    // Could also be ACC0-ACC7
                    104...111 => try writer.print("wCGR0{}", .{reg_number - 104}),
                    112...127 => try writer.print("wR0{}", .{reg_number - 112}),
                    128 => try writer.writeAll("SPSR"),
                    129 => try writer.writeAll("SPSR_FIQ"),
                    130 => try writer.writeAll("SPSR_IRQ"),
                    131 => try writer.writeAll("SPSR_ABT"),
                    132 => try writer.writeAll("SPSR_UND"),
                    133 => try writer.writeAll("SPSR_SVC"),
                    // 134-142 None
                    else => try writeUnknownReg(writer, reg_number),
                }
            },
            .aarch64 => {
                switch (reg_number) {
                    0...30 => try writer.print("W{}", .{reg_number}),
                    31 => try writer.writeAll("WSP"),
                    32 => try writer.writeAll("PC"),
                    33 => try writer.writeAll("ELR_mode"),
                    34 => try writer.writeAll("RA_SIGN_STATE"),
                    35 => try writer.writeAll("TPIDRRO_ELO"),
                    36 => try writer.writeAll("TPIDR_ELO"),
                    37 => try writer.writeAll("TPIDR_EL1"),
                    38 => try writer.writeAll("TPIDR_EL2"),
                    39 => try writer.writeAll("TPIDR_EL3"),
                    // 40-45 Reserved
                    46 => try writer.writeAll("VG"),
                    47 => try writer.writeAll("FFR"),
                    48...63 => try writer.print("P{}", .{reg_number - 48}),
                    64...95 => try writer.print("B{}", .{reg_number - 64}),
                    96...127 => try writer.print("Z{}", .{reg_number - 96}),
                    else => try writeUnknownReg(writer, reg_number),
                }
            },
            else => try writeUnknownReg(writer, reg_number),
        }
    } else try writeUnknownReg(writer, reg_number);
}

const FormatRegisterData = struct {
    reg_number: u8,
    reg_ctx: abi.RegisterContext,
    arch: ?std.Target.Cpu.Arch,
};

pub fn formatRegister(
    data: FormatRegisterData,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = fmt;
    _ = options;
    try writeRegisterName(writer, data.arch, data.reg_number, data.reg_ctx);
}

pub fn fmtRegister(
    reg_number: u8,
    reg_ctx: abi.RegisterContext,
    arch: ?std.Target.Cpu.Arch,
) std.fmt.Formatter(formatRegister) {
    return .{
        .data = .{
            .reg_number = reg_number,
            .reg_ctx = reg_ctx,
            .arch = arch,
        },
    };
}
