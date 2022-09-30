const DwarfDump = @This();

const std = @import("std");
const assert = std.debug.assert;
const dwarf = std.dwarf;
const leb = std.leb;
const fs = std.fs;
const mem = std.mem;

const Allocator = mem.Allocator;
const AbbrevLookupTable = std.AutoHashMap(u64, struct { pos: usize, len: usize });
const Context = @import("Context.zig");

gpa: Allocator,
ctx: Context,
data: []const u8,

pub fn deinit(self: *DwarfDump) void {
    self.gpa.free(self.data);
}

pub fn parse(gpa: Allocator, file: fs.File) !DwarfDump {
    const file_size = try file.getEndPos();
    const data = try file.readToEndAlloc(gpa, file_size);
    errdefer gpa.free(data);

    var self = DwarfDump{
        .gpa = gpa,
        .ctx = undefined,
        .data = data,
    };

    self.ctx = try Context.parse(self.data);

    return self;
}

pub fn printCompileUnits(self: DwarfDump, writer: anytype) !void {
    var cu_it = CompileUnitIterator{};
    while (try cu_it.next(self.ctx)) |cu| {
        const cuh = cu.value.cuh;

        var lookup = AbbrevLookupTable.init(self.gpa);
        defer lookup.deinit();
        try lookup.ensureUnusedCapacity(std.math.maxInt(u8));
        try genAbbrevLookupByKind(self.ctx, cuh.debug_abbrev_offset, &lookup);

        const next_unit_offset = cuh.length + @as(u64, if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32));
        try writer.writeAll("__debug_info contents:\n");
        try writer.print("0x{x:0>16}: Compile Unit: length = 0x{x:0>16}, format = {s}, version = 0x{x:0>4}, abbr_offset = 0x{x:0>16}, addr_size = 0x{x:0>2} (next unit at 0x{x:0>16})\n", .{
            cu.off,
            cuh.length,
            if (cuh.is_64bit) "DWARF64" else "DWARF32",
            cuh.version,
            cuh.debug_abbrev_offset,
            cuh.address_size,
            next_unit_offset,
        });
        try writer.writeByte('\n');

        var children: usize = 0;
        const indent: usize = 10;

        var abbrev_it = AbbrevEntryIterator{};
        while (try abbrev_it.next(self.ctx, cu.value, lookup)) |entry| {
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
            var attr_it = AttributeIterator{};
            while (try attr_it.next(self.ctx, entry.value, cuh)) |attr| {
                try formatIndent(children * 2, writer);
                try writer.print("{s: <22}{s: <30}", .{ "", formatATName(attr.value.name) });
                try formatIndent(indent - children * 2, writer);

                switch (attr.value.name) {
                    dwarf.AT.high_pc => {
                        const value = (try attr.value.getConstant(self.ctx)) orelse return error.MalformedDwarf;
                        if (low_pc) |base| {
                            try writer.print("({x:0>16})\n", .{value + base});
                        }
                    },
                    dwarf.AT.@"type" => {
                        const off = (try attr.value.getReference(self.ctx)) orelse return error.MalformedDwarf;
                        try writer.print("({x})\n", .{off});
                    },
                    else => {
                        if (try attr.value.getConstant(self.ctx)) |constant| {
                            try writer.print("({x})\n", .{constant});
                            continue;
                        }
                        if (try attr.value.getReference(self.ctx)) |off| {
                            try writer.print("({x})\n", .{off});
                            continue;
                        }
                        switch (attr.value.form) {
                            dwarf.FORM.strp => {
                                const str = attr.value.getString(self.ctx, cuh) orelse return error.MalformedDwarf;
                                try writer.print("({s})\n", .{str});
                            },
                            dwarf.FORM.sec_offset => {
                                const value = if (cuh.is_64bit)
                                    mem.readIntLittle(u64, attr.value.getDebugInfo(self.ctx)[0..8])
                                else
                                    mem.readIntLittle(u32, attr.value.getDebugInfo(self.ctx)[0..4]);
                                try writer.print("({x:0>16})\n", .{value});
                            },
                            dwarf.FORM.addr => {
                                const value = attr.value.getAddr(self.ctx, cuh) orelse return error.MalformedDwarf;
                                try writer.print("({x:0>16})\n", .{value});

                                if (attr.value.name == dwarf.AT.low_pc) {
                                    low_pc = value;
                                }
                            },
                            dwarf.FORM.exprloc => {
                                var stream = std.io.fixedBufferStream(attr.value.getDebugInfo(self.ctx));
                                const reader = stream.reader();
                                const expr_len = try leb.readULEB128(u64, reader);
                                var i: u64 = 0;
                                try writer.writeAll("( ");
                                while (i < expr_len) : (i += 1) {
                                    const byte = try reader.readByte();
                                    try writer.print("{x} ", .{byte});
                                }
                                try writer.writeAll(")\n");
                            },
                            dwarf.FORM.flag_present => {
                                try writer.writeAll("(true)\n");
                            },

                            dwarf.FORM.data1,
                            dwarf.FORM.data2,
                            dwarf.FORM.data4,
                            dwarf.FORM.data8,
                            dwarf.FORM.udata,
                            dwarf.FORM.sdata,
                            => unreachable,

                            dwarf.FORM.ref1,
                            dwarf.FORM.ref2,
                            dwarf.FORM.ref4,
                            dwarf.FORM.ref8,
                            dwarf.FORM.ref_udata,
                            => unreachable,

                            else => {},
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

fn formatDIETag(tag: u64) []const u8 {
    return switch (tag) {
        std.dwarf.TAG.compile_unit => "DW_TAG_compile_unit",
        std.dwarf.TAG.variable => "DW_TAG_variable",
        std.dwarf.TAG.array_type => "DW_TAG_array_type",
        std.dwarf.TAG.subrange_type => "DW_TAG_subrange_type",
        std.dwarf.TAG.formal_parameter => "DW_TAG_formal_parameter",
        std.dwarf.TAG.subprogram => "DW_TAG_subprogram",
        std.dwarf.TAG.base_type => "DW_TAG_base_type",
        std.dwarf.TAG.pointer_type => "DW_TAG_pointer_type",
        else => "DW_TAG_unknown", // TODO
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
        std.dwarf.AT.@"type" => "DW_AT_type",
        std.dwarf.AT.decl_file => "DW_AT_decl_file",
        std.dwarf.AT.decl_line => "DW_AT_decl_line",
        std.dwarf.AT.location => "DW_AT_location",
        std.dwarf.AT.count => "DW_AT_count",
        std.dwarf.AT.encoding => "DW_AT_encoding",
        std.dwarf.AT.byte_size => "DW_AT_byte_size",
        std.dwarf.AT.prototyped => "DW_AT_prototyped",
        std.dwarf.AT.frame_base => "DW_AT_framebase",
        std.dwarf.AT.external => "DW_AT_external",

        0x3e02 => "DW_AT_LLVM_sysroot",
        0x3fef => "DW_AT_APPLE_sdk",

        else => "DW_AT_unknown", // TODO
    };
}

fn Result(comptime T: type) type {
    return struct { off: usize, value: T };
}

fn result(off: usize, value: anytype) Result(@TypeOf(value)) {
    return .{ .off = off, .value = value };
}

const CompileUnitIterator = struct {
    pos: usize = 0,

    fn next(self: *CompileUnitIterator, ctx: Context) !?Result(CompileUnit) {
        if (self.pos >= ctx.debug_info.len) return null;

        var stream = std.io.fixedBufferStream(ctx.debug_info);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const cuh = try CompileUnit.Header.read(reader);
        const total_length = cuh.length + @as(u64, if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32));

        const cu = CompileUnit{
            .cuh = cuh,
            .debug_info_off = creader.bytes_read,
        };
        const res = result(self.pos, cu);

        self.pos += total_length;

        return res;
    }
};

fn findCompileUnit(ctx: Context, address: u64) !?CompileUnit {
    var cu_it = CompileUnitIterator{};

    while (try cu_it.next(ctx)) |cu| {
        const maybe_cu_entry: ?AbbrevEntry = while (try cu.nextAbbrevEntry()) |entry| switch (entry.tag) {
            dwarf.TAG.compile_unit => break entry,
            else => continue,
        } else null;

        var cu_entry = maybe_cu_entry orelse continue;

        var maybe_low_pc: ?u64 = null;
        var maybe_high_pc: ?u64 = null;
        while (try cu_entry.nextAttribute()) |attr| switch (attr.name) {
            dwarf.AT.low_pc => {
                if (attr.getAddr(cu.cuh)) |addr| {
                    maybe_low_pc = addr;
                    continue;
                }
                if (try attr.getConstant()) |constant| {
                    maybe_low_pc = @intCast(u64, constant);
                    continue;
                }
                unreachable;
            },
            dwarf.AT.high_pc => {
                if (attr.getAddr(cu.cuh)) |addr| {
                    maybe_high_pc = addr;
                    continue;
                }
                if (try attr.getConstant()) |constant| {
                    const casted = @intCast(u64, constant);
                    maybe_high_pc = if (maybe_low_pc) |lc| lc + casted else casted;
                    continue;
                }
            },
            else => {},
        };

        const low_pc = maybe_low_pc orelse continue;
        const high_pc = maybe_high_pc orelse continue;

        if (low_pc <= address and address < high_pc) return cu;
    }

    return null;
}

fn genAbbrevLookupByKind(ctx: Context, off: usize, lookup: *AbbrevLookupTable) !void {
    const data = ctx.debug_abbrev[off..];
    var stream = std.io.fixedBufferStream(data);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    var open_scope = false;
    while (true) {
        const kind = try leb.readULEB128(u64, reader);
        if (kind == 0) {
            if (open_scope) return error.MalformedDwarf;
            break;
        }
        open_scope = true;

        const pos = creader.bytes_read;

        while (true) {
            const byte = try reader.readByte();
            if (byte == 0) {
                if ((try reader.readByte()) == 0x0) {
                    open_scope = false;
                    break;
                }
            }
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
        is_64bit: bool,
        length: u64,
        version: u16,
        debug_abbrev_offset: u64,
        address_size: u8,

        fn read(reader: anytype) !Header {
            var length: u64 = try reader.readIntLittle(u32);

            const is_64bit = length == 0xffffffff;
            if (is_64bit) {
                length = try reader.readIntLittle(u64);
            }

            const version = try reader.readIntLittle(u16);
            const debug_abbrev_offset = if (is_64bit)
                try reader.readIntLittle(u64)
            else
                try reader.readIntLittle(u32);
            const address_size = try reader.readIntLittle(u8);

            return Header{
                .is_64bit = is_64bit,
                .length = length,
                .version = version,
                .debug_abbrev_offset = debug_abbrev_offset,
                .address_size = address_size,
            };
        }
    };

    inline fn getDebugInfo(self: CompileUnit, ctx: Context) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.cuh.length];
    }
};

const AbbrevEntryIterator = struct {
    pos: usize = 0,

    fn next(self: *AbbrevEntryIterator, ctx: Context, cu: CompileUnit, lookup: AbbrevLookupTable) !?Result(AbbrevEntry) {
        if (self.pos + cu.debug_info_off >= ctx.debug_info.len) return null;

        const kind = ctx.debug_info[self.pos + cu.debug_info_off];
        self.pos += 1;

        if (kind == 0) {
            return result(self.pos + cu.debug_info_off - 1, AbbrevEntry.@"null"());
        }

        const abbrev_pos = lookup.get(kind) orelse return error.MalformedDwarf;
        const len = try findAbbrevEntrySize(ctx, abbrev_pos.pos, abbrev_pos.len, self.pos + cu.debug_info_off, cu.cuh);
        const entry = try getAbbrevEntry(ctx, abbrev_pos.pos, abbrev_pos.len, self.pos + cu.debug_info_off, len);

        self.pos += len;

        return result(self.pos + cu.debug_info_off - len - 1, entry);
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

    inline fn getDebugInfo(self: AbbrevEntry, ctx: Context) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.debug_info_len];
    }

    inline fn getDebugAbbrev(self: AbbrevEntry, ctx: Context) []const u8 {
        return ctx.debug_abbrev[self.debug_abbrev_off..][0..self.debug_abbrev_len];
    }
};

const Attribute = struct {
    name: u64,
    form: u64,
    debug_info_off: usize,
    debug_info_len: usize,

    inline fn getDebugInfo(self: Attribute, ctx: Context) []const u8 {
        return ctx.debug_info[self.debug_info_off..][0..self.debug_info_len];
    }

    fn getString(self: Attribute, ctx: Context, cuh: CompileUnit.Header) ?[]const u8 {
        if (self.form != dwarf.FORM.strp) return null;
        const debug_info = self.getDebugInfo(ctx);
        const off = if (cuh.is_64bit)
            mem.readIntLittle(u64, debug_info[0..8])
        else
            mem.readIntLittle(u32, debug_info[0..4]);
        return getDwarfString(ctx.debug_str, off);
    }

    fn getConstant(self: Attribute, ctx: Context) !?i128 {
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

    fn getReference(self: Attribute, ctx: Context) !?u64 {
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

    fn getAddr(self: Attribute, ctx: Context, cuh: CompileUnit.Header) ?u64 {
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
};

const AttributeIterator = struct {
    debug_abbrev_pos: usize = 0,
    debug_info_pos: usize = 0,

    fn next(self: *AttributeIterator, ctx: Context, entry: AbbrevEntry, cuh: CompileUnit.Header) !?Result(Attribute) {
        const debug_abbrev = entry.getDebugAbbrev(ctx);
        if (self.debug_abbrev_pos >= debug_abbrev.len) return null;

        var stream = std.io.fixedBufferStream(debug_abbrev[self.debug_abbrev_pos..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        const name = try leb.readULEB128(u64, reader);
        const form = try leb.readULEB128(u64, reader);

        self.debug_abbrev_pos += creader.bytes_read;

        const len = try findFormSize(
            ctx,
            form,
            self.debug_info_pos + entry.debug_info_off,
            entry.debug_info_len - self.debug_info_pos,
            cuh,
        );
        const attr = Attribute{
            .name = name,
            .form = form,
            .debug_info_off = self.debug_info_pos + entry.debug_info_off,
            .debug_info_len = entry.debug_info_len - self.debug_info_pos,
        };

        self.debug_info_pos += len;

        return result(attr.debug_info_off, attr);
    }
};

fn getAbbrevEntry(ctx: Context, da_off: usize, da_len: usize, di_off: usize, di_len: usize) !AbbrevEntry {
    const debug_abbrev = ctx.debug_abbrev[da_off..][0..da_len];
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    const tag = try leb.readULEB128(u64, reader);
    const children = try reader.readByte();

    return AbbrevEntry{
        .tag = tag,
        .children = children,
        .debug_abbrev_off = creader.bytes_read + da_off,
        .debug_abbrev_len = da_len - creader.bytes_read,
        .debug_info_off = di_off,
        .debug_info_len = di_len,
    };
}

fn findFormSize(ctx: Context, form: u64, di_off: usize, di_len: ?usize, cuh: CompileUnit.Header) !usize {
    const debug_info = if (di_len) |len|
        ctx.debug_info[di_off..][0..len]
    else
        ctx.debug_info[di_off..];
    var stream = std.io.fixedBufferStream(debug_info);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    return switch (form) {
        dwarf.FORM.strp => if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32),
        dwarf.FORM.sec_offset => if (cuh.is_64bit) @sizeOf(u64) else @sizeOf(u32),
        dwarf.FORM.addr => cuh.address_size,
        dwarf.FORM.exprloc => blk: {
            const expr_len = try leb.readULEB128(u64, reader);
            var i: u64 = 0;
            while (i < expr_len) : (i += 1) {
                _ = try reader.readByte();
            }
            break :blk creader.bytes_read;
        },
        dwarf.FORM.flag_present => 0,

        dwarf.FORM.data1 => @sizeOf(u8),
        dwarf.FORM.data2 => @sizeOf(u16),
        dwarf.FORM.data4 => @sizeOf(u32),
        dwarf.FORM.data8 => @sizeOf(u64),
        dwarf.FORM.udata => blk: {
            _ = try leb.readULEB128(u64, reader);
            break :blk creader.bytes_read;
        },
        dwarf.FORM.sdata => blk: {
            _ = try leb.readILEB128(i64, reader);
            break :blk creader.bytes_read;
        },

        dwarf.FORM.ref1 => @sizeOf(u8),
        dwarf.FORM.ref2 => @sizeOf(u16),
        dwarf.FORM.ref4 => @sizeOf(u32),
        dwarf.FORM.ref8 => @sizeOf(u64),
        dwarf.FORM.ref_udata => blk: {
            _ = try leb.readULEB128(u64, reader);
            break :blk creader.bytes_read;
        },

        else => return error.ToDo,
    };
}

fn findAbbrevEntrySize(ctx: Context, da_off: usize, da_len: usize, di_off: usize, cuh: CompileUnit.Header) !usize {
    const debug_abbrev = ctx.debug_abbrev[da_off..][0..da_len];
    var stream = std.io.fixedBufferStream(debug_abbrev);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();

    _ = try leb.readULEB128(u64, reader);
    _ = try reader.readByte();

    var len: usize = 0;
    while (creader.bytes_read < debug_abbrev.len) {
        _ = try leb.readULEB128(u64, reader);
        const form = try leb.readULEB128(u64, reader);
        const form_len = try findFormSize(ctx, form, di_off + len, null, cuh);
        len += form_len;
    }

    return len;
}

fn getDwarfString(debug_str: []const u8, off: u64) []const u8 {
    assert(off < debug_str.len);
    return mem.sliceTo(@ptrCast([*:0]const u8, debug_str.ptr + off), 0);
}
