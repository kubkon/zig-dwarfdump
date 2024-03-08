base: Context,
version: u32,

debug_info: []const u8 = &.{},
debug_line: []const u8 = &.{},
debug_loc: []const u8 = &.{},
debug_ranges: []const u8 = &.{},
debug_pubnames: []const u8 = &.{},
debug_pubtypes: []const u8 = &.{},
debug_str: []const u8 = &.{},
debug_abbrev: []const u8 = &.{},

pub fn isWasmFile(data: []const u8) bool {
    return data.len >= 4 and std.mem.eql(u8, &std.wasm.magic, data[0..4]);
}

pub fn deinit(wasm_file: *Wasm, gpa: std.mem.Allocator) void {
    _ = wasm_file;
    _ = gpa;
}

pub fn parse(gpa: std.mem.Allocator, data: []const u8) !*Wasm {
    const wasm = try gpa.create(Wasm);
    errdefer gpa.destroy(wasm);

    wasm.* = .{
        .base = .{
            .tag = .wasm,
            .data = data,
        },
        .version = 0,
    };

    var fbs = std.io.fixedBufferStream(data);
    const reader = fbs.reader();
    try reader.skipBytes(4, .{});
    wasm.version = try reader.readInt(u32, .little);

    while (reader.readByte()) |byte| {
        const tag = try std.meta.intToEnum(std.wasm.Section, byte);
        const len = try std.leb.readULEB128(u32, reader);
        switch (tag) {
            .custom => {
                const name_len = try std.leb.readULEB128(u32, reader);
                var buf: [200]u8 = undefined;
                try reader.readNoEof(buf[0..name_len]);
                const name = buf[0..name_len];
                const remaining_size =
                    len - getULEB128Size(name_len) - name_len;
                if (std.mem.startsWith(u8, name, ".debug")) {
                    const debug_info = data[reader.context.pos..][0..remaining_size];
                    if (std.mem.eql(u8, name, ".debug_info")) {
                        wasm.debug_info = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_line")) {
                        wasm.debug_line = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_loc")) {
                        wasm.debug_loc = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_ranges")) {
                        wasm.debug_ranges = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_pubnames")) {
                        wasm.debug_pubnames = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_pubtypes")) {
                        wasm.debug_pubtypes = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_abbrev")) {
                        wasm.debug_abbrev = debug_info;
                    } else if (std.mem.eql(u8, name, ".debug_str")) {
                        wasm.debug_str = debug_info;
                    }
                }
                try reader.skipBytes(remaining_size, .{});
            },
            else => try reader.skipBytes(len, .{}),
        }
    } else |err| switch (err) {
        error.EndOfStream => {}, // finished parsing
        else => |e| return e,
    }
    return wasm;
}

pub fn getDebugAbbrevData(wasm_file: *const Wasm) ?[]const u8 {
    if (wasm_file.debug_abbrev.len == 0) return null;
    return wasm_file.debug_abbrev;
}

pub fn getDebugStringData(wasm_file: *const Wasm) ?[]const u8 {
    if (wasm_file.debug_str.len == 0) return null;
    return wasm_file.debug_str;
}

pub fn getDebugInfoData(wasm_file: *const Wasm) ?[]const u8 {
    if (wasm_file.debug_info.len == 0) return null;
    return wasm_file.debug_info;
}

/// From a given unsigned integer, returns the size it takes
/// in bytes to store the integer using leb128-encoding.
fn getULEB128Size(uint_value: anytype) u32 {
    const T = @TypeOf(uint_value);
    const U = if (@typeInfo(T).Int.bits < 8) u8 else T;
    var value = @as(U, @intCast(uint_value));

    var size: u32 = 0;
    while (value != 0) : (size += 1) {
        value >>= 7;
    }
    return size;
}

const std = @import("std");
const Context = @import("../Context.zig");
const Wasm = @This();
