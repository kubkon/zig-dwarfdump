base: Context,

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
    };
    return wasm;
}

const std = @import("std");
const Context = @import("../Context.zig");
const Wasm = @This();
