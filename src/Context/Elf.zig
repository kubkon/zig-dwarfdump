const Elf = @This();

const std = @import("std");

const Allocator = std.mem.Allocator;
const Context = @import("../Context.zig");

pub const base_tag: Context.Tag = .elf;

base: Context,

header: std.elf.Elf64_Ehdr,

debug_info: []const u8,
debug_abbrev: []const u8,
debug_str: []const u8,

pub fn isElfFile(data: []const u8) bool {
    // TODO: 32bit ELF files
    const header = @ptrCast(*const std.elf.Elf64_Ehdr, @alignCast(@alignOf(std.elf.Elf64_Ehdr), data.ptr)).*;
    return std.mem.eql(u8, "\x7fELF", header.e_ident[0..4]);
}

pub fn deinit(elf: *Elf, gpa: Allocator) void {
    _ = elf;
    _ = gpa;
}

pub fn parse(gpa: Allocator, data: []const u8) !*Elf {
    const elf = try gpa.create(Elf);
    errdefer gpa.destroy(elf);

    elf.* = .{
        .base = .{
            .tag = .elf,
            .data = data,
        },
        .header = undefined,
        .debug_info = undefined,
        .debug_abbrev = undefined,
        .debug_str = undefined,
    };
    elf.header = @ptrCast(*const std.elf.Elf64_Ehdr, @alignCast(@alignOf(std.elf.Elf64_Ehdr), data.ptr)).*;

    const shdrs = elf.getShdrs();

    var debug_info_h: ?std.elf.Elf64_Shdr = null;
    var debug_abbrev_h: ?std.elf.Elf64_Shdr = null;
    var debug_str_h: ?std.elf.Elf64_Shdr = null;

    for (shdrs) |shdr, i| switch (shdr.sh_type) {
        std.elf.SHT_PROGBITS => {
            const sh_name = elf.getShString(@intCast(u32, i));
            if (std.mem.eql(u8, sh_name, ".debug_info")) {
                debug_info_h = shdr;
            }
            if (std.mem.eql(u8, sh_name, ".debug_abbrev")) {
                debug_abbrev_h = shdr;
            }
            if (std.mem.eql(u8, sh_name, ".debug_str")) {
                debug_str_h = shdr;
            }
        },
        else => {},
    };

    if (debug_info_h == null or debug_abbrev_h == null or debug_str_h == null) {
        return error.MissingDebugInfo;
    }

    const dih = debug_info_h.?;
    const dah = debug_abbrev_h.?;
    const dsh = debug_str_h.?;
    elf.debug_info = data[dih.sh_offset..][0..dih.sh_size];
    elf.debug_abbrev = data[dah.sh_offset..][0..dah.sh_size];
    elf.debug_str = data[dsh.sh_offset..][0..dsh.sh_size];

    return elf;
}

pub fn getDebugInfoData(elf: *const Elf) []const u8 {
    return elf.debug_info;
}

pub fn getDebugStringData(elf: *const Elf) []const u8 {
    return elf.debug_str;
}

pub fn getDebugAbbrevData(elf: *const Elf) []const u8 {
    return elf.debug_abbrev;
}

fn getShdrs(elf: *const Elf) []const std.elf.Elf64_Shdr {
    const shdrs = @ptrCast(
        [*]const std.elf.Elf64_Shdr,
        @alignCast(@alignOf(std.elf.Elf64_Shdr), elf.base.data.ptr + elf.header.e_shoff),
    )[0..elf.header.e_shnum];
    return shdrs;
}

fn getShdrData(elf: *const Elf, index: u32) []const u8 {
    const shdrs = elf.getShdrs();
    const shdr = shdrs[index];
    return elf.base.data[shdr.sh_offset..][0..shdr.sh_size];
}

fn getShString(elf: *const Elf, off: u32) []const u8 {
    const shstrtab = elf.getShdrData(elf.header.e_shstrndx);
    std.debug.assert(off < shstrtab.len);
    return std.mem.sliceTo(@ptrCast([*:0]const u8, shstrtab.ptr + off), 0);
}
