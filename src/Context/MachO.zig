const MachO = @This();

const std = @import("std");

const Allocator = std.mem.Allocator;
const Context = @import("../Context.zig");

pub const base_tag: Context.Tag = .macho;

base: Context,

header: std.macho.mach_header_64,

pub fn isMachOFile(data: []const u8) bool {
    const header = @ptrCast(*const std.macho.mach_header_64, @alignCast(@alignOf(std.macho.mach_header_64), data.ptr)).*;
    return header.magic == std.macho.MH_MAGIC_64;
}

pub fn deinit(macho: *MachO, gpa: Allocator) void {
    _ = macho;
    _ = gpa;
}

pub fn parse(gpa: Allocator, data: []const u8) !*MachO {
    const macho = try gpa.create(MachO);
    errdefer gpa.destroy(macho);

    macho.* = .{
        .base = .{
            .tag = .macho,
            .data = data,
        },
        .header = undefined,
    };

    macho.header = @ptrCast(*const std.macho.mach_header_64, @alignCast(@alignOf(std.macho.mach_header_64), data.ptr)).*;

    return macho;
}

pub fn getDebugInfoData(macho: *const MachO) ![]const u8 {
    const sect = macho.getSectionByName("__DWARF", "__debug_info") orelse return error.MissingDebugInfo;
    return macho.getSectionData(sect);
}

pub fn getDebugStringData(macho: *const MachO) ![]const u8 {
    const sect = macho.getSectionByName("__DWARF", "__debug_str") orelse return error.MissingDebugInfo;
    return macho.getSectionData(sect);
}

pub fn getDebugAbbrevData(macho: *const MachO) ![]const u8 {
    const sect = macho.getSectionByName("__DWARF", "__debug_abbrev") orelse return error.MissingDebugInfo;
    return macho.getSectionData(sect);
}

pub fn getSectionByName(macho: *const MachO, segname: []const u8, sectname: []const u8) ?std.macho.section_64 {
    var it = macho.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            for (lc.getSections()) |sect| {
                if (std.mem.eql(u8, sect.segName(), segname) and std.mem.eql(u8, sect.sectName(), sectname)) {
                    return sect;
                }
            }
        },
        else => {},
    };
    return null;
}

pub fn getSectionData(macho: *const MachO, sect: std.macho.section_64) []const u8 {
    const size = @intCast(usize, sect.size);
    return macho.base.data[sect.offset..][0..size];
}

pub fn isX86(macho: *const MachO) bool {
    return macho.header.cputype == std.macho.CPU_TYPE_X86_64;
}

pub fn isARM(macho: *const MachO) bool {
    return macho.header.cputype == std.macho.CPU_TYPE_ARM64;
}

fn getLoadCommandsIterator(macho: *const MachO) std.macho.LoadCommandIterator {
    const data = @alignCast(@alignOf(u64), macho.base.data[@sizeOf(std.macho.mach_header_64)..])[0..macho.header.sizeofcmds];
    return .{
        .ncmds = macho.header.ncmds,
        .buffer = data,
    };
}
