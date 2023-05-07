const MachO = @This();

const std = @import("std");

const Allocator = std.mem.Allocator;
const Context = @import("../Context.zig");

pub const base_tag: Context.Tag = .macho;

base: Context,

header: std.macho.mach_header_64,
debug_info_sect: ?std.macho.section_64 = null,
debug_abbrev_sect: ?std.macho.section_64 = null,
debug_string_sect: ?std.macho.section_64 = null,

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

    var it = macho.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            for (lc.getSections()) |sect| {
                if (std.mem.eql(u8, sect.segName(), "__DWARF")) {
                    if (std.mem.eql(u8, sect.sectName(), "__debug_info")) {
                        macho.debug_info_sect = sect;
                    }
                    if (std.mem.eql(u8, sect.sectName(), "__debug_abbrev")) {
                        macho.debug_abbrev_sect = sect;
                    }
                    if (std.mem.eql(u8, sect.sectName(), "__debug_str")) {
                        macho.debug_string_sect = sect;
                    }
                }
            }
        },
        else => {},
    };

    return macho;
}

pub fn getDebugInfoData(macho: *const MachO) ?[]const u8 {
    const sect = macho.debug_info_sect orelse return null;
    return macho.getSectionData(sect);
}

pub fn getDebugStringData(macho: *const MachO) ?[]const u8 {
    const sect = macho.debug_string_sect orelse return null;
    return macho.getSectionData(sect);
}

pub fn getDebugAbbrevData(macho: *const MachO) ?[]const u8 {
    const sect = macho.debug_abbrev_sect orelse return null;
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

pub fn getArch(macho: *const MachO) ?std.Target.Cpu.Arch {
    _ = macho;
    return null;
}
