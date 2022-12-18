const MachO = @This();

const std = @import("std");

const Allocator = std.mem.Allocator;
const Context = @import("../Context.zig");

pub const base_tag: Context.Tag = .macho;

base: Context,

header: std.macho.mach_header_64,

debug_info: []const u8,
debug_abbrev: []const u8,
debug_string: []const u8,

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
        .debug_info = undefined,
        .debug_abbrev = undefined,
        .debug_string = undefined,
    };

    macho.header = @ptrCast(*const std.macho.mach_header_64, @alignCast(@alignOf(std.macho.mach_header_64), data.ptr)).*;

    var debug_info_h: ?std.macho.section_64 = null;
    var debug_abbrev_h: ?std.macho.section_64 = null;
    var debug_string_h: ?std.macho.section_64 = null;

    var it = macho.getLoadCommandsIterator();
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            for (lc.getSections()) |sect| {
                if (std.mem.eql(u8, sect.segName(), "__DWARF")) {
                    if (std.mem.eql(u8, sect.sectName(), "__debug_info")) {
                        debug_info_h = sect;
                    }
                    if (std.mem.eql(u8, sect.sectName(), "__debug_abbrev")) {
                        debug_abbrev_h = sect;
                    }
                    if (std.mem.eql(u8, sect.sectName(), "__debug_str")) {
                        debug_string_h = sect;
                    }
                }
            }
        },
        else => {},
    };

    if (debug_info_h == null or debug_abbrev_h == null or debug_string_h == null) {
        return error.MissingDebugInfo;
    }

    const dih = debug_info_h.?;
    const dah = debug_abbrev_h.?;
    const dsh = debug_string_h.?;
    macho.debug_info = data[dih.offset..][0..dih.size];
    macho.debug_abbrev = data[dah.offset..][0..dah.size];
    macho.debug_string = data[dsh.offset..][0..dsh.size];

    return macho;
}

pub fn getDebugInfoData(macho: *const MachO) []const u8 {
    return macho.debug_info;
}

pub fn getDebugStringData(macho: *const MachO) []const u8 {
    return macho.debug_string;
}

pub fn getDebugAbbrevData(macho: *const MachO) []const u8 {
    return macho.debug_abbrev;
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

fn getLoadCommandsIterator(macho: *const MachO) std.macho.LoadCommandIterator {
    const data = @alignCast(@alignOf(u64), macho.base.data[@sizeOf(std.macho.mach_header_64)..])[0..macho.header.sizeofcmds];
    return .{
        .ncmds = macho.header.ncmds,
        .buffer = data,
    };
}
