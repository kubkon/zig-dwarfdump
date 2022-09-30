const Context = @This();

const std = @import("std");
const macho = std.macho;
const mem = std.mem;

debug_info: []const u8,
debug_abbrev: []const u8,
debug_str: []const u8,

pub fn parse(data: []const u8) !Context {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();

    // Try MachO first
    const header = try reader.readStruct(macho.mach_header_64);
    if (header.magic == macho.MH_MAGIC_64) {
        return parseMachO(data);
    }

    return error.TODOOtherBackends;
}

fn parseMachO(data: []const u8) !Context {
    var stream = std.io.fixedBufferStream(data);
    const reader = stream.reader();
    const header = try reader.readStruct(macho.mach_header_64);

    var debug_info_h: ?macho.section_64 = null;
    var debug_abbrev_h: ?macho.section_64 = null;
    var debug_string_h: ?macho.section_64 = null;

    const lc_data = @alignCast(@alignOf(u64), data.ptr + @sizeOf(macho.mach_header_64))[0..header.sizeofcmds];
    var it = macho.LoadCommandIterator{
        .ncmds = header.ncmds,
        .buffer = lc_data,
    };
    while (it.next()) |lc| switch (lc.cmd()) {
        .SEGMENT_64 => {
            for (lc.getSections()) |sect| {
                if (!sect.isDebug()) continue;
                if (mem.eql(u8, sect.sectName(), "__debug_info")) {
                    debug_info_h = sect;
                }
                if (mem.eql(u8, sect.sectName(), "__debug_abbrev")) {
                    debug_abbrev_h = sect;
                }
                if (mem.eql(u8, sect.sectName(), "__debug_str")) {
                    debug_string_h = sect;
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
    const debug_info = data[dih.offset..][0..dih.size];
    const debug_abbrev = data[dah.offset..][0..dah.size];
    const debug_string = data[dsh.offset..][0..dsh.size];

    return Context{
        .debug_info = debug_info,
        .debug_abbrev = debug_abbrev,
        .debug_str = debug_string,
    };
}
