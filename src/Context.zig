const Context = @This();

const std = @import("std");
const elf = std.elf;
const macho = std.macho;
const mem = std.mem;

debug_info: []const u8,
debug_abbrev: []const u8,
debug_str: []const u8,

pub fn parse(data: []const u8) !Context {
    // Try MachO first
    {
        const header = @ptrCast(*const macho.mach_header_64, @alignCast(@alignOf(macho.mach_header_64), data.ptr)).*;
        if (header.magic == macho.MH_MAGIC_64) {
            return parseMachO(data);
        }
    }

    // Next, let's try ELF
    {
        // TODO: 32bit ELF files
        const header = @ptrCast(*const elf.Elf64_Ehdr, @alignCast(@alignOf(elf.Elf64_Ehdr), data.ptr)).*;
        if (mem.eql(u8, "\x7fELF", header.e_ident[0..4])) {
            return parseElf(data);
        }
    }

    return error.TODOOtherBackends;
}

fn parseMachO(data: []const u8) !Context {
    const header = @ptrCast(*const macho.mach_header_64, @alignCast(@alignOf(macho.mach_header_64), data.ptr)).*;

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
                if (mem.eql(u8, sect.segName(), "__DWARF")) {
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

fn parseElf(data: []const u8) !Context {
    const header = @ptrCast(*const elf.Elf64_Ehdr, @alignCast(@alignOf(elf.Elf64_Ehdr), data.ptr)).*;

    const shdrs = @ptrCast(
        [*]const elf.Elf64_Shdr,
        @alignCast(@alignOf(elf.Elf64_Shdr), data.ptr + header.e_shoff),
    )[0..header.e_shnum];

    const shstrtab = blk: {
        const shdr = shdrs[header.e_shstrndx];
        break :blk data[shdr.sh_offset..][0..shdr.sh_size];
    };

    var debug_info_h: ?elf.Elf64_Shdr = null;
    var debug_abbrev_h: ?elf.Elf64_Shdr = null;
    var debug_str_h: ?elf.Elf64_Shdr = null;

    for (shdrs) |shdr| switch (shdr.sh_type) {
        elf.SHT_PROGBITS => {
            const sh_name = mem.sliceTo(@ptrCast([*:0]const u8, shstrtab.ptr + shdr.sh_name), 0);
            if (mem.eql(u8, sh_name, ".debug_info")) {
                debug_info_h = shdr;
            }
            if (mem.eql(u8, sh_name, ".debug_abbrev")) {
                debug_abbrev_h = shdr;
            }
            if (mem.eql(u8, sh_name, ".debug_str")) {
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
    const debug_info = data[dih.sh_offset..][0..dih.sh_size];
    const debug_abbrev = data[dah.sh_offset..][0..dah.sh_size];
    const debug_str = data[dsh.sh_offset..][0..dsh.sh_size];

    return Context{
        .debug_info = debug_info,
        .debug_abbrev = debug_abbrev,
        .debug_str = debug_str,
    };
}
