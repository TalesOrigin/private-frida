#!/usr/bin/env python3
"""Generates minimal-but-valid Mach-O and PE binaries containing the
fingerprint strings, for testing tools/harden.py's parsers and replacer
without needing Apple/Windows toolchains."""

import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "."

# ---------------------------------------------------------------- Mach-O 64
cstring = b"frida-server\0Frida/17.18.0\0frida:rpc\0GumQuick\0"
DATA_OFF = 0x100
SECT_SIZE_64 = 80
SEG_HDR = 72

segment_cmdsize = SEG_HDR + SECT_SIZE_64
# magic u32, cputype i32, cpusubtype u16, 2 pad, filetype u32, ncmds u32,
# sizeofcmds u32, flags u32, reserved u32  (32 bytes, load cmds at 32)
header = struct.pack(
    "<IiH2xIIIII",
    0xFEEDFACF,          # magic (MH_MAGIC_64, little-endian)
    0x01000007,          # cputype: X86_64
    3,                   # cpusubtype
    6,                   # filetype: MH_DYLIB
    1,                   # ncmds
    segment_cmdsize,     # sizeofcmds
    0,                   # flags
    0,                   # reserved
)
assert len(header) == 32, len(header)
segment = struct.pack("<II16sQQQQiiII",
                      0x19,                       # LC_SEGMENT_64
                      segment_cmdsize,
                      b"__TEXT",                   # segname
                      0x1000,                     # vmaddr
                      0x2000,                     # vmsize
                      0,                          # fileoff
                      DATA_OFF + len(cstring),    # filesize
                      7,                          # maxprot
                      5,                          # initprot
                      1,                          # nsects
                      0)                          # flags
section = struct.pack("<16s16sQQIIIIIIII",
                      b"__cstring", b"__TEXT",    # names
                      0x1000,                     # addr
                      len(cstring),               # size
                      DATA_OFF,                   # file offset
                      0,                          # align
                      0,                          # reloff
                      0,                          # nreloc
                      0,                          # flags
                      0, 0, 0)                    # reserved
macho = header + segment + section
macho += b"\0" * (DATA_OFF - len(macho))
macho += cstring
open(f"{OUT}/synthetic.macho", "wb").write(macho)

# ---------------------------------------------------------------------- PE
rdata_ascii = b"frida-server\0FRIDA_GUM test\0frida:rpc\0"
rdata_wide = "frida resource\0".encode("utf-16-le")
RDATA_OFF = 0x200
rsize = len(rdata_ascii) + len(rdata_wide)

dos = bytearray(128)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x80)  # e_lfanew

coff = struct.pack("<HHIIIHH",
                   0x8664,   # machine: AMD64
                   1,        # nsec
                   0,        # timestamp
                   0,        # symtab ptr
                   0,        # nsyms
                   240,      # size of optional header
                   0x2)      # chars: executable

opt = bytearray(240)
struct.pack_into("<H", opt, 0, 0x20B)  # PE32+ magic

sec = bytearray(40)
sec[0:6] = b".rdata"
struct.pack_into("<II", sec, 8, rsize, 0x1000)          # vsize, vaddr
struct.pack_into("<II", sec, 16, rsize, RDATA_OFF)      # rsize, rptr

pe = bytes(dos) + b"PE\0\0" + coff + bytes(opt) + bytes(sec)
pad_to = RDATA_OFF - len(pe)
assert pad_to >= 0, pad_to
pe += b"\0" * pad_to
pe += rdata_ascii + rdata_wide
open(f"{OUT}/synthetic.exe", "wb").write(pe)

print(f"wrote {OUT}/synthetic.macho ({len(macho)} bytes)")
print(f"wrote {OUT}/synthetic.exe ({len(pe)} bytes)")
