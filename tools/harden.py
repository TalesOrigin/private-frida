#!/usr/bin/env python3
"""Post-build hardener for private Frida artifacts.

Takes built Frida binaries (frida-server, frida-gadget, frida-agent,
frida-portal, frida-inject, ...) and makes them harder to fingerprint:

  1. String/symbol replacement  -- replaces well-known fingerprint strings
     ("frida", "Frida", "FRIDA", "gum", "Gum", "GUM") with a configurable
     alias, in place, length-preserving. Only touches printable
     NUL-terminated string runs inside data sections (never code sections),
     so section sizes, relocations and embedded blobs (e.g. the GResource
     agent embedded in frida-server) stay structurally valid. Strings on
     the --keep list (e.g. the "frida:rpc" RPC marker that stock Frida
     clients emit) are left alone so stock clients keep working.
     Because every name-based cross-reference inside a single artifact
     (embedded agent symbols, GResource paths, the "frida_agent_main"
     lookup, ...) is rewritten consistently, renamed artifacts keep
     working as a set.
  2. Stripping                  -- removes symbol/debug tables
     (ELF: .symtab/.strtab/.debug*, Mach-O: symbol table + debug info,
     PE: symbol table + debug directory) using the best available strip
     tool for the artifact's format and architecture.
  3. Renaming                   -- renames the file so the process name
     and module path no longer say "frida" (frida-server -> <alias>-server).

Usage:
  harden.py FILE [FILE ...] [options]

Options:
  --out-dir DIR       write results to DIR instead of in place
  --alias NAME        replacement for "frida" (default: vexrd)
  --no-strip          skip stripping
  --require-strip     fail (instead of warn) if the binary cannot be stripped
  --strip-bin PATH    strip tool to prefer (e.g. a cross or llvm-strip)
  --no-rename         keep the original file names
  --no-strings        skip string replacement
  --keep STR          do not replace occurrences inside STR (repeatable;
                      default: frida:rpc)
  --verbose           print per-file detail
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

DEFAULT_ALIAS = "vexrd"
DEFAULT_KEEP = ["frida:rpc"]

PRINTABLE = frozenset(range(0x20, 0x7F))


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def warn(msg):
    print(f"warning: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Replacement table
# ---------------------------------------------------------------------------

def build_replacements(alias):
    a_upper = alias[0].upper() + alias[1:]
    g = alias[:3]
    # Longest patterns first so one scan pass never double-rewrites.
    return [
        (b"frida", alias.encode("ascii")),
        (b"Frida", a_upper.encode("ascii")),
        (b"FRIDA", alias.upper().encode("ascii")),
        (b"gum", g.encode("ascii")),
        (b"Gum", (g[0].upper() + g[1:]).encode("ascii")),
        (b"GUM", g.upper().encode("ascii")),
    ]


def utf16le(pattern):
    return b"".join(bytes((ord(c), 0)) for c in pattern.decode("ascii"))


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(data):
    if data.startswith(b"\x7fELF"):
        return "elf"
    if len(data) >= 4:
        magic = struct.unpack("<I", data[:4])[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF):
            return "macho"
        if magic in (0xCEFAEDFE, 0xCFFAEDFE):
            return "macho"
        if magic == 0xCAFEBABE or magic == 0xBEBAFECA:
            return "macho-fat"
    if data.startswith(b"MZ") and len(data) > 0x40:
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off + 4] == b"PE\0\0":
            return "pe"
    return None


# ---------------------------------------------------------------------------
# ELF
# ---------------------------------------------------------------------------

def elf_data_sections(data):
    """Yield (name, offset, size) for string-bearing ELF sections."""
    ei_class = data[4]
    if ei_class not in (1, 2):
        return []
    is64 = ei_class == 2
    end = ">" if data[5] == 2 else "<"
    if is64:
        # e_shoff @0x28; e_flags(4)@0x30, e_ehsize(2)@0x34, e_phentsize(2)@0x36,
        # e_phnum(2)@0x38, e_shentsize(2)@0x3a, e_shnum(2)@0x3c, e_shstrndx(2)@0x3e
        e_shoff = struct.unpack_from(end + "Q", data, 0x28)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x3A)
    else:
        # e_shoff @0x20; e_flags(4)@0x24, e_ehsize(2)@0x28, e_phentsize(2)@0x2a,
        # e_phnum(2)@0x2c, e_shentsize(2)@0x2e, e_shnum(2)@0x30, e_shstrndx(2)@0x32
        e_shoff = struct.unpack_from(end + "I", data, 0x20)[0]
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + "HHH", data, 0x2E)
    if e_shoff == 0 or e_shnum == 0 or e_shnum > 65535 or e_shentsize == 0:
        return []

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is64:
            sh_name, sh_type, sh_flags, _sh_addr, sh_offset, sh_size = \
                struct.unpack_from(end + "IIQQQQ", data, off)
        else:
            sh_name, sh_type, sh_flags, _sh_addr, sh_offset, sh_size = \
                struct.unpack_from(end + "IIIIII", data, off)
        sections.append((sh_name, sh_type, sh_offset, sh_size))

    # section name table (section at index e_shstrndx)
    if e_shstrndx >= e_shnum:
        return []
    _name_off, _name_type, name_offset, name_size = sections[e_shstrndx]
    strtab = data[name_offset:name_offset + name_size]

    wanted = {".rodata", ".data", ".dynstr", ".strtab", ".comment"}
    result = []
    for sh_name, _sh_type, sh_offset, sh_size in sections:
        if sh_offset == 0 or sh_size == 0 or sh_offset + sh_size > len(data):
            continue
        name = strtab[sh_name:strtab.find(b"\0", sh_name)].decode("latin-1")
        if name in wanted or name.startswith(".rodata.") or name.startswith(".data."):
            result.append((name, sh_offset, sh_size))
    return result


# ---------------------------------------------------------------------------
# Mach-O
# ---------------------------------------------------------------------------

MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64 = 0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE
LC_SEGMENT, LC_SEGMENT_64 = 1, 0x19


def _macho_sections(data, base):
    """Sections of one Mach-O slice: list of (segname, sectname, offset, size)."""
    magic = struct.unpack_from("<I", data, base)[0]
    is64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    end = ">" if magic in (MH_CIGAM, MH_CIGAM_64) else "<"
    if is64:
        ncmds = struct.unpack_from(end + "I", data, base + 16)[0]
        off = base + 32
    else:
        ncmds = struct.unpack_from(end + "I", data, base + 16)[0]
        off = base + 28
    sections = []
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(end + "II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        if cmd == LC_SEGMENT_64 and is64:
            # cmd u32, cmdsize u32, segname[16], vmaddr u64, vmsize u64,
            # fileoff u64, filesize u64, maxprot i32, initprot i32,
            # nsects u32, flags u32  -> sections start at off+72
            segname = data[off + 8:off + 24].split(b"\0")[0].decode("latin-1")
            nsects = struct.unpack_from(end + "I", data, off + 64)[0]
            soff = off + 72
            for _s in range(nsects):
                # sectname[16], segname[16], addr u64, size u64, offset u32,
                # align u32, reloff u32, nreloc u32, flags u32, resv u32*3
                sectname = data[soff:soff + 16].split(b"\0")[0].decode("latin-1")
                s_size, s_offset = struct.unpack_from(end + "QI", data, soff + 40)
                sections.append((segname, sectname, s_offset, s_size))
                soff += 80
        elif cmd == LC_SEGMENT and not is64:
            # ... segname[16], vmaddr u32, vmsize u32, fileoff u32, filesize u32,
            # maxprot i32, initprot i32, nsects u32, flags u32 -> sections at off+56
            segname = data[off + 8:off + 24].split(b"\0")[0].decode("latin-1")
            nsects = struct.unpack_from(end + "I", data, off + 48)[0]
            soff = off + 56
            for _s in range(nsects):
                # sectname[16], segname[16], addr u32, size u32, offset u32, ...
                sectname = data[soff:soff + 16].split(b"\0")[0].decode("latin-1")
                s_size, s_offset = struct.unpack_from(end + "II", data, soff + 36)
                sections.append((segname, sectname, s_offset, s_size))
                soff += 68
        off += cmdsize
    return sections


def _macho_string_sections(sections, total_size):
    wanted_sect = {"__cstring", "__ustring", "__symbol_string", "__const"}
    wanted_seg = {"__TEXT", "__DATA", "__DATA_CONST"}
    return [(f"{seg}.{sect}", off, size) for seg, sect, off, size in sections
            if seg in wanted_seg and sect in wanted_sect and off + size <= total_size]


def macho_data_sections(data):
    if data[:4] in (struct.pack("<I", 0xCAFEBABE), struct.pack("<I", 0xBEBAFECA)):
        magic = struct.unpack_from("<I", data, 0)[0]
        end = ">" if magic == 0xBEBAFECA else "<"
        nfat = struct.unpack_from(end + "I", data, 4)[0]
        result = []
        for i in range(nfat):
            _cpu, _sub, offset, size, _align = struct.unpack_from(end + "IIIII", data, 8 + i * 20)
            if offset + size > len(data):
                continue
            result.extend(_macho_string_sections(_macho_sections(data, offset), len(data)))
        return result
    return _macho_string_sections(_macho_sections(data, 0), len(data))


# ---------------------------------------------------------------------------
# PE
# ---------------------------------------------------------------------------

def pe_data_sections(data):
    # COFF header starts at pe_off+4 (after the "PE\0\0" signature):
    # machine u16 @0, nsec u16 @2, ts u32 @4, symtab u32 @8, nsyms u32 @12,
    # sizeopt u16 @16, chars u16 @18 -> 20 bytes, optional header follows
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, pe_off + 6)[0]
    sizeopt = struct.unpack_from("<H", data, pe_off + 20)[0]
    opt_off = pe_off + 24
    nsec_off = opt_off + sizeopt
    result = []
    for i in range(nsec):
        off = nsec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].split(b"\0")[0].decode("latin-1")
        rsize, rptr = struct.unpack_from("<II", data, off + 16)
        if rptr == 0 or rsize == 0 or rptr + rsize > len(data):
            continue
        if name in (".rdata", ".data", ".rsrc"):
            result.append((name, rptr, rsize))
    return result


# ---------------------------------------------------------------------------
# String-run scanning and length-preserving replacement
# ---------------------------------------------------------------------------

def _protected_ranges(run, keepers):
    ranges = []
    for keeper in keepers:
        start = 0
        while True:
            idx = run.find(keeper, start)
            if idx == -1:
                break
            ranges.append((idx, idx + len(keeper)))
            start = idx + 1
    return ranges


def replace_in_run(run, patterns, keepers):
    """Replace patterns in one printable string run. Returns (new_run, counts)."""
    protected = _protected_ranges(run, keepers)

    def is_protected(pos, length):
        for s, e in protected:
            if pos < e and pos + length > s:
                return True
        return False

    out = bytearray()
    pos = 0
    counts = {p: 0 for p, _ in patterns}
    while pos < len(run):
        matched = None
        for pat, repl in patterns:
            if run.startswith(pat, pos) and not is_protected(pos, len(pat)):
                matched = (pat, repl)
                break
        if matched is None:
            out.append(run[pos])
            pos += 1
        else:
            pat, repl = matched
            assert len(repl) == len(pat), "replacement must be length-preserving"
            out += repl
            counts[pat] += 1
            pos += len(pat)
    return bytes(out), counts


def utf16_runs(data):
    """Maximal runs of UTF-16LE char pairs with high byte 0 and printable low byte."""
    runs = []
    i = 0
    n = len(data)
    while i < n - 1:
        if data[i + 1] == 0 and data[i] in PRINTABLE:
            start = i
            while i < n - 1 and data[i + 1] == 0 and data[i] in PRINTABLE:
                i += 2
            runs.append((start, data[start:i]))
        else:
            i += 2 if (i % 2 == 0) else 1
    return runs


def harden_strings(data, fmt, alias, keepers, verbose):
    """Return (new_data, total_replacements)."""
    replacements = build_replacements(alias)
    total = 0

    if fmt in ("elf", "macho", "macho-fat"):
        section_fn = elf_data_sections if fmt == "elf" else macho_data_sections
        sections = section_fn(data)
        buf = bytearray(data)
        for name, off, size in sections:
            run_off = off
            run_end = off + size
            # find printable runs
            i = 0
            while i < size:
                if data[off + i] in PRINTABLE:
                    start = i
                    while i < size and data[off + i] in PRINTABLE:
                        i += 1
                    run = data[off + start:off + i]
                    new_run, counts = replace_in_run(run, replacements, keepers)
                    replaced = sum(counts.values())
                    if replaced:
                        buf[off + start:off + start + len(new_run)] = new_run
                        total += replaced
                        if verbose:
                            for pat, c in counts.items():
                                if c:
                                    print(f"    section {name}: replaced {c} x {pat.decode()}")
                else:
                    i += 1
        return bytes(buf), total

    if fmt == "pe":
        sections = pe_data_sections(data)
        buf = bytearray(data)
        # ASCII runs
        for name, off, size in sections:
            i = 0
            while i < size:
                if data[off + i] in PRINTABLE:
                    start = i
                    while i < size and data[off + i] in PRINTABLE:
                        i += 1
                    run = data[off + start:off + i]
                    new_run, counts = replace_in_run(run, replacements, keepers)
                    replaced = sum(counts.values())
                    if replaced:
                        buf[off + start:off + start + len(new_run)] = new_run
                        total += replaced
                        if verbose:
                            print(f"    section {name} (ascii): {sum(counts.values())} replacements")
                else:
                    i += 1
        # UTF-16LE runs (PE resources)
        for name, off, size in sections:
            for start, run in utf16_runs(data[off:off + size]):
                text = run.decode("utf-16-le", errors="ignore")
                if not any(k.lower() in text.lower() for k in ("frida", "gum")):
                    continue
                ukeepers = [utf16le(k) for k in keepers]
                urepl = [(utf16le(p), utf16le(r)) for p, r in replacements]
                new_run, counts = replace_in_run(run, urepl, ukeepers)
                replaced = sum(counts.values())
                if replaced:
                    buf[off + start:off + start + len(new_run)] = new_run
                    total += replaced
                    if verbose:
                        print(f"    section {name} (utf16): {replaced} replacements")
        return bytes(buf), total

    warn(f"unknown format: not touching strings")
    return data, 0


def _keeper_ranges(blob, keepers):
    ranges = []
    for k in keepers:
        if not k:
            continue
        start = 0
        while True:
            idx = blob.find(k, start)
            if idx == -1:
                break
            ranges.append((idx, idx + len(k)))
            start = idx + 1
    return ranges


def is_text(data):
    if len(data) == 0:
        return False
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    control = sum(1 for c in text if ord(c) < 0x20 and c not in "\n\r\t")
    return control / max(len(text), 1) < 0.01


def harden_text(data, alias, keepers, verbose=False):
    """Whole-file replacement for text artifacts (headers, .vapi, .gir, ...)."""
    replacements = build_replacements(alias)
    keepers = [k.decode("ascii") for k in keepers]

    def replace_once(text):
        protected = []
        for k in keepers:
            start = 0
            while True:
                idx = text.find(k, start)
                if idx == -1:
                    break
                protected.append((idx, idx + len(k)))
                start = idx + 1

        def is_protected(pos, length):
            return any(s < pos + length and e > pos for s, e in protected)

        out = []
        pos = 0
        counts = 0
        while pos < len(text):
            matched = None
            for pat, repl in replacements:
                p = pat.decode("ascii")
                if text.startswith(p, pos) and not is_protected(pos, len(p)):
                    matched = (p, repl.decode("ascii"))
                    break
            if matched is None:
                out.append(text[pos])
                pos += 1
            else:
                out.append(matched[1])
                pos += len(matched[0])
                counts += 1
        return "".join(out), counts

    text = data.decode("utf-8")
    new_text, counts = replace_once(text)
    if counts and verbose:
        print(f"    text: {counts} replacements")
    return new_text.encode("utf-8"), counts


def verify_no_leftovers(data, fmt, keepers):
    """Count remaining pattern hits in data sections (0 expected outside keepers)."""
    patterns = [p for p, _ in build_replacements("x" * 5)]
    sections = {"elf": elf_data_sections, "macho": macho_data_sections,
                "macho-fat": macho_data_sections, "pe": pe_data_sections}[fmt](data)
    hits = 0
    for _name, off, size in sections:
        blob = data[off:off + size]
        kranges = _keeper_ranges(blob, keepers)
        for pat in patterns:
            start = 0
            while True:
                idx = blob.find(pat, start)
                if idx == -1:
                    break
                if not any(s < idx + len(pat) and e > idx for s, e in kranges):
                    hits += 1
                start = idx + 1
    return hits


# ---------------------------------------------------------------------------
# Stripping
# ---------------------------------------------------------------------------

def strip_binary(path, preferred=None, verbose=False):
    """Strip `path` in place. Returns (ok, tool_used)."""
    candidates = []
    if preferred:
        candidates.append([preferred])
    candidates.append(["llvm-strip"])
    candidates.append(["strip"])
    for cmd in candidates:
        tool = shutil.which(cmd[0])
        if tool is None:
            if preferred and cmd[0] == preferred:
                warn(f"strip tool not found: {preferred}; falling back")
            continue
        result = subprocess.run([tool, path], capture_output=True, text=True)
        if result.returncode == 0:
            if verbose:
                print(f"    stripped with {tool}")
            return True, tool
        # wrong-architecture "file not recognized" -> try next candidate
        if verbose:
            print(f"    {tool} failed: {result.stderr.strip()[:200]}")
    return False, None


# ---------------------------------------------------------------------------
# Renaming
# ---------------------------------------------------------------------------

def renamed_name(name, alias, do_rename):
    if not do_rename:
        return name
    new = name.replace("frida", alias)
    if new == name:
        # e.g. libgum-*.so style names that don't contain "frida"
        new = name.replace("gum", alias[:3])
    return new


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

BINARY_FORMATS = ("elf", "macho", "macho-fat", "pe")


def process_file(path, args, verbose):
    print(f"harden: {path}")
    data = open(path, "rb").read()
    fmt = detect_format(data)
    is_binary = fmt in BINARY_FORMATS
    if is_binary:
        print(f"    format: {fmt}")
    elif is_text(data):
        fmt = "text"
        print("    format: text")
    else:
        fmt = "unknown"
        warn(f"unrecognized format (not a known binary or text), skipping")

    keepers = [k.encode("ascii") for k in args.keep]

    replacements = 0
    if args.strings and is_binary:
        data, replacements = harden_strings(data, fmt, args.alias, keepers, verbose)
        print(f"    string replacements: {replacements}")
        leftovers = verify_no_leftovers(data, fmt, keepers)
        if leftovers:
            warn(f"{leftovers} un-kept fingerprint string(s) remain in data sections")
    elif args.strings and fmt == "text":
        data, replacements = harden_text(data, args.alias, keepers, verbose)
        print(f"    string replacements: {replacements}")

    # output path: keep the file's position relative to --out-dir when it is
    # inside it (artifact trees), otherwise write next to the input
    newname = renamed_name(os.path.basename(path), args.alias, args.rename)
    if args.out_dir:
        ab_out = os.path.abspath(args.out_dir)
        ab_dir = os.path.abspath(os.path.dirname(path) or ".")
        if ab_dir == ab_out or ab_dir.startswith(ab_out + os.sep):
            out_path = os.path.join(ab_out, os.path.relpath(ab_dir, ab_out), newname)
        else:
            out_path = os.path.join(ab_out, newname)
    else:
        out_path = os.path.join(os.path.dirname(path) or ".", newname)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(out_path) or ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp_path, os.stat(path).st_mode & 0o777)  # keep exec bits
        # sanity: binary magic must survive (text files are expected to change)
        if is_binary and data[:4] != open(path, "rb").read(4):
            die("internal error: magic bytes changed during string replacement")

        stripped = False
        tool = None
        if args.strip:
            if is_binary:
                stripped, tool = strip_binary(tmp_path, args.strip_bin, verbose)
                if not stripped and args.require_strip:
                    die(f"could not strip {path}")
                if not stripped and not args.require_strip:
                    warn(f"could not strip {path} (no working strip tool for this format/arch)")
            elif verbose:
                print("    strip: not applicable")
        else:
            if verbose:
                print("    strip: skipped")

        if os.path.abspath(tmp_path) == os.path.abspath(out_path):
            os.replace(tmp_path, out_path)
        else:
            shutil.move(tmp_path, out_path)
        if os.path.abspath(out_path) != os.path.abspath(path):
            os.remove(path)
        print(f"    -> {out_path} (stripped: {stripped}{f' with {tool}' if tool else ''})")
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return out_path


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="+", metavar="FILE")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument("--alias", default=DEFAULT_ALIAS)
    parser.add_argument("--strip", dest="strip", action="store_true", default=True)
    parser.add_argument("--no-strip", dest="strip", action="store_false")
    parser.add_argument("--require-strip", action="store_true")
    parser.add_argument("--strip-bin", default=None)
    parser.add_argument("--rename", dest="rename", action="store_true", default=True)
    parser.add_argument("--no-rename", dest="rename", action="store_false")
    parser.add_argument("--strings", dest="strings", action="store_true", default=True)
    parser.add_argument("--no-strings", dest="strings", action="store_false")
    parser.add_argument("--keep", action="append", default=None, metavar="STR")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    alias = args.alias
    if len(alias) != 5 or not alias.isascii() or not alias.isalnum():
        die(f"alias must be 5 alphanumeric ascii characters, got '{alias}'")
    if alias.lower() == "frida":
        die("alias must differ from 'frida'")
    args.alias = alias.lower()

    keepers = list(DEFAULT_KEEP)
    for k in (args.keep or []):
        if k not in keepers:
            keepers.append(k)
    args.keep = keepers

    for path in args.files:
        if not os.path.isfile(path):
            die(f"no such file: {path}")
        process_file(path, args, args.verbose)


if __name__ == "__main__":
    main(sys.argv[1:])
