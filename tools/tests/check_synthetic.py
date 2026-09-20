#!/usr/bin/env python3
"""Asserts harden.py's output on the synthetic Mach-O/PE test files."""
import sys

alias, path, kind = sys.argv[1], sys.argv[2], sys.argv[3]
a_upper = alias[0].upper() + alias[1:]
g_upper = alias[:3].upper()

data = open(path, "rb").read()

if kind == "macho":
    # input was: "frida-server\0Frida/17.18.0\0frida:rpc\0GumQuick\0"
    expect = {
        f"{alias}-server".encode(): "lowercase name",
        f"{a_upper}/17.18.0".encode(): "capitalized name",
        b"frida:rpc": "kept wire marker",
        (alias[:3][0].upper() + alias[:3][1:] + "Quick").encode(): "Gum prefix",
    }
    forbid = [b"frida-server", b"Frida/", b"GumQuick"]
elif kind == "pe":
    # ascii input: "frida-server\0FRIDA_GUM test\0frida:rpc\0"
    # wide input:  "frida resource\0"
    expect = {
        f"{alias}-server".encode(): "ascii name",
        f"{alias.upper()}_{g_upper} test".encode(): "ascii FRIDA_GUM",
        b"frida:rpc": "kept ascii wire marker",
        f"{alias} resource\0".encode("utf-16-le"): "kept wide name (utf-16)",
    }
    forbid = [b"frida-server", b"FRIDA_GUM"]
else:
    sys.exit(f"unknown kind {kind}")

for needle, label in expect.items():
    assert needle in data, f"{kind}: missing {label}: {needle!r}"

for needle in forbid:
    assert needle not in data, f"{kind}: still present: {needle!r}"
    assert needle.decode("ascii").encode("utf-16-le") not in data, \
        f"{kind}: still present (utf-16): {needle!r}"

print(f"synthetic {kind} checks passed")
