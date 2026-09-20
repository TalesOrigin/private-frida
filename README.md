# private-frida

A private build pipeline for [Frida](https://frida.re) that produces
artifacts hardened against fingerprinting and detection:

- **Custom ports** — the built `frida-server` (and the default connect
  port of `frida-inject` / `frida-portal`) no longer uses the well-known
  **27042**/27052 control/cluster ports.
- **Stripped symbols** — symbol tables and debug info are removed from
  every built artifact (ELF, Mach-O, PE).
- **Patched names and strings** — fingerprint strings and symbol names
  (`frida`, `Frida`, `FRIDA`, `gum`, `Gum`, `GUM`) are rewritten to a
  configurable alias, and artifacts are renamed (`frida-server` →
  `<alias>-server`), so the process name, module path (`/proc/*/maps`)
  and on-disk binary no longer identify as Frida.

Built on top of the upstream Frida source (pinned as a git submodule).

## How to build

Use the **Build Frida** workflow (`workflow_dispatch`) and choose:

| Input       | Default | Meaning                                                                 |
| ----------- | ------- | ----------------------------------------------------------------------- |
| `os`        | android | Target OS (windows / linux / macos / android / ios)                      |
| `arch`      | arm64   | Target architecture                                                      |
| `component` | frida-server | Component to build (see workflow options)                          |
| `port`      | `39053` | Custom default control port (cluster port = `port + 10`)                |
| `alias`     | `vexrd` | Replacement for `frida` — exactly 5 alphanumeric chars, `a-z0-9`         |
| `strip`     | `true`  | Strip symbols from artifacts                                            |
| `rename`    | `true`  | Rename artifacts away from `frida-*`                                    |
| `obfuscate` | `true`  | Patch fingerprint strings/symbols in artifacts                          |

After the build, download the `frida-<component>-<os>-<arch>` artifact.
For a `frida-server` build with the defaults the artifact is
`vexrd-server`, listening on `127.0.0.1:39053` by default.

### Using the private server with a stock client

The client on your machine is unchanged; just point it at the custom
port:

```sh
frida -H 127.0.0.1:39053            # or over adb:
adb forward tcp:39053 tcp:39053
frida -H 127.0.0.1:39053 -U
```

`frida.get_device_manager().add_remote_device('127.0.0.1:39053')` works
equally well from Python.

## What gets changed and what doesn't

Per artifact (ELF / Mach-O / PE, incl. the agent embedded inside
`frida-server`'s GResource blob):

1. **String/symbol patching** (`tools/harden.py`, `--strings`)
   - `frida`/`Frida`/`FRIDA` → alias (e.g. `vexrd`/`Vexrd`/`VEXRD`)
   - `gum`/`Gum`/`GUM` → alias prefix (e.g. `vex`/`Vex`/`VEX`)
   - Replacement is length-preserving and only touches printable
     NUL-terminated string runs inside data sections — never code
     sections, never binary data (icons, GResource tables, embedded
     agent code). All name-based cross-references *inside* one artifact
     are rewritten consistently (embedded agent symbol
     `frida_agent_main`, GResource paths, the server's own lookup
     string, HTTP `Server:` banner, `re.frida.server` temp dir, …).
   - **`frida:rpc` is whitelisted**: the RPC wire marker used by stock
     Frida clients is left untouched, so unmodified clients keep working.
     Add more exceptions with `--keep STR` (repeatable).
2. **Stripping** — `strip`/`llvm-strip`/cross `*-strip` as appropriate
   for the target architecture (`.symtab`/`.strtab`/`.debug*` removed;
   dynamic symbols needed at runtime are kept).
3. **Renaming** — every `frida` in the file name is replaced with the
   alias: `frida-server` → `vexrd-server`, `frida-gadget.so` →
   `vexrd-gadget.so`, `libfrida-core.a` → `libvexrd-core.a`, …

The port change is applied at **build time** by
`tools/patch-defaults.sh`, which rewrites
`subprojects/frida-core/lib/base/socket.vala`:

```
DEFAULT_CONTROL_PORT = 27042  ->  <port>
DEFAULT_CLUSTER_PORT = 27052  ->  <port> + 10
```

### Compatibility notes

- A private `frida-server` works with **stock clients** (python `frida`,
  `frida-tools`) — only the port differs.
- Private **agents/gadgets** must be paired with a private server from
  the *same build*, because their entry symbols
  (`frida_agent_main` / `frida_gadget_main`) are renamed too. An
  injector that `dlsym`s the gadget entry must use the renamed symbol
  (`<alias>_gadget_main`).
- Builds with `assets=installed` (e.g. iOS) load the agent from disk at
  runtime: rename the installed asset files/dirs to match the alias as
  well (e.g. `frida-17/…/frida-agent-64.so` →
  `<alias>-17/…/<alias>-agent-64.so`).
- `debug: true` + `strip: true` = debug build that is stripped again at
  the end. Use `strip: false` to keep symbols.

## Local testing

```sh
bash tools/tests/run_tests.sh
```

Builds a realistic fixture pair (a shared-library "agent" embedded into
an executable "server", mirroring `frida-agent` inside
`frida-server`), runs the hardener, and verifies that the hardened
binary still runs with all name-based lookups passing, that fingerprint
strings are gone (except `frida:rpc`), that symbols are stripped, that
embedded binary data is byte-identical, and exercises the Mach-O and PE
code paths with synthetic binaries.

```
$ bash tools/tests/run_tests.sh | tail -6
  ok: mach-o synthetic: strings replaced, rpc kept, keep-list honored
== testing PE code path (synthetic)
synthetic pe checks passed
  ok: pe synthetic: ascii + utf-16 strings replaced, rpc kept

ALL TESTS PASSED
```

`tools/harden.py` can also be run standalone on any Frida artifact:

```sh
python3 tools/harden.py frida-server-17.18.0-android-arm64 \
    --alias vexrd --verbose            # strip + rename + patch
python3 tools/harden.py x.so --no-strings --keep 'frida:rpc'
```
