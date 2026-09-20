#!/usr/bin/env bash
# Patches the Frida source tree (submodule checkout) so the built artifacts
# use custom default ports instead of the well-known 27042/27052.
#
#   usage: patch-defaults.sh --root <frida source dir> --port <N> [--cluster-port <M>]
#
# The control port is what frida-server binds (and what frida-inject /
# frida-portal / the python client connect to by default). The cluster port
# is used for peer server clustering; it defaults to <N> + 10, matching the
# upstream 27042/27052 offset.
set -euo pipefail

ROOT=""
PORT=""
CLUSTER=""

while [ $# -gt 0 ]; do
  case "$1" in
    --root) ROOT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --cluster-port) CLUSTER="$2"; shift 2 ;;
    *) echo "usage: $0 --root DIR --port N [--cluster-port M]" >&2; exit 2 ;;
  esac
done

if [ -z "$ROOT" ] || [ -z "$PORT" ]; then
  echo "usage: $0 --root DIR --port N [--cluster-port M]" >&2
  exit 2
fi

case "$PORT" in
  ''|*[!0-9]*) echo "error: port must be a number, got '$PORT'" >&2; exit 2 ;;
esac
if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "error: port out of range 1-65535: $PORT" >&2
  exit 2
fi
if [ -z "$CLUSTER" ]; then
  CLUSTER=$(( (PORT + 10) % 65536 ))
fi
case "$CLUSTER" in
  ''|*[!0-9]*) echo "error: cluster port must be a number, got '$CLUSTER'" >&2; exit 2 ;;
esac
if [ "$CLUSTER" -lt 1 ] || [ "$CLUSTER" -gt 65535 ]; then
  echo "error: cluster port out of range 1-65535: $CLUSTER" >&2
  exit 2
fi

FILE="$ROOT/subprojects/frida-core/lib/base/socket.vala"
if [ ! -f "$FILE" ]; then
  echo "error: $FILE not found (is the frida-core submodule checked out?)" >&2
  exit 1
fi

PY="$(command -v python3 || command -v python)"
"$PY" - "$FILE" "$PORT" "$CLUSTER" <<'EOF'
import re
import sys

path, port, cluster = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path, encoding="utf-8").read()

new, n_control = re.subn(r"DEFAULT_CONTROL_PORT\s*=\s*\d+",
                         f"DEFAULT_CONTROL_PORT = {port}", src)
new, n_cluster = re.subn(r"DEFAULT_CLUSTER_PORT\s*=\s*\d+",
                         f"DEFAULT_CLUSTER_PORT = {cluster}", new)

if n_control != 1 or n_cluster != 1:
    sys.exit(f"error: expected to patch 1 control + 1 cluster port constant, "
             f"got {n_control} + {n_cluster} (frida version drift?)")

open(path, "w", encoding="utf-8").write(new)
print(f"patched {path}")
print(f"  DEFAULT_CONTROL_PORT: 27042 -> {port}")
print(f"  DEFAULT_CLUSTER_PORT: 27052 -> {cluster}")
EOF
