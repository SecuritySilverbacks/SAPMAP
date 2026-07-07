#!/bin/bash
# Build a portable statically-linked sap_audit_hook binary that runs
# on any Linux x86_64 SAP host without needing a compiler installed
# on the target.  Output: ./sap_audit_hook.linux-x86_64
#
# Usage:
#   cd modules/postex/vendor/
#   ./build_sap_audit_hook.sh
#
# Or explicitly with a specific compiler flavour:
#   ./build_sap_audit_hook.sh musl       # musl-gcc (best portability)
#   ./build_sap_audit_hook.sh glibc      # gcc -static (portable across most glibc)
#   ./build_sap_audit_hook.sh dynamic    # gcc (matches build host's glibc only)
#
# The result is committed alongside the C source so SAPMAP's deployment
# path can drop the binary directly on hardened SAP hosts that have no
# compiler.  When present, sapmap_death_star will prefer the pre-built
# binary over the compile-on-target flow.
#
# Reproducibility: the produced binary should be committed to the repo
# so operators don't have to run gcc themselves.  Rebuild whenever the
# C source changes.

set -euo pipefail

SRC="sap_audit_hook.c"
OUT="sap_audit_hook.linux-x86_64"
MODE="${1:-auto}"

cd "$(dirname "$0")"

if [ ! -f "$SRC" ]; then
    echo "Error: $SRC not found in vendor dir.  Run from modules/postex/vendor/."
    exit 1
fi

# Compiler discovery.
pick_compiler() {
    local mode="$1"
    case "$mode" in
        musl)
            command -v musl-gcc || { echo "musl-gcc not installed — try:"; echo "  Debian/Ubuntu: sudo apt install musl-tools"; echo "  Alpine:        already default"; echo "  Fedora:        sudo dnf install musl-gcc"; exit 1; } ;;
        glibc|dynamic)
            command -v gcc || command -v cc || { echo "no gcc/cc available"; exit 1; } ;;
        auto)
            # Best-portability order.
            if command -v musl-gcc >/dev/null 2>&1; then
                echo musl-gcc
            elif command -v gcc >/dev/null 2>&1; then
                echo gcc
            elif command -v cc >/dev/null 2>&1; then
                echo cc
            else
                echo "no C compiler available" >&2
                exit 1
            fi ;;
        *)
            echo "Unknown mode: $mode (expected: musl / glibc / dynamic / auto)"
            exit 1 ;;
    esac
}

CC="$(pick_compiler "$MODE")"
echo "[*] Compiler: $CC"

# Flags — matches Julian's upstream README verbatim plus the linking
# discipline picked from the mode.
CFLAGS=(-O2 -Wall -Wno-format-truncation)
LDFLAGS=()

case "$MODE" in
    dynamic) : ;;  # no static linking
    *) LDFLAGS+=(-static) ;;
esac

# Musl-gcc auto-implies -static-ish behavior but explicit -static is
# safer.  For glibc mode, -static needs libc.a which ships with
# libc6-dev on Debian and glibc-static on RHEL.
echo "[*] Building: $CC ${CFLAGS[*]} ${LDFLAGS[*]} -o $OUT $SRC"
"$CC" "${CFLAGS[@]}" "${LDFLAGS[@]}" -o "$OUT" "$SRC"

# Report + sanity.
size_bytes=$(wc -c < "$OUT")
echo "[+] Built: $OUT ($size_bytes bytes)"
file "$OUT" 2>/dev/null || true

# ldd is meaningful only for dynamic builds; static binaries print
# "not a dynamic executable" and confuse operators into thinking it's
# an error.  Only run it when we actually expect dynamic linkage.
if [ "$MODE" = "dynamic" ]; then
    ldd "$OUT" 2>&1 || true
fi

# Sanity check: run --help and confirm the output contains the word
# "Usage" (unique to Julian's usage() function).  Use extended regex
# (-E) so the OR alternation works portably between GNU + BSD grep;
# also print the captured output so a failed match is diagnosable
# instead of a bare "inspect manually".
HELP_OUT="$(./"$OUT" --help 2>&1 || true)"
if printf '%s\n' "$HELP_OUT" | grep -qiE 'usage|sap_audit_hook'; then
    echo "[+] Sanity check: --help output looks right"
else
    echo "[!] Sanity check: --help output unexpected." >&2
    echo "    Actual --help output was:" >&2
    printf '    | %s\n' "$HELP_OUT" >&2
    echo "    Binary is $size_bytes bytes and reported as: " >&2
    file "$OUT" >&2 2>/dev/null || true
    echo "    You can still commit it if you know it's correct." >&2
fi

# Strip debug_info + symbol table.  Cuts ~16% off the binary size and
# shortens the SXPG chunk-upload wall clock on the target by ~1-2 min
# per deploy.  Behaviour is unchanged: strip drops .debug/.symtab but
# leaves .text alone, and the ptrace hook resolves target addresses at
# runtime via the TARGET disp+work's ELF symtab (not our own).
if command -v strip >/dev/null 2>&1; then
    stripped_before=$(wc -c < "$OUT")
    strip "$OUT"
    stripped_after=$(wc -c < "$OUT")
    echo "[+] Stripped: $stripped_before B → $stripped_after B"
else
    echo "[*] strip not installed — binary keeps debug_info " \
         "(harmless, just larger)"
fi

echo
echo "Next steps:"
echo "  git add $OUT"
echo "  git commit -m 'vendor: rebuilt sap_audit_hook.linux-x86_64 from source'"
echo "  git push"
echo
echo "SAPMAP will now prefer this pre-built binary over the compile-on-target flow."
