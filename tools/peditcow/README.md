# pedit-COW — vendored upstream build

This directory builds SAPMAP's vendored copy of
[sgkdev/packet_edit_meme](https://github.com/sgkdev/packet_edit_meme),
the Linux LPE for CVE-2026-46331 (net/sched/act_pedit.c partial copy-on-write).
Vulnerable kernel range 5.18 → 7.1-rc6.

## Files

- `build.sh` — Clones upstream into `src/upstream/`, builds the static
  binary, and injects the bytes into
  `modules/exploitation/_peditcow_blob.py`.

- `src/upstream/` (generated, gitignored) — Fresh clone of the upstream
  PoC repo. Like `tools/godpotato/src/upstream/`, this is per-build-host
  transient — the shipped artefact is the hex blob, not the source.

- `_peditcow_blob.py` (in `modules/exploitation/`, generated) —
  Hex-encoded static binary that ships with SAPMAP. Auto-generated;
  do not hand-edit.

## Building

```bash
# On any Linux x86_64 host with gcc + static libc:
bash tools/peditcow/build.sh

# Or via docker on macOS/Windows/etc:
DOCKER=1 bash tools/peditcow/build.sh
```

This is a one-off step. The resulting blob is checked into the
repository so end users never need a Linux build host.

## Why upstream-unmodified

Unlike `tools/dirtyfrag/` (which carries a vendored fork of `exp.c`
to drop the interactive-PTY shell), the pedit-COW PoC already does
the right thing for SAPMAP's delivery model — it patches `/bin/su`'s
page cache and execve's a single command, no TTY required.

The audit pass identified two cleanup gaps left by upstream:

1. The `tc qdisc add dev lo clsact` rule is not removed on exit —
   leaks across re-runs.
2. The `/tmp/.pedit_calib` scratch file is not removed on early-error
   paths.

Both are handled by the wrapper script that
`sapmap_peditcow.run_as_root` writes around the binary
(`tc qdisc del dev lo clsact 2>/dev/null` and `rm -f /tmp/.pedit_calib`
appended after the exploit returns), so the upstream source stays
unpatched and re-pulls from the public repo cleanly.

The `--ubuntu` flag (AppArmor `aa-exec` bypass) is also intentionally
not passed — it's forensically loud and is only useful on the Ubuntu
distros where the upstream fix has not landed; SAPMAP falls through to
DirtyFrag in that case.

## License & attribution

Upstream PoC released by @sgkdev under the upstream repo's stated
license. This directory only contains the build harness — the actual
source is fetched from GitHub on demand.
