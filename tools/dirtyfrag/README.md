# Dirty Frag — vendored fork

This directory holds SAPMAP's vendored copy of [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag),
the universal Linux LPE published by Hyunwoo Kim (@v4bel) that chains
xfrm-ESP and RxRPC page-cache writes to obtain root on every major
Linux distribution from 2017 onward.

## Files

- `exp.c` — Modified fork of upstream `exp.c`. Two changes (see header
  comment at the top of the file for the full diff narrative):
  1. `shell_elf` patches `/usr/bin/su` to `execve("/tmp/.df_run.sh", NULL, NULL)`
     instead of dropping `/bin/sh`. The wrapper script is written by
     SAPMAP before invocation and captures the operator-supplied
     command's stdout/stderr into `/tmp/.df_result`.
  2. `main()` no longer calls `run_root_pty()` — there's no
     controlling TTY when SAPMAP invokes the binary via SAPXPG. The
     post-patch step just fork+`exec_su_login()`s once and waits.

- `build.sh` — Build the binary and inject it into
  `modules/exploitation/_dirtyfrag_blob.py`. Run on any Linux x86_64
  host, or with `DOCKER=1` to use an alpine container.

- `_dirtyfrag_blob.py` (in `modules/exploitation/`, generated) —
  Hex-encoded static binary that ships with SAPMAP. Auto-generated;
  do not hand-edit.

## Building

```bash
# On any Linux x86_64 host with gcc + static libc:
bash tools/dirtyfrag/build.sh

# Or via docker on macOS/Windows/etc:
DOCKER=1 bash tools/dirtyfrag/build.sh
```

This is a one-off step. The resulting blob is checked into the
repository so end users never need a Linux build host.

## Why a fork

The upstream binary drops into an interactive root pty. SAPMAP invokes
the LPE over SAPXPG, where there is no TTY and no way to interact with
a shell. We need a one-shot "run this command as root, write output to
file" mode — hence the small fork.

## License & attribution

Per the user's confirmation that license has been settled with V4bel.
The header comment in `exp.c` credits @v4bel and links upstream.
