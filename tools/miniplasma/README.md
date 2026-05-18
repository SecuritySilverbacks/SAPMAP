# MiniPlasma — Windows LPE for SAPMAP

Vendored Windows local privilege escalation to NT AUTHORITY\SYSTEM.
The companion to `tools/dirtyfrag/` on the Linux side.

## Vulnerability

- **CVE-2020-17103** — race condition in `cldflt!HsmOsBlockPlaceholderAccess`,
  the Cloud Files Mini-Filter Driver.
- Originally reported to MSRC in 2020 by James Forshaw (Google Project Zero).
- Microsoft issued a patch, but per Nightmare-Eclipse's 2025 reinvestigation
  the patch was either never shipped or silently rolled back.  The original
  PoC still works, unmodified.
- **Affected:** Windows 10 1709+, Server 2019+ — anything with `cldflt.sys`.
- **Effect:** any authenticated user → `NT AUTHORITY\SYSTEM`.

Upstream PoC: https://github.com/Nightmare-Eclipse/MiniPlasma

## SAPMAP modifications

The upstream PoC spawns an interactive `conhost.exe` as SYSTEM, which is
useless for unattended automation.  We forked it under `src/` with these
changes:

1. **No interactive console.** The SYSTEM context reads a wrapper batch
   path from an env var (`SAPMAP_MP_WRAPPER`, default
   `%TEMP%\.mp_run.bat`) and runs that as SYSTEM via `CreateProcessAsUser`.
   The wrapper handles stdout redirection to a result file the SAPMAP
   caller reads back via `certutil -encode`.
2. **Randomized named-pipe name.** The fixed IOC `MiniPlasmaWERPipe` is
   replaced with a per-invocation GUID (or operator-supplied via
   `SAPMAP_MP_PIPE`).
3. **Quiet mode.** `--quiet` / `-q` flag suppresses `Console.WriteLine`
   output (the success/failure signal is the result file, not stderr).
4. **ConfuserEx obfuscation.** Post-build pass to defeat the static
   signatures Defender/EDRs ship for the upstream binary.

## Building

Run on a **Windows host** with .NET Framework 4.7.2+ SDK and MSBuild:

```powershell
cd C:\src\SAPMAP\tools\miniplasma
.\build.ps1
```

The script:
1. Restores NuGet packages (Costura.Fody, NtApiDotNet, TaskScheduler).
2. Builds Release via msbuild — Costura merges deps into `mp_bin.exe`.
3. Downloads ConfuserEx CLI if not present, runs the obfuscation pass
   (`ConfuserEx.crproj` = rename + anti-tamper + anti-debug + constants).
4. Reads the obfuscated `.exe`, hex-encodes it, writes
   `modules/exploitation/_miniplasma_blob.py`.

Result: SAPMAP picks up the blob on next launch.  Commit + push so other
operators get it for free.

### Skipping obfuscation (dev only)

```powershell
.\build.ps1 -SkipObfuscation
```

Faster iteration, but the resulting blob trips Defender on any modern
Win10/11 — **only** for testing the SAPMAP plumbing.

### Required Windows components

- **MSBuild** — get it from Build Tools for Visual Studio 2019/2022
  (free): https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
  → pick the ".NET desktop build tools" workload.
- **NuGet CLI** — `build.ps1` auto-downloads if not on PATH.
- **PowerShell 5+** — ships with Windows.
- **.NET Framework 4.7.2 dev pack** — installed with Build Tools.

## Runtime requirements (target)

- Windows 10 build ≥ 16299 (1709, "Fall Creators Update") OR Server 2019+.
- `cldflt.sys` present (default-on; can be removed by image hardening).
- .NET Framework ≥ 4.7.2 installed (Win10 1803+ stock).
- OS-exec from the SAP service account (typically `<sid>adm`, a local
  Administrators member — MiniPlasma works from any user, no prior
  admin needed, but SAPMAP already needs OS-exec via SAPXPG / CVE-2025-31324
  / created-user to deliver the binary).

## Race condition caveat

Per the upstream README: "success rate may vary since it's a race
condition."  In practice the race resolves on 80–95% of attempts within
a few seconds.  `sapmap_miniplasma.run_as_system` doesn't auto-retry
on first failure (engagement-day caution — repeated runs leave more
artefacts), but the operator can simply re-fire the menu action.

## OPSEC notes

- Default delivery path is `C:\Windows\Temp\mp_bin.exe`.  The exploit
  cleans up after itself (deletes the fake System32\\wermgr.exe + the
  Volatile Environment registry artefacts), but the `mp_bin.exe` and
  result-file artefacts in `%TEMP%` need a manual sweep on engagement
  exit.
- ConfuserEx defeats static-signature detection but does not hide the
  EDR-visible behaviour (registry symlinks, fake wermgr, WER scheduled
  task firing).  Behaviour-based EDRs will detect the chain even with
  perfect obfuscation.  Engagement-day-only.
- The vendored binary is **not** committed unobfuscated — only the
  ConfuserEx-processed `.exe` goes into `_miniplasma_blob.py`.

## License

The modified PoC under `src/` retains upstream MiniPlasma's license
(MIT-style, see the upstream repo).  The SAPMAP-side Python and build
scripts ship under SAPMAP's licence.
