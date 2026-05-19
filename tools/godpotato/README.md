# GodPotato - Windows LPE for SAPMAP

Vendored Windows local privilege escalation to NT AUTHORITY\SYSTEM
via SeImpersonate.  The companion to `tools/miniplasma/` for the OS
builds where MiniPlasma's cldflt.sys race can't fire (Server 2016,
Win10 pre-1709).

## What it is

- Upstream: https://github.com/BeichenDream/GodPotato (Apache 2.0)
- Mechanism: DCOM unmarshalling tricks (OXID resolver + IStream)
  coerce RPCSS (running as SYSTEM) into outbound NTLM auth to a
  local listener controlled by the exploit; the user's
  `SeImpersonatePrivilege` then lets the exploit impersonate the
  SYSTEM token and `CreateProcessWithTokenW` the operator's command.
- Affected: **Windows Server 2012 - 2022, Windows 10 - 11**.  No
  known patch - Microsoft can't fix this without breaking DCOM
  unmarshalling generally.
- Prerequisite: the calling user (the SAP service account that
  SAPXPG or the JSP shell runs as) must hold
  `SeImpersonatePrivilege`.  SAP defaults grant it to `<sid>adm`
  and `SAPService<SID>`.

## SAPMAP modifications vs upstream

Minimal — the upstream PoC's command-line API (`-cmd "<command>"`)
already matches what we need.  Two build-time tweaks only:

1. **Output type changed from Library to Exe.**  Upstream ships
   as a DLL meant to be loaded via `InstallUtil.exe` (an EDR-bait
   sequence).  We want a standalone .exe we can drop and run
   directly via the JSP shell or SAPXPG.
2. **TargetFramework bumped to net40** so it's safely compatible
   with every Server 2012+ install without depending on .NET 2.0
   being explicitly enabled (which Server 2016+ doesn't ship
   enabled by default in some configurations).

The actual exploitation logic, GodPotato classes, SharpToken
helpers, and NativeAPI bindings are vendored UNMODIFIED from
upstream.  See `tools/godpotato/src/` for the files; diff against
the upstream repo to confirm equivalence.

## Building

Run on a **Windows host** with .NET Framework 4.x SDK + MSBuild
(free from Build Tools for Visual Studio 2022 with the ".NET
desktop build tools" workload):

```powershell
cd C:\path\to\SAPMAP\tools\godpotato
.\build.ps1
```

The script:
1. Restores NuGet packages (none expected — pure BCL refs).
2. Builds Release via msbuild — produces a single self-contained
   `gp_bin.exe` (~100 KB; no Costura merge needed because there
   are no dependency DLLs to embed).
3. Auto-downloads ConfuserEx CLI if not present, runs the same
   obfuscation pass as MiniPlasma (rename + anti-debug +
   constants encryption; anti-tamper deliberately dropped due
   to PE-loader regression).
4. Hex-encodes the obfuscated `.exe` into
   `modules/exploitation/_godpotato_blob.py` with SHA-256 + size
   metadata.

### Skipping obfuscation (dev only)

```powershell
.\build.ps1 -SkipObfuscation
```

Faster iteration but trips Defender on any modern Win10/11.
Use only for testing the SAPMAP plumbing.

## Runtime requirements (target)

- Windows Server 2012 (build 9200) or later, OR Win8 / Win10 / Win11.
- The user that runs `gp_bin.exe` holds `SeImpersonatePrivilege`
  in its token.  Check with `whoami /priv` — every SAP install
  grants this to `<sid>adm` / `SAPService<SID>` at install time.
- .NET Framework 4.0 or later installed (default on every
  supported Windows build).
- OS-exec foothold for SAPMAP to deliver the binary (SAPXPG,
  CVE-2025-31324 JSP shell, or a SAPMAP-created OS user).

## OPSEC notes

- Default delivery path is `C:\Windows\Temp\gp_bin.exe`.  After
  successful escalation the binary + temp artefacts are removed
  by the SAPMAP cleanup phase.  Engagement-day cleanup should
  still sweep `%TEMP%\.gp_*` paths on exit.
- ConfuserEx defeats static-signature detection but not
  behaviour-based EDR (RPCSS coercion + NTLM relay over named
  pipe leave forensic traces).  Engagement-day-only.
- The vendored binary is **not** committed unobfuscated — only
  the ConfuserEx-processed `.exe` lands in `_godpotato_blob.py`.

## License

The vendored GodPotato sources under `src/` retain upstream's
Apache 2.0 license.  See `LICENSE` for the upstream copy.  The
SAPMAP-side Python and build scripts ship under SAPMAP's licence.
