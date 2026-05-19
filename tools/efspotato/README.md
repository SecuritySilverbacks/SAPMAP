# EfsPotato - Windows LPE for SAPMAP

Vendored Windows local privilege escalation to NT AUTHORITY\SYSTEM
via MS-EFSRPC coercion of lsass.exe.  The companion to
`tools/godpotato/` for the service-account contexts where GodPotato's
DCOM-unmarshal approach can't promote impersonation level (notably
NETWORK SERVICE on Server 2016).

## What it is

- Upstream: https://github.com/zcgonvh/EfsPotato (no explicit
  licence; "GMH's fuck Tools" research suite, public domain de-facto)
- Mechanism: Calls MS-EFSR `EfsRpcEncryptFileSrv` (and method
  variants) against lsass.exe via a UNC-style filename like
  `\\.\pipe\<guid>\pipe\srvsvc` that points at our own named-pipe
  listener.  lsass calls back, authenticates as SYSTEM, and the
  exploit relays that auth through `ImpersonateNamedPipeClient`.
  Combined with the calling user's `SeImpersonatePrivilege` this
  yields a SYSTEM token in Impersonation level - good for
  `CreateProcessAsUser`.
- CVE history: CVE-2021-36942 patched the original EfsRpcOpenFileRaw
  method; EfsPotato is the patch bypass using EfsRpcEncryptFileSrv +
  alternative pipes (lsarpc / efsrpc / samr / lsass / netlogon).
  Microsoft has acknowledged but not fully patched.
- Affected: Server 2012 - 2022, Win8 - Win11.  All builds in scope.
- Prerequisite: SeImpersonatePrivilege held by the calling user.
  Default-granted to SAP service accounts AND to NETWORK SERVICE /
  LOCAL SERVICE / IIS APPPOOL\\* contexts, so this works in scenarios
  where GodPotato gets stuck (e.g. JSP shell on a SAP Java app pool
  running as NETWORK SERVICE).

## Build

Run on a **Windows host** with .NET Framework 4.7.2+ SDK and MSBuild
(free from Build Tools for Visual Studio 2022 with the ".NET
desktop build tools" workload):

```powershell
cd C:\path\to\SAPMAP\tools\efspotato
.\build.ps1
```

The script:
1. Clones `zcgonvh/EfsPotato` from GitHub (single .cs file, no csproj
   upstream).
2. Generates a synthetic csproj wrapper that compiles
   `EfsPotato.cs` as a standalone Exe (net4.7.2, AssemblyName
   `efs_bin`).
3. Builds via msbuild.
4. Auto-downloads ConfuserEx CLI if not present, runs the same
   protection set as MiniPlasma/GodPotato (rename + anti-debug +
   constants; anti-tamper deliberately omitted).
5. Hex-encodes the obfuscated .exe into
   `modules/exploitation/_efspotato_blob.py`.

### Skipping obfuscation (dev only)

```powershell
.\build.ps1 -SkipObfuscation
```

## Runtime requirements (target)

- Server 2012 build 9200 or later, OR Win8 / Win10 / Win11.
- `SeImpersonatePrivilege` held by the calling user.
- .NET Framework 4.7.2+ installed.
- OS-exec foothold for SAPMAP to deliver the binary.

## Pipe fallback (multi-pipe at runtime)

EfsPotato accepts an optional `[pipe]` argument: `lsarpc` (default),
`efsrpc`, `samr`, `lsass`, `netlogon`.  Hardened images sometimes
disable one or two of these but rarely all of them.  SAPMAP's
`run_as_system` iterates through them in order until one produces
a result file - the operator doesn't have to guess which is open.

## OPSEC notes

- Default delivery path is `C:\Windows\Temp\efs_bin.exe`.  After
  successful escalation the binary + temp artefacts are removed
  by the SAPMAP cleanup phase.
- The MS-EFSRPC coercion leaves a transient log entry on the target
  (lsass.exe outbound named-pipe authentication).  Behaviour-based
  EDR may flag this.  ConfuserEx defeats static signatures only.
- The vendored binary is **not** committed unobfuscated - only the
  ConfuserEx-processed `.exe` lands in `_efspotato_blob.py`.

## License

The vendored EfsPotato source under `src/upstream/` retains
upstream's de-facto-public-domain status.  The SAPMAP-side Python
and build scripts ship under SAPMAP's licence.
