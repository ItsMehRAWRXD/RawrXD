#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [string]$AsmFile = "D:\linker_ir_harness.asm",
    [string]$ObjFile = "linker_ir_harness_crash.obj",
    [string]$CoffObjFile = "coff_linker.obj",
    [string]$ArenaObjFile = "arena_alloc.obj",
    [string]$LinkerIrObjFile = "linker_ir.obj",
    [string]$ExeFile = "linker_ir_harness_crash.exe",
    [string]$VsRoot = "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC",
    [string]$SdkRoot = "C:\Program Files (x86)\Windows Kits\10\Lib",
    [string[]]$IncludeDirs = @("D:\", "D:\rawrxd", $PWD.Path)
)

$ErrorActionPreference = 'Stop'

function Resolve-LatestToolchain {
    param([Parameter(Mandatory)] [string]$Root)

    if (-not (Test-Path -LiteralPath $Root)) {
        throw "MSVC root not found: $Root"
    }

    $latest = Get-ChildItem -LiteralPath $Root -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No MSVC toolchain versions found under $Root"
    }

    $binPath = Join-Path $latest.FullName 'bin\Hostx64\x64'
    $ml64 = Join-Path $binPath 'ml64.exe'
    $link = Join-Path $binPath 'link.exe'

    if (-not (Test-Path -LiteralPath $ml64)) {
        throw "ml64.exe not found at $ml64"
    }
    if (-not (Test-Path -LiteralPath $link)) {
        throw "link.exe not found at $link"
    }

    [pscustomobject]@{
        Version = $latest.Name
        Ml64 = $ml64
        Link = $link
    }
}

    function Resolve-LatestWindowsKitLibDir {
        $kitRoot = 'C:\Program Files (x86)\Windows Kits\10\Lib'
        if (-not (Test-Path -LiteralPath $kitRoot)) {
            return $null
        }

        $latestVersion = Get-ChildItem -LiteralPath $kitRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $latestVersion) {
            return $null
        }

        $x64LibDir = Join-Path $latestVersion.FullName 'um\x64'
        if (Test-Path -LiteralPath $x64LibDir) {
            return $x64LibDir
        }

        return $null
    }

function Resolve-LatestSdkLibPath {
    param([Parameter(Mandatory)] [string]$Root)

    if (-not (Test-Path -LiteralPath $Root)) {
        throw "Windows SDK lib root not found: $Root"
    }

    $latest = Get-ChildItem -LiteralPath $Root -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latest) {
        throw "No Windows SDK versions found under $Root"
    }

    $umX64 = Join-Path $latest.FullName 'um\x64'
    $kernel32 = Join-Path $umX64 'kernel32.lib'

    if (-not (Test-Path -LiteralPath $kernel32)) {
        throw "kernel32.lib not found at $kernel32"
    }

    [pscustomobject]@{
        Version = $latest.Name
        LibPath = $umX64
        Kernel32 = $kernel32
    }
}

$asmPath = if ([System.IO.Path]::IsPathRooted($AsmFile)) { $AsmFile } else { Join-Path $PWD $AsmFile }
$objPath = if ([System.IO.Path]::IsPathRooted($ObjFile)) { $ObjFile } else { Join-Path $PWD $ObjFile }
$coffObjPath = if ([System.IO.Path]::IsPathRooted($CoffObjFile)) { $CoffObjFile } else { Join-Path $PWD $CoffObjFile }
$arenaObjPath = if ([System.IO.Path]::IsPathRooted($ArenaObjFile)) { $ArenaObjFile } else { Join-Path $PWD $ArenaObjFile }
$linkerIrObjPath = if ([System.IO.Path]::IsPathRooted($LinkerIrObjFile)) { $LinkerIrObjFile } else { Join-Path $PWD $LinkerIrObjFile }
$exePath = if ([System.IO.Path]::IsPathRooted($ExeFile)) { $ExeFile } else { Join-Path $PWD $ExeFile }

$coffAsmPath = "D:\coff_linker.asm"
$arenaAsmPath = "D:\arena_alloc.asm"
$linkerIrAsmPath = "D:\linker_ir.asm"

if (-not (Test-Path -LiteralPath $asmPath)) {
    throw "ASM source not found: $asmPath"
}
if (-not (Test-Path -LiteralPath $coffAsmPath)) {
    throw "Required source not found: $coffAsmPath"
}
if (-not (Test-Path -LiteralPath $arenaAsmPath)) {
    throw "Required source not found: $arenaAsmPath"
}
if (-not (Test-Path -LiteralPath $linkerIrAsmPath)) {
    throw "Required source not found: $linkerIrAsmPath"
}

$toolchain = Resolve-LatestToolchain -Root $VsRoot
$sdk = Resolve-LatestSdkLibPath -Root $SdkRoot
$windowsKitLibDir = Resolve-LatestWindowsKitLibDir
Write-Host "Using Toolchain: $($toolchain.Version)" -ForegroundColor Cyan
Write-Host "ml64: $($toolchain.Ml64)"
Write-Host "link: $($toolchain.Link)"
if ($windowsKitLibDir) {
    Write-Host "Windows SDK lib: $windowsKitLibDir"
} else {
    Write-Host "Windows SDK lib not found automatically." -ForegroundColor Yellow
}
Write-Host "SDK: $($sdk.Version)"
Write-Host "libpath: $($sdk.LibPath)"
 $includeArgs = @()
 foreach ($dir in $IncludeDirs) {
     if ($dir -and (Test-Path -LiteralPath $dir)) {
         $includeArgs += '/I'
         $includeArgs += $dir
     }
 }
 if (-not $includeArgs) {
     throw "No valid include directories found."
 }
Write-Host "Assembling $asmPath..." -ForegroundColor Yellow
& $toolchain.Ml64 /c /Zi @includeArgs /Fo"$objPath" "$asmPath"
if ($LASTEXITCODE -ne 0) {
    throw "Assembly failed with exit code $LASTEXITCODE"
}

Write-Host "Assembling $coffAsmPath..." -ForegroundColor Yellow
& $toolchain.Ml64 /c /Zi @includeArgs /Fo"$coffObjPath" "$coffAsmPath"
if ($LASTEXITCODE -ne 0) {
    throw "Assembly failed for $coffAsmPath with exit code $LASTEXITCODE"
}

Write-Host "Assembling $arenaAsmPath..." -ForegroundColor Yellow
& $toolchain.Ml64 /c /Zi @includeArgs /Fo"$arenaObjPath" "$arenaAsmPath"
if ($LASTEXITCODE -ne 0) {
    throw "Assembly failed for $arenaAsmPath with exit code $LASTEXITCODE"
}

Write-Host "Assembling $linkerIrAsmPath..." -ForegroundColor Yellow
& $toolchain.Ml64 /c /Zi @includeArgs /Fo"$linkerIrObjPath" "$linkerIrAsmPath"
if ($LASTEXITCODE -ne 0) {
    throw "Assembly failed for $linkerIrAsmPath with exit code $LASTEXITCODE"
}

Write-Host "Linking $exePath..." -ForegroundColor Yellow
if ($windowsKitLibDir) {
    & $toolchain.Link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /MACHINE:X64 /LIBPATH:"$windowsKitLibDir" /OUT:"$exePath" "$objPath" "$coffObjPath" "$arenaObjPath" "$linkerIrObjPath" "$($sdk.Kernel32)"
} else {
    & $toolchain.Link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /MACHINE:X64 /OUT:"$exePath" "$objPath" "$coffObjPath" "$arenaObjPath" "$linkerIrObjPath" "$($sdk.Kernel32)"
}
if ($LASTEXITCODE -ne 0) {
    throw "Linking failed with exit code $LASTEXITCODE"
}

Write-Host "Build Complete: $exePath" -ForegroundColor Green
