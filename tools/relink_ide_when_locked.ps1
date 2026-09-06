# Link RawrXD-Win32IDE to bin\RawrXD-Win32IDE.new.exe when the running IDE locks bin\RawrXD-Win32IDE.exe.
# Usage: powershell -File tools\relink_ide_when_locked.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path "$root\build-ninja\CMakeFiles\RawrXD-Win32IDE.rsp")) {
    $root = 'F:\~dev\rawrxd'
}
$build = Join-Path $root 'build-ninja'
$link = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe'
if (-not (Test-Path $link)) {
    throw "link.exe not found at $link"
}
Push-Location $build
try {
    $out = 'bin\RawrXD-Win32IDE.new.exe'
    $pdb = 'bin\RawrXD-Win32IDE.new.pdb'
    Write-Host "Linking to $out (main exe may stay locked)..."
    & $link /nologo '@CMakeFiles\RawrXD-Win32IDE.rsp' "/out:$out" "/pdb:$pdb" `
        /machine:x64 /INCREMENTAL:NO /subsystem:windows /LTCG /LARGEADDRESSAWARE:NO `
        /DEBUG:FULL /MANIFEST:NO /FORCE:MULTIPLE /STACK:4194304
    if ($LASTEXITCODE -ne 0) { throw "link failed with exit $LASTEXITCODE" }
    $hash = (Get-FileHash $out -Algorithm SHA256).Hash
    Write-Host "OK: $out"
    Write-Host "SHA256: $hash"
    Write-Host "Launch: $build\$out"
    Write-Host "After closing the old IDE, replace bin\RawrXD-Win32IDE.exe manually or rerun ninja."
}
finally {
    Pop-Location
}
