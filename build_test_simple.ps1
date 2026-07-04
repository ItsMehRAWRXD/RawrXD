$Script:ErrorActionPreference = 'Stop'

$Script:vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$Script:vsInstallDir = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null | Select-Object -First 1

$Script:MasmExe = Get-ChildItem "$vsInstallDir\VC\Tools\MSVC\*\bin\Hostx64\x64\ml64.exe" | Select-Object -First 1 -ExpandProperty FullName
$Script:LinkExe = Get-ChildItem "$vsInstallDir\VC\Tools\MSVC\*\bin\Hostx64\x64\link.exe" | Select-Object -First 1 -ExpandProperty FullName

$Script:masmDir = Split-Path $MasmExe -Parent
$Script:msvcRoot = (Resolve-Path (Join-Path $masmDir "..\..\..")).Path
$Script:msvcLibX64 = Join-Path $msvcRoot "lib\x64"

$Script:sdkRoot = "C:\Program Files (x86)\Windows Kits\10\Lib"
$Script:versions = Get-ChildItem $sdkRoot -Directory | Where-Object { $_.Name -match '^\d+\.' } | Sort-Object Name -Descending
$Script:sdkUmX64 = Join-Path $versions[0].FullName "um\x64"
$Script:sdkUcrtX64 = Join-Path $versions[0].FullName "ucrt\x64"

Write-Host "Building simple test..."
& $MasmExe /c /nologo test_simple_batch.asm
& $LinkExe /NOLOGO /SUBSYSTEM:CONSOLE /ENTRY:main test_simple_batch.obj RawrXD_PE_Writer.obj kernel32.lib /LIBPATH:"$msvcLibX64" /LIBPATH:"$sdkUcrtX64" /LIBPATH:"$sdkUmX64"

if (Test-Path test_simple_batch.exe) {
    Write-Host "Running test..."
    & .\test_simple_batch.exe
}
