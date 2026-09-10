# Relink with VS env so comctl32.lib resolves; assumes HeadlessIDE.obj already built
$ErrorActionPreference = 'Continue'
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$log = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\relink_vsenv.log'
$bat = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\relink_vsenv.bat'
$lines = @(
  '@echo off',
  "call `"$vs`"",
  'cd /d G:\~dev\rawrxd\build-fd',
  'if exist bin\RawrXD-Win32IDE.pdb del /f /q bin\RawrXD-Win32IDE.pdb',
  'link.exe /nologo @CMakeFiles\RawrXD-Win32IDE.rsp /out:bin\RawrXD-Win32IDE.exe /implib:RawrXD-Win32IDE.lib /pdb:bin\RawrXD-Win32IDE.pdb /machine:x64 /INCREMENTAL:NO /subsystem:windows /LARGEADDRESSAWARE:NO /DEBUG:FULL /MANIFEST:NO /FORCE:MULTIPLE /STACK:4194304',
  'echo LINK_EXIT=%ERRORLEVEL%'
)
[IO.File]::WriteAllLines($bat, $lines)
cmd /c $bat 2>&1 | Tee-Object -FilePath $log | Select-Object -Last 30
$exe = 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe'
if (-not (Test-Path -LiteralPath $exe)) { exit 1 }
$dest = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_bin\RawrXD-Win32IDE_r1cap.exe'
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Copy-Item -LiteralPath $exe -Destination $dest -Force
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $dest | Out-Null
$sha = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash
Write-Host "R1CAP_SHA256=$sha"
exit 0
