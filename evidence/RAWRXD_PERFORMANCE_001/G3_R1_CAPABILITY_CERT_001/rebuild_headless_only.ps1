Set-Location -LiteralPath 'G:\~dev\rawrxd\build-fd'
$cmds = & ninja -t commands RawrXD-Win32IDE 2>$null
$hit = $cmds | Where-Object { $_ -match 'HeadlessIDE\.cpp' -and $_ -match 'cl\.exe' } | Select-Object -First 1
if (-not $hit) { Write-Host 'NO_COMPILE_CMD'; exit 1 }
Write-Host 'COMPILE_BEGIN'
cmd /c $hit
Write-Host "COMPILE_EXIT=$LASTEXITCODE"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Link using existing rsp (LAA:NO at link; editbin later for cert)
Get-Process -Name 'mspdbsrv','link' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
Remove-Item -LiteralPath 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.pdb' -Force -EA SilentlyContinue
$linkExe = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe'
$args = @(
  '/nologo',
  '@CMakeFiles\RawrXD-Win32IDE.rsp',
  '/out:bin\RawrXD-Win32IDE.exe',
  '/implib:RawrXD-Win32IDE.lib',
  '/pdb:bin\RawrXD-Win32IDE.pdb',
  '/machine:x64',
  '/INCREMENTAL:NO',
  '/subsystem:windows',
  '/LARGEADDRESSAWARE:NO',
  '/DEBUG:FULL',
  '/MANIFEST:NO',
  '/FORCE:MULTIPLE',
  '/STACK:4194304'
)
Write-Host 'LINK_BEGIN'
& $linkExe @args 2>&1 | Select-Object -Last 25
Write-Host "LINK_EXIT=$LASTEXITCODE"
$exe = 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe'
if (-not (Test-Path -LiteralPath $exe)) { exit 1 }
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
Write-Host "EXE_SHA256=$sha"
$dest = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_CAPABILITY_CERT_001\smoke_bin\RawrXD-Win32IDE_r1cap.exe'
New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
Copy-Item -LiteralPath $exe -Destination $dest -Force
$editbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\editbin.exe'
& $editbin /LARGEADDRESSAWARE $dest | Out-Null
Write-Host "COPIED_LAA=$dest"
exit 0
