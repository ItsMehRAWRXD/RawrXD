$ErrorActionPreference = 'Continue'
Set-Location -LiteralPath 'G:\~dev\rawrxd\build-fd'
Get-Process -Name 'RawrXD*','mspdbsrv','link' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force -Path 'G:\~dev\rawrxd\build-fd\bin' | Out-Null
Remove-Item -LiteralPath 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.pdb' -Force -ErrorAction SilentlyContinue
$linkExe = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe'
$log = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke\direct_link_r1b.out.log'
$args = @(
  '/nologo',
  '@CMakeFiles\RawrXD-Win32IDE.rsp',
  '/out:bin\RawrXD-Win32IDE.exe',
  '/implib:RawrXD-Win32IDE.lib',
  '/pdb:bin\RawrXD-Win32IDE.pdb',
  '/version:0.0',
  '/machine:x64',
  '/INCREMENTAL:NO',
  '/subsystem:windows',
  '/LARGEADDRESSAWARE:NO',
  '/DEBUG:FULL',
  '/MAP:G:/~dev/rawrxd/build-fd/bin/RawrXD-Win32IDE.map',
  '/MAPINFO:EXPORTS',
  '/MANIFEST:NO',
  '/FORCE:MULTIPLE',
  '/STACK:4194304'
)
Write-Host 'LINK_BEGIN'
& $linkExe @args 2>&1 | Tee-Object -FilePath $log | Select-Object -Last 20
Write-Host "LINK_EXIT=$LASTEXITCODE"
$exeOut = 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe'
if (-not (Test-Path -LiteralPath $exeOut)) {
  Write-Host 'LINK_FAILED_NO_EXE'
  exit 1
}
$len = (Get-Item -LiteralPath $exeOut).Length
if ($len -lt 50MB) {
  Write-Host "LINK_FAILED_TOO_SMALL bytes=$len"
  exit 1
}
Copy-Item -LiteralPath $exeOut -Destination 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' -Force
$sha = (Get-FileHash 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' -Algorithm SHA256).Hash
Write-Host "SMOKE_SHA=$sha"
Get-Item 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' | Format-List FullName,Length,LastWriteTime
