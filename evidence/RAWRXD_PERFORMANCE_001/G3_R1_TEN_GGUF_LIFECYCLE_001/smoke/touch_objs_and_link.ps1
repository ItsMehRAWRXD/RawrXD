$ErrorActionPreference = 'Continue'
$n = Get-Date
$c = 0
Get-ChildItem -LiteralPath 'G:\~dev\rawrxd\build-fd\CMakeFiles\RawrXD-Win32IDE.dir' -Recurse -Filter '*.obj' -ErrorAction SilentlyContinue |
  ForEach-Object { $_.LastWriteTime = $n; $script:c++ }
Write-Host "touched=$c"
Set-Location -LiteralPath 'G:\~dev\rawrxd\build-fd'
& ninja -t restat 2>&1 | Out-Host
$linkLog = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_001\smoke\direct_link_r1.out.log'
$linkExe = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\link.exe'
$outDir = 'G:\~dev\rawrxd\build-fd\bin'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
# Surgical link: LAA:NO matches sealed R01 / matrix smoke
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
Write-Host "LINK_BEGIN"
& $linkExe @args 2>&1 | Tee-Object -FilePath $linkLog | Select-Object -Last 30
Write-Host "LINK_EXIT=$LASTEXITCODE"
if (Test-Path -LiteralPath 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe') {
  Copy-Item -LiteralPath 'G:\~dev\rawrxd\build-fd\bin\RawrXD-Win32IDE.exe' -Destination 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' -Force
  $sha = (Get-FileHash 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' -Algorithm SHA256).Hash
  Write-Host "SMOKE_SHA=$sha"
  Get-Item 'G:\~dev\rawrxd\smoke_bin\RawrXD-Win32IDE_r1matrix.exe' | Format-List FullName,Length,LastWriteTime
} else {
  Write-Host 'LINK_FAILED_NO_EXE'
  exit 1
}
