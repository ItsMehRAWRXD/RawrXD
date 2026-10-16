param([string]$Root='F:\rawrxd', [string]$Build='F:\rawrxd\build_cmake')
$ErrorActionPreference='Stop'
$symbols=@('AssertHardThreadAffinity','RestrictOsBackgroundTasks','Deep2Device_ScoreAdapter','Deep2Device_PickBestIndex','TraceComplete','TraceBegin','TraceSetDestination')
$rg=Get-Command rg -ErrorAction SilentlyContinue
if (-not $rg) { throw 'ripgrep (rg) is required for this diagnostic; no source changes were made.' }
Write-Host '=== SOURCE DECLARATIONS / DEFINITIONS ==='
foreach ($symbol in $symbols) {
  Write-Host "`n--- $symbol ---"
  & $rg.Source -n --glob '*.{h,hpp,c,cc,cpp,cxx}' --fixed-strings $symbol (Join-Path $Root 'src') (Join-Path $Root 'include') 2>&1
}
Write-Host "`n=== CURRENT BINARIES ==="
Get-ChildItem $Build -Recurse -Filter rawr.exe -File -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime
Write-Host "`n=== COMMAND RESOLUTION ==="
Get-Command rawr.exe -All -ErrorAction SilentlyContinue | Select-Object CommandType,Source,Definition
Write-Host "`n=== LINK COMMANDS ==="
Get-ChildItem $Build -Recurse -Filter '*.tlog' -Directory -ErrorAction SilentlyContinue |
  Where-Object Name -like '*link*' | Select-Object -First 15 FullName
Write-Host 'Inspect actual linker /VERBOSE:LIB output to distinguish missing object files from signature mismatches.'
