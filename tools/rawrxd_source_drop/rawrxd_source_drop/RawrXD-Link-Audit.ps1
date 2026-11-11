# Read-only symbol inventory. Requires dumpbin in the MSVC developer environment.
[CmdletBinding()]
param([string]$Root='F:\rawrxd',[string]$Out='')
$ErrorActionPreference='Stop'
if (-not $Out) {$Out=Join-Path $Root 'evidence\link-symbol-audit.txt'}
New-Item -ItemType Directory -Force -Path (Split-Path $Out) | Out-Null
$symbols=@('AssertHardThreadAffinity','RestrictOsBackgroundTasks','Deep2Device_ScoreAdapter','Deep2Device_PickBestIndex','TraceComplete','TraceBegin','TraceSetDestination')
$dump=Get-Command dumpbin.exe -ErrorAction Stop
$files=Get-ChildItem (Join-Path $Root 'build_cmake') -Recurse -File -Include '*.obj','*.lib' -ErrorAction Stop
"AUDIT_ROOT=$Root`nARTIFACTS=$($files.Count)" | Set-Content $Out
foreach ($f in $files) {
 $lines=& $dump.Source /symbols $f.FullName 2>$null
 foreach($s in $symbols) {
  $hits=@($lines | Select-String -SimpleMatch $s)
  foreach($h in $hits) {
   $classification=if($h.Line -match '\bUNDEF\b'){'REFERENCE'}else{'DEFINITION_CANDIDATE'}
   "[$classification] $s | $($f.FullName) | $($h.Line.Trim())" | Add-Content $Out
  }
 }
}
Write-Host "Audit written: $Out"
Write-Host 'Compare full decorated names, namespace, calling convention, and linked libraries.'
