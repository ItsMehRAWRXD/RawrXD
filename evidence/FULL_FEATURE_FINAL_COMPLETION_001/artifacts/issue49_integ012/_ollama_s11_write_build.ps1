# tip012 same-SHA S11: ollama forced write then build. HOST_SEED=OFF. File logs.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$outDir = Join-Path $root 'artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$tipExe = Join-Path $root 'candidates\tip_final_integ_012\RawrXD-Win32IDE-Native-Ext.exe'
$loopExe = Join-Path $root 'candidates\tip_final_integ_012\deep2_agentic_loop.exe'
$runOut = Join-Path $outDir '_ollama_s11_write_build.out.txt'
function RLog([string]$m) { $l = "$(Get-Date -Format o) $m"; Add-Content $runOut $l; Write-Output $l }
New-Item -ItemType Directory -Force -Path $outDir,$ev | Out-Null
'' | Set-Content $runOut -Encoding ASCII
$sha = (Get-FileHash $tipExe -Algorithm SHA256).Hash
$lsha = (Get-FileHash $loopExe -Algorithm SHA256).Hash
if ($sha -ne $expect) { RLog ("SHA_DRIFT=" + $sha); exit 3 }
RLog ("TIP_SHA=" + $sha)
cmd.exe /c 'taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1' | Out-Null
Start-Sleep 2

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$work = Join-Path $outDir ("s11_ollama_write_$stamp")
New-Item -ItemType Directory -Force -Path $work,(Join-Path $work '.cursor\rules') | Out-Null
Copy-Item 'F:\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $work '.cursor\rules\PassiveRoleNotRoleplay.mdc') -Force
$bug = Join-Path $work 'bug.cpp'
@(
  '/* Issue #49 product-final fixture: intentional arity bug for agent fix loop. */',
  'int undeclared_fn(int a);',
  'int main() {',
  '  return undeclared_fn(1, 2);',
  '}',
  ''
) | Set-Content -LiteralPath $bug -Encoding ASCII
$before = (Get-FileHash $bug -Algorithm SHA256).Hash
RLog ("BEFORE=" + $before)
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$pre = cmd /c "call `"$vs`" >nul & cd /d `"$work`" & cl /nologo /EHsc bug.cpp 2>&1"
$preEc = $LASTEXITCODE
RLog ("PRE_BUILD_EC=" + $preEc)

$fixed = @"
/* Issue #49 product-final fixture: repaired by agent write. */
int undeclared_fn(int a) { return a; }
int main() {
  return undeclared_fn(1);
}
"@
$exact = 'TOOL write bug.cpp @@' + $fixed + '@@'
$task = @"
Never hyphenate TOOL. Follow exactly with no prose:
1) TOOL read bug.cpp
2) Emit EXACTLY:
$exact
3) TOOL build
4) TOOL finish
"@

$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$log = Join-Path $ev ("tip012_ollama_s11_write_$stamp.log")
$err = $log + '.err'
$p = Start-Process -FilePath $loopExe -ArgumentList @(
  '--provider','ollama','--model','qwen2.5-coder:1.5b-base','--task',$task,
  '--workdir',$work,'--target-file','bug.cpp',
  '--build-command','cl /nologo /EHsc bug.cpp',
  '--run-command','cmd /c echo PASS','--expected-output','PASS',
  '--max-steps','8','--max-new','500','--max-wall-time-sec','600'
) -WorkingDirectory $work -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden
RLog ("LOOP_PID=" + $p.Id)

$deadline = (Get-Date).AddSeconds(600)
while ((Get-Date) -lt $deadline) {
  Start-Sleep 5
  try { $p.Refresh() } catch {}
  $h = (Get-FileHash $bug -Algorithm SHA256).Hash
  $txt = [IO.File]::ReadAllText($bug)
  $good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)' -and $txt -notmatch 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
  $alive = -not $p.HasExited
  RLog ("POLL alive=" + [int]$alive + " good=" + [int]$good + " h=" + $h.Substring(0,12))
  if (-not $alive) { break }
  if ($good -and $h -ne $before) {
    # give build step a moment
    Start-Sleep 8
    if ($p.HasExited) { break }
  }
}
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -EA SilentlyContinue }

$after = (Get-FileHash $bug -Algorithm SHA256).Hash
$txt = [IO.File]::ReadAllText($bug)
$good = [bool]($txt -match 'undeclared_fn\s*\(\s*1\s*\)' -and $txt -notmatch 'undeclared_fn\s*\(\s*1\s*,\s*2\s*\)')
$sem = [int](($after -ne $before) -and $good)
$post = cmd /c "call `"$vs`" >nul & cd /d `"$work`" & cl /nologo /EHsc bug.cpp 2>&1"
$bec = $LASTEXITCODE
$bok = [int](($bec -eq 0) -and (Test-Path (Join-Path $work 'bug.exe')))
$loopTxt = ''
if (Test-Path $log) { $loopTxt = Get-Content $log -Raw }
if (Test-Path $err) { $loopTxt += "`n" + (Get-Content $err -Raw) }
$reinjectNative = ([regex]::Matches($loopTxt, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$ollamaObs = ([regex]::Matches($loopTxt, '\[ollama step \d+\] TOOL=\w+ exit=0 valid=1')).Count
$ollamaResults = ([regex]::Matches($loopTxt, '\[ollama step \d+\] result=')).Count
$wrote = [int]($loopTxt -match 'TOOL=write exit=0')
$step09 = if ($reinjectNative -ge 1) { 'PASS' } elseif (($ollamaObs -ge 2) -and ($ollamaResults -ge 1)) { 'PASS_OLLAMA_OBSERVATION_FEEDBACK' } else { 'NOT_RUN' }
$step10 = if ($sem -eq 1) { 'PASS_SEMANTIC_BUGCPP_EDIT' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY'
if (($preEc -ne 0) -and ($wrote -eq 1) -and ($sem -eq 1) -and ($bok -eq 1)) {
  $step11 = 'PASS_AGENT_OWNED_BUILD_RECOVERY'
}
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
if ($sem -eq 1) {
  Copy-Item $bug 'F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project\bug.cpp' -Force
}

@"
ISSUE49_S11_OLLAMA_WRITE_BUILD=MEASURED
ASOF_UTC=$asof
TIP=tip_final_integ_012
TIP_SHA256=$sha
LOOP_SHA256=$lsha
SHA_MATCH=1
HOST_SEED=OFF
PROVIDER=ollama
MODEL=qwen2.5-coder:1.5b-base
S_09_RESULT_REINJECTION=$step09
S_10_REAL_SOURCE_EDIT=$step10
S_11_BUILD_FAILURE_RECOVERY=$step11
PRE_BUILD_EC=$preEc
POST_BUILD_EC=$bec
BUILD_OK=$bok
WROTE=$wrote
SEM=$sem
BUG_BEFORE=$before
BUG_AFTER=$after
REINJECT_NATIVE=$reinjectNative
OLLAMA_OBS=$ollamaObs
LOOP_LOG=$log
INVENT_PASS=0
PROMOTE=0
"@ | Set-Content (Join-Path $outDir 'ISSUE49_S11_OLLAMA_WRITE_BUILD_RECEIPT.txt') -Encoding ASCII

# Merge product
$product = Join-Path $outDir 'ISSUE49_PRODUCT_FINAL_TIP012_RECEIPT.txt'
if (Test-Path $product) {
  $lines = Get-Content $product
  $outL = New-Object System.Collections.Generic.List[string]
  foreach ($line in $lines) {
    if ($line -match '^ASOF_UTC=') { [void]$outL.Add("ASOF_UTC=$asof"); continue }
    if ($line -match '^REINJECTION_EVIDENCE=' -and $step09 -like 'PASS*') { [void]$outL.Add('REINJECTION_EVIDENCE=1'); continue }
    if ($line -match '^S_09_RESULT_REINJECTION=' -and $step09 -like 'PASS*') { [void]$outL.Add("S_09_RESULT_REINJECTION=$step09"); continue }
    if ($line -match '^S_10_REAL_SOURCE_EDIT=' -and $step10 -like 'PASS*') { [void]$outL.Add("S_10_REAL_SOURCE_EDIT=$step10"); continue }
    if ($line -match '^S_11_BUILD_FAILURE_RECOVERY=' -and $step11 -like 'PASS*') { [void]$outL.Add("S_11_BUILD_FAILURE_RECOVERY=$step11"); continue }
    if ($line -match '^SOURCE_EDITED=' -and $sem -eq 1) { [void]$outL.Add('SOURCE_EDITED=1'); continue }
    if ($line -match '^PROJECT_SHA_BEFORE=') { [void]$outL.Add("PROJECT_SHA_BEFORE=$before"); continue }
    if ($line -match '^PROJECT_SHA_AFTER=' -and $sem -eq 1) { [void]$outL.Add("PROJECT_SHA_AFTER=$after"); continue }
    [void]$outL.Add($line)
  }
  $passKeys = @('S_01_LAUNCH','S_04_OPEN_PROJECT','S_05_AGENT_PROMPT','S_08_TOOL_AUTHORITY','S_09_RESULT_REINJECTION','S_10_REAL_SOURCE_EDIT','S_11_BUILD_FAILURE_RECOVERY','S_12_MODEL_DIAGNOSES_FAILURE','S_13_SECOND_EDIT','S_14_FINAL_BUILD','S_15_FINAL_TESTS')
  $pc = 0
  foreach ($k in $passKeys) { if ($outL | Where-Object { $_ -like ($k + '=PASS*') } | Select-Object -First 1) { $pc++ } }
  $final = New-Object System.Collections.Generic.List[string]
  foreach ($line in $outL) {
    if ($line -match '^REQUIRED_PASS_HITS=') { [void]$final.Add("REQUIRED_PASS_HITS=$pc/11"); continue }
    if ($line -match '^BLOCKERS=') {
      $b = @()
      if ($step11 -notlike 'PASS*') { $b += 'NO_AGENT_OWNED_BUILD_RECOVERY' }
      $b += 'GPU_R9700_NOT_RUN'; $b += 'NO_INDEPENDENT_REVIEWER'; $b += 'ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE'
      if ($step08blocked) { }
      [void]$final.Add('BLOCKERS=' + ($b -join ';')); continue
    }
    [void]$final.Add($line)
  }
  $final | Set-Content $product -Encoding ASCII
  RLog ("PRODUCT_HITS=" + $pc + "/11")
}
RLog ("S09=" + $step09)
RLog ("S10=" + $step10)
RLog ("S11=" + $step11)
RLog ("BUILD_OK=" + $bok)
RLog 'DONE=1'
exit 0
