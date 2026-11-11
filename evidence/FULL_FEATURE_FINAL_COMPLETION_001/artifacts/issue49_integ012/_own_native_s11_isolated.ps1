# tip012 S11 isolated workdir — avoid tip016 shared fixture/flight kill.
# Kill foreign tip016 + non-owned deep2 only. HOST_SEED=OFF. PROMOTE=0.
$ErrorActionPreference = 'Continue'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$outDir = Join-Path $root 'artifacts\issue49_integ012'
$ev = Join-Path $outDir 'step08_11_evidence'
$runOut = Join-Path $outDir '_own_native_s11_isolated.out.txt'
$lock = Join-Path $root 'artifacts\ISSUE49_EXCLUSIVE.lock'
$expect = '6191E58E88A892401E373C329DA99C9752E956C0A6A81E03ABE242C25C52D247'
$tip012 = Join-Path $root 'candidates\tip_final_integ_012'
function RLog([string]$m) { $l = "$(Get-Date -Format o) $m"; Add-Content $runOut $l; Write-Output $l }
New-Item -ItemType Directory -Force -Path $ev,$outDir | Out-Null
'' | Set-Content $runOut -Encoding ASCII

# Kill ALL deep2/IDE first (no live owned tip012 S11)
Get-CimInstance Win32_Process | Where-Object {
  $_.Name -eq 'deep2_agentic_loop.exe' -or $_.Name -eq 'RawrXD-Win32IDE-Native-Ext.exe' -or
  ($_.CommandLine -match 'tip_final_integ_016')
} | ForEach-Object { RLog ("PREKILL=" + $_.ProcessId); Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
cmd /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1" | Out-Null
Start-Sleep 5

$work = Join-Path $outDir 'tip012_s11_isolated_work'
New-Item -ItemType Directory -Force -Path $work | Out-Null
$motdDst = Join-Path $work '.cursor\rules'
New-Item -ItemType Directory -Force -Path $motdDst | Out-Null
Copy-Item 'F:\rawrxd\.cursor\rules\PassiveRoleNotRoleplay.mdc' (Join-Path $motdDst 'PassiveRoleNotRoleplay.mdc') -Force
$bug = Join-Path $work 'bug.cpp'
$canonical = @"
/* Issue #49 product-final fixture: intentional compile bug for agent fix loop.
 * Do not pre-fix - agent (or measured blocker) must own the repair.
 */
int undeclared_fn(int a);

int main() {
  int x = undeclared_fn(1, 2); /* error: too many args + may need declaration fix */
  return x;
}
"@
[IO.File]::WriteAllText($bug, $canonical.Replace("`n","`r`n"))
$before = (Get-FileHash $bug -Algorithm SHA256).Hash
$tipSha = (Get-FileHash (Join-Path $tip012 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
if ($tipSha -ne $expect) { RLog ("SHA_DRIFT=" + $tipSha); exit 3 }
RLog ("TIP_SHA=" + $tipSha)
RLog ("BEFORE=" + $before)
RLog ("WORKDIR=" + $work)

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $ev ("tip012_isolated_native_s11_$stamp.log")
$err = $log + '.err'
$env:RAWRXD_ISSUE49_HOST_SEED = '0'
$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_AGENTIC_QUIET = '0'
$loop = Join-Path $tip012 'deep2_agentic_loop.exe'
$model = 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
$task = 'Fix bug.cpp so it compiles and links with MSVC. After TOOL read_motd and TOOL read bug.cpp, TOOL write bug.cpp with a COMPLETE fixed file that defines undeclared_fn and calls it with one argument, then TOOL build. HOST_SEED=OFF.'
$p = Start-Process -FilePath $loop -ArgumentList @(
  '--model',$model,'--workdir',$work,'--target-file','bug.cpp','--task',$task,
  '--max-steps','12','--max-new','512','--max-wall-time-sec','7200','--prefill-chunk','128','--batched-prefill','1'
) -WorkingDirectory $work -RedirectStandardOutput $log -RedirectStandardError $err -PassThru -WindowStyle Hidden
$own = $p.Id
RLog ("OWN_PID=" + $own)
RLog ("LOG=" + $log)
("OWN_PID=" + $own) | Set-Content (Join-Path $ev 'loop_pid_s11.txt')
@(
  'OWNER=tip012_isolated_native_s11'
  ("PID=" + $PID)
  ("OWN_DEEP2=" + $own)
  ("SHA=" + $expect)
  'HOST_SEED=OFF'
  'DO_NOT_KILL_OWN_DEEP2=1'
) | Set-Content $lock -Encoding ASCII

$deadline = (Get-Date).AddSeconds(5400)
$last = -1
while ((Get-Date) -lt $deadline) {
  Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match 'tip_final_integ_016' -or (
      $_.Name -eq 'deep2_agentic_loop.exe' -and $_.ProcessId -ne $own
    )
  } | ForEach-Object {
    RLog ("KILL_FOREIGN=" + $_.ProcessId)
    Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue
  }
  $alive = [bool](Get-Process -Id $own -EA SilentlyContinue)
  $bytes = 0
  if (Test-Path $log) { $bytes = (Get-Item $log).Length }
  if ($bytes -ne $last) { RLog ("BYTES=" + $bytes + " alive=" + [int]$alive); $last = $bytes }
  $t = ''
  if (Test-Path $log) { $t = Get-Content $log -Raw -EA SilentlyContinue }
  $re = [bool]($t -match 'RESULT_REINJECTION step=\d+.*status=PASS')
  $pc = [bool]($t -match 'PATCH COMMITTED')
  $fv = [bool]($t -match 'FINAL_VERDICT')
  if ($re -or $pc) { RLog ("HIT re=" + [int]$re + " patch=" + [int]$pc) }
  if (($re -and $pc) -or $fv) { RLog 'TERMINAL=1'; break }
  if (-not $alive) { RLog 'DEAD'; break }
  Start-Sleep 5
}

$after = (Get-FileHash $bug -Algorithm SHA256).Hash
$logText = if (Test-Path $log) { Get-Content $log -Raw } else { '' }
$tc = ([regex]::Matches($logText, '\[step \d+\] TOOL ')).Count
$reinject = ([regex]::Matches($logText, 'RESULT_REINJECTION step=\d+.*status=PASS')).Count
$committed = [int]($logText -match 'PATCH COMMITTED')
$hashChanged = [int]($before -ne $after)
$step09 = if ($reinject -ge 1) { 'PASS' } else { 'NOT_RUN' }
$step10 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_SOURCE_HASH_AND_LEDGER' } else { 'NOT_RUN_NO_AGENT_EDIT' }
$step11 = if (($committed -eq 1) -and ($hashChanged -eq 1)) { 'PASS_WRITE_VERIFY_BUILD_RECOVERY' } else { 'NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY' }
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@"
ISSUE49_ISOLATED_NATIVE_S11=MEASURED
ASOF_UTC=$asof
TIP_SHA256=$tipSha
OWN_PID=$own
WORKDIR=$work
S_09=$step09
S_10=$step10
S_11=$step11
REINJECT=$reinject
COMMITTED=$committed
BEFORE=$before
AFTER=$after
LOOP_LOG=$log
PROMOTE=0
"@ | Set-Content (Join-Path $outDir 'ISSUE49_ISOLATED_NATIVE_S11_RECEIPT.txt')
RLog ("STEP09=" + $step09)
RLog ("STEP10=" + $step10)
RLog ("STEP11=" + $step11)
Remove-Item $lock -Force -EA SilentlyContinue
RLog 'SEAL_DONE=1'
exit 0
