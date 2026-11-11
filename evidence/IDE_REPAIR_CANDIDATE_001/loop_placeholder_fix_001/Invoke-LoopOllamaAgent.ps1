# Fail-closed live ollama agent proof for placeholder @@ fix.
# PROMOTE=0 CERTIFIED=0
param(
  [string]$LoopExe = 'F:\rawrxd\build_tip_debug_rel\bin\deep2_agentic_loop.exe',
  [string]$OutRoot = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001',
  [string]$Model = 'bigdaddyg-productivity-local:latest',
  [int]$MaxSteps = 12,
  [int]$MaxWallSec = 300
)
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $OutRoot ("live_issue49_loop3795_" + $stamp)
New-Item -ItemType Directory -Force -Path $out,(Join-Path $out '.cursor\rules') | Out-Null
Copy-Item -LiteralPath 'g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc' `
  -Destination (Join-Path $out '.cursor\rules\PassiveRoleNotRoleplay.mdc') -Force

$bug = @"
#include <cstdio>
int add(int a, int b) { return a - b; }
int main() { std::printf("AGENT_RESULT=%d\n", add(2, 3)); return 0; }
"@
Set-Content -LiteralPath (Join-Path $out 'bug.cpp') -Value $bug -Encoding ASCII

$stdout = Join-Path $out 'agent.stdout.log'
$stderr = Join-Path $out 'agent.stderr.log'
$receipt = Join-Path $out 'AGENT_RESULT_RECEIPT.txt'
$beforeSha = (certutil -hashfile (Join-Path $out 'bug.cpp') SHA256 | Select-Object -Skip 1 -First 1).Trim()

$bugExe = Join-Path $out 'bug.exe'
$buildCmd = "cl /nologo /EHsc /std:c++20 /Fe:`"$bugExe`" `"$(Join-Path $out 'bug.cpp')`""
$runCmd = $bugExe
$argsList = @(
  '--provider','ollama',
  '--model',$Model,
  '--workdir',$out,
  '--target-file','bug.cpp',
  '--build-command',$buildCmd,
  '--run-command',$runCmd,
  '--max-steps',("$MaxSteps"),
  '--max-wall-time-sec',("$MaxWallSec"),
  '--expected-output','AGENT_RESULT=5'
)

$p = Start-Process -FilePath $LoopExe -ArgumentList $argsList `
  -WorkingDirectory $out -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -NoNewWindow
$deadline = (Get-Date).AddSeconds($MaxWallSec + 60)
while (-not $p.HasExited -and (Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 3
}
$timedOut = -not $p.HasExited
if ($timedOut) {
  try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
}
Start-Sleep 1
try { $p.Refresh() } catch {}
$exit = if ($p.HasExited) { $p.ExitCode } else { -1 }

$afterPath = Join-Path $out 'bug.cpp'
$afterSha = if (Test-Path $afterPath) {
  (certutil -hashfile $afterPath SHA256 | Select-Object -Skip 1 -First 1).Trim()
} else { '' }
$afterText = if (Test-Path $afterPath) { Get-Content -LiteralPath $afterPath -Raw } else { '' }
$stdoutText = if (Test-Path $stdout) { Get-Content -LiteralPath $stdout -Raw } else { '' }

$writeBodyBad = [int]($stdoutText -match 'write_body_bytes=25')
$writeBodyOk = [int]($stdoutText -match 'write_body_bytes=(1[0-9]{2}|[2-9][0-9]{2,})')
$editPass = [int]($stdoutText -match 'OLLAMA_AGENT_EDIT PASS')
$btPass = [int]($stdoutText -match 'OLLAMA_AGENT_BUILD_TEST PASS')
$verdictPass = [int]($stdoutText -match 'OLLAMA_AGENT_VERDICT PASS')
$agentResult5 = [int]($stdoutText -match 'AGENT_RESULT=5')
$sourceFixed = [int]($afterText -match 'return a \+ b')

$agentResult = 'OPEN'
if ($verdictPass -eq 1 -and $agentResult5 -eq 1 -and $sourceFixed -eq 1 -and $writeBodyBad -eq 0) {
  $agentResult = 'PASS'
} elseif ($timedOut) {
  $agentResult = 'FAIL_TIMEOUT'
} else {
  $agentResult = 'FAIL'
}

@"
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
OUT=$out
LOOP_EXE=$LoopExe
LOOP_SHA256=3795c179b997491be427981865fe79509058bcd0b24f53e1159ddeed6a9a15f3
MODEL=$Model
PROCESS_EXIT=$exit
TIMED_OUT=$([int]$timedOut)
BEFORE_SHA256=$beforeSha
AFTER_SHA256=$afterSha
WRITE_BODY_25_HIT=$writeBodyBad
WRITE_BODY_LARGE_HIT=$writeBodyOk
OLLAMA_AGENT_EDIT_PASS=$editPass
OLLAMA_AGENT_BUILD_TEST_PASS=$btPass
OLLAMA_AGENT_VERDICT_PASS=$verdictPass
AGENT_RESULT_5_IN_LOG=$agentResult5
SOURCE_FIXED_PLUS=$sourceFixed
AGENT_RESULT_GATE=$agentResult
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
"@ | Set-Content -LiteralPath $receipt -Encoding UTF8

Write-Host "RECEIPT=$receipt"
Write-Host "AGENT_RESULT_GATE=$agentResult"
Get-Content -LiteralPath $receipt
exit $(if ($agentResult -eq 'PASS') { 0 } else { 1 })
