$ErrorActionPreference = 'Stop'
$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$src = Join-Path $root 'candidates\tip_final_integ_013'
$dst = Join-Path $root 'candidates\tip_final_integ_014'
$built = 'F:\rawrxd\build\bin\RelWithDebInfo\RawrXD-Win32IDE-Native-Ext.exe'
$pdb = 'F:\rawrxd\build\bin\RelWithDebInfo\RawrXD-Win32IDE-Native-Ext.pdb'
if (-not (Test-Path -LiteralPath $dst)) {
  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  Copy-Item -LiteralPath (Join-Path $src 'deep2_agentic_loop.exe') -Destination $dst -Force
  if (Test-Path (Join-Path $src 'debuggee_fixture.exe')) {
    Copy-Item -LiteralPath (Join-Path $src 'debuggee_fixture.exe') -Destination $dst -Force
  }
}
Copy-Item -LiteralPath $built -Destination (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.exe') -Force
if (Test-Path $pdb) { Copy-Item -LiteralPath $pdb -Destination (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.pdb') -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $dst 'issue49_logs'), (Join-Path $dst 'logs') | Out-Null
$sha = (Get-FileHash -LiteralPath (Join-Path $dst 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
$loopSha = (Get-FileHash -LiteralPath (Join-Path $dst 'deep2_agentic_loop.exe') -Algorithm SHA256).Hash
$sha | Set-Content -LiteralPath (Join-Path $dst 'SHA256.txt') -Encoding ASCII
$loopSha | Set-Content -LiteralPath (Join-Path $dst 'LOOP_SHA256.txt') -Encoding ASCII
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
@"
tip_final_integ_014
REASON=IDE_WATCHDOG_AND_WALL_EXTENSION_FOR_7B
FROM_TIP=tip_final_integ_013
TIP013_SHA=1BACCED694A98F39C9A5147CA6AEE1A86D1E87EF134691B28FF6BD9B463844C9
TIP014_SHA=$sha
LOOP_SHA256=$loopSha
WATCHDOG_DEFAULT_STARTUP_MS=180000
WATCHDOG_DEFAULT_WALL_MS=2400000
FORCE_LOCAL_MAX_WALL_SEC=2400
ENV_RAWRXD_AGENTIC_MAX_WALL_SEC=1
ENV_RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS=1
ENV_RAWRXD_AGENTIC_WATCHDOG_WALL_MS=1
HOST_SEED=OFF
PROMOTE=0
TIP_MOVE=0
CONTROLLING=CC79
ASOF_UTC=$asof
"@ | Set-Content -LiteralPath (Join-Path $dst 'CANDIDATE.txt') -Encoding ASCII
@"
MODEL_PATH=F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf
MODEL_SHA256=1664FCCAB734674A50763490A8C6931B70E3F2F8EC10031B54806D30E5F956B6
WIRED_FOR=ISSUE49_TIP014_WATCHDOG
HOST_SEED=OFF
"@ | Set-Content -LiteralPath (Join-Path $dst 'MODEL_WIRED.txt') -Encoding ASCII
Write-Output "TIP014_SHA=$sha"
Write-Output "LOOP_SHA=$loopSha"

$t = Get-Content -LiteralPath (Join-Path $root 'artifacts\issue49_integ013_remeasure.ps1') -Raw
$t = $t -replace 'tip_final_integ_013','tip_final_integ_014'
$t = $t -replace 'issue49_integ013','issue49_integ014'
$t = $t -replace 'TIP013','TIP014'
$t = $t -replace 'tip013','tip014'
$t = $t -replace '1BACCED694A98F39C9A5147CA6AEE1A86D1E87EF134691B28FF6BD9B463844C9',$sha
Set-Content -LiteralPath (Join-Path $root 'artifacts\issue49_integ014_remeasure.ps1') -Value $t -Encoding UTF8

$excl = @"
# Exclusive Issue #49 for tip_final_integ_014 (7B watchdog/wall extended EXE).
# HOST_SEED=OFF. tip_013 remains frozen for loop 08-11 authority.
`$ErrorActionPreference = 'Continue'
`$root = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
`$lock = Join-Path `$root 'artifacts\ISSUE49_EXCLUSIVE.lock'
`$harness = Join-Path `$root 'artifacts\issue49_integ014_remeasure.ps1'
`$expect = '$sha'
@(
  'OWNER=issue49_tip014_watchdog7b'
  "PID=`$PID"
  "ASOF_UTC=`$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "SHA=`$expect"
  'DO_NOT_STOP_PROCESS_NATIVE_EXT=1'
  'HOST_SEED=OFF'
  'MODEL=qwen2.5-coder-7b-instruct.Q4_K_M.gguf'
) | Set-Content -LiteralPath `$lock -Encoding ASCII
`$env:RAWRXD_FORCE_LOCAL_AGENTIC = '1'
`$env:RAWRXD_AGENTIC_QUIET = '0'
`$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
`$env:RAWRXD_AGENTIC_MAX_WALL_SEC = '7200'
`$env:RAWRXD_AGENTIC_WATCHDOG_STARTUP_MS = '300000'
`$env:RAWRXD_AGENTIC_WATCHDOG_WALL_MS = '7200000'
cmd.exe /c "taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1 & taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM debuggee_fixture.exe >nul 2>&1"
Start-Sleep 2
`$code = 1
try {
  & `$harness -AgentWaitSec 7200 -ModelPath 'F:\rawrxd\models\qwen2.5-coder-7b-instruct.Q4_K_M.gguf' -ExpectSha `$expect
  `$code = `$LASTEXITCODE
} finally {
  Remove-Item -LiteralPath `$lock -Force -EA SilentlyContinue
}
exit `$(if (`$null -eq `$code) { 1 } else { `$code })
"@
Set-Content -LiteralPath (Join-Path $root 'artifacts\run_issue49_tip014_exclusive.ps1') -Value $excl -Encoding UTF8
Write-Output 'TIP014_STAGED=1'
