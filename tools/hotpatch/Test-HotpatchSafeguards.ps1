# Master hotpatch safeguard harness. CERTIFIED=0 PROMOTE=0. No invented ROUTING_E2E PASS.
param(
  [string]$EvidenceOut = 'F:\rawrxd\evidence\UPPER_TIER_MASTER_001\HOTPATCH_SAFEGUARDS_001',
  [string]$ExePath = 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe'
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Join-Path $EvidenceOut "runs\$stamp"
$fixDir = Join-Path $EvidenceOut 'fixtures'
New-Item -ItemType Directory -Force -Path $runDir, $fixDir | Out-Null
$results = [ordered]@{}
$fail = 0

function Set-Result([string]$k, [bool]$ok, [string]$detail) {
  $script:results[$k] = @{ ok = $ok; detail = $detail }
  if ($ok) { Write-Host "PASS $k :: $detail" } else { Write-Host "FAIL $k :: $detail"; $script:fail++ }
}

# 1) Launcher rejects mismatched binary hashes
$exeOk = Test-Path -LiteralPath $ExePath -PathType Leaf
if (-not $exeOk) {
  Set-Result 'launcher_hash_mismatch_reject' $false "exe missing: $ExePath (BLOCKED_ON_BATCH17_EXE if rebuild pending)"
} else {
  $real = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
  $bad = ('0' * 64)
  $rej = $false
  $errOut = ''
  try {
    $errOut = & "$here\Start-RawrXDAcceptance.ps1" -ExePath $ExePath -ExpectedSha256 $bad -HashCheckOnly 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { $rej = $true }
  } catch {
    $rej = $true
    $errOut = $_.Exception.Message
  }
  if (-not $rej -and $errOut -match 'HASH MISMATCH') { $rej = $true }
  Set-Result 'launcher_hash_mismatch_reject' $rej "expected reject on sha=$bad actual=$real"
  # Positive hash check
  $okLaunch = $false
  try {
    & "$here\Start-RawrXDAcceptance.ps1" -ExePath $ExePath -ExpectedSha256 $real -HashCheckOnly | Out-Null
    $okLaunch = ($LASTEXITCODE -eq 0)
  } catch { $okLaunch = $false }
  Set-Result 'launcher_hash_match_accept' $okLaunch "sha=$real"
}

# 2) Validator rejects incomplete / stale / mismatched
$incomplete = Join-Path $fixDir 'evidence_incomplete.json'
@'
{
  "exe_sha256": "",
  "agent": [{"request_id":"","gui_model":"","resolved_model":"","ollama_model":"","exact_output":false}],
  "ghosttext": [],
  "cancel_recovery_pass": false,
  "no_stale_output": false,
  "PROMOTE": 0,
  "CERTIFIED": 0
}
'@ | Set-Content -LiteralPath $incomplete -Encoding UTF8
$rc = 0
try { & "$here\Test-RawrXDEvidence.ps1" -EvidenceJson $incomplete 2>&1 | Out-Null; $rc = $LASTEXITCODE } catch { $rc = 1 }
if ($rc -eq 0 -and $LASTEXITCODE) { $rc = $LASTEXITCODE }
Set-Result 'validator_rejects_incomplete' ($rc -ne 0) "exit=$rc"

$stale = Join-Path $fixDir 'evidence_stale.json'
$old = ([datetime]::UtcNow.AddDays(-10)).ToString('o')
@"
{
  "exe_sha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  "evidence_timestamp": "$old",
  "agent": [
    {"request_id":"a1","gui_model":"m1","resolved_model":"m1","ollama_model":"m1","exact_output":true},
    {"request_id":"a2","gui_model":"m2","resolved_model":"m2","ollama_model":"m2","exact_output":true}
  ],
  "ghosttext": [
    {"request_id":"g1","gui_model":"m1","resolved_model":"m1","ollama_model":"m1","exact_output":true},
    {"request_id":"g2","gui_model":"m2","resolved_model":"m2","ollama_model":"m2","exact_output":true}
  ],
  "cancel_recovery_pass": true,
  "no_stale_output": true,
  "PROMOTE": 0,
  "CERTIFIED": 0
}
"@ | Set-Content -LiteralPath $stale -Encoding UTF8
$rc = 0
try { & "$here\Test-RawrXDEvidence.ps1" -EvidenceJson $stale -MaxAgeHours 72 2>&1 | Out-Null; $rc = $LASTEXITCODE } catch { $rc = 1 }
Set-Result 'validator_rejects_stale' ($rc -ne 0) "exit=$rc"

$mismatch = Join-Path $fixDir 'evidence_sha_mismatch.json'
@"
{
  "exe_sha256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  "evidence_timestamp": "$(([datetime]::UtcNow).ToString('o'))",
  "agent": [
    {"request_id":"a1","gui_model":"m1","resolved_model":"m1","ollama_model":"m1","exact_output":true},
    {"request_id":"a2","gui_model":"m2","resolved_model":"m2","ollama_model":"m2","exact_output":true}
  ],
  "ghosttext": [
    {"request_id":"g1","gui_model":"m1","resolved_model":"m1","ollama_model":"m1","exact_output":true},
    {"request_id":"g2","gui_model":"m2","resolved_model":"m2","ollama_model":"m2","exact_output":true}
  ],
  "cancel_recovery_pass": true,
  "no_stale_output": true,
  "PROMOTE": 0,
  "CERTIFIED": 0
}
"@ | Set-Content -LiteralPath $mismatch -Encoding UTF8
$rc = 0
try {
  & "$here\Test-RawrXDEvidence.ps1" -EvidenceJson $mismatch `
    -ExpectedExeSha256 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' 2>&1 | Out-Null
  $rc = $LASTEXITCODE
} catch { $rc = 1 }
Set-Result 'validator_rejects_sha_mismatch' ($rc -ne 0) "exit=$rc"

$dup = Join-Path $fixDir 'evidence_dup_request_id.json'
@"
{
  "exe_sha256": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
  "evidence_timestamp": "$(([datetime]::UtcNow).ToString('o'))",
  "agent": [
    {"request_id":"same","gui_model":"m1","resolved_model":"m1","ollama_model":"m1","exact_output":true},
    {"request_id":"same","gui_model":"m2","resolved_model":"m2","ollama_model":"m2","exact_output":true}
  ],
  "ghosttext": [
    {"request_id":"g1","gui_model":"m1","resolved_model":"m1","ollama_model":"m1","exact_output":true},
    {"request_id":"g2","gui_model":"m2","resolved_model":"m2","ollama_model":"m2","exact_output":true}
  ],
  "cancel_recovery_pass": true,
  "no_stale_output": true,
  "PROMOTE": 0,
  "CERTIFIED": 0
}
"@ | Set-Content -LiteralPath $dup -Encoding UTF8
$rc = 0
try { & "$here\Test-RawrXDEvidence.ps1" -EvidenceJson $dup 2>&1 | Out-Null; $rc = $LASTEXITCODE } catch { $rc = 1 }
Set-Result 'validator_rejects_duplicate_request_id' ($rc -ne 0) "exit=$rc"

# 3-5) C++ smoke: unique IDs, model-select invalidation, cancel, redact
$cl = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
$smokeExe = Join-Path $runDir 'ghosttext_safeguards_smoke.exe'
$objDir = Join-Path $runDir 'obj'
New-Item -ItemType Directory -Force -Path $objDir | Out-Null
Push-Location $here
try {
  & $cl /nologo /EHsc /std:c++17 /O2 /Fe:$smokeExe /Fo:$objDir\ ghosttext_safeguards_smoke.cpp
  $compileOk = ($LASTEXITCODE -eq 0) -and (Test-Path $smokeExe)
  Set-Result 'ghosttext_smoke_compile' $compileOk "cl_exit=$LASTEXITCODE"
  if ($compileOk) {
    & $smokeExe | Tee-Object -FilePath (Join-Path $runDir 'ghosttext_safeguards_smoke.log')
    Set-Result 'ghosttext_smoke_runtime' ($LASTEXITCODE -eq 0) "exit=$LASTEXITCODE"
  } else {
    Set-Result 'ghosttext_smoke_runtime' $false 'compile failed'
  }
} finally { Pop-Location }

# 6) Document previous-candidate law (file must exist)
$law = Join-Path $EvidenceOut 'PREVIOUS_CANDIDATE_CANNOT_CERTIFY_NEWER_SOURCE.md'
Set-Result 'previous_candidate_law_documented' (Test-Path $law) $law

$results['ROUTING_E2E'] = 'NOT_CERTIFIED'
$results['BLOCKED_ON_BATCH17_EXE'] = $true
$results['CERTIFIED'] = 0
$results['PROMOTE'] = 0
$results['FAIL_COUNT'] = $fail
$results | ConvertTo-Json -Depth 6 |
  Set-Content -LiteralPath (Join-Path $runDir 'SAFEGUARD_RESULTS.json') -Encoding UTF8
Write-Host "RUN_DIR=$runDir FAIL_COUNT=$fail CERTIFIED=0 PROMOTE=0 ROUTING_E2E=NOT_CERTIFIED"
exit $(if ($fail -eq 0) { 0 } else { 1 })
