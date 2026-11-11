# Source-only ModelGenie IR numerical diagnostic + opt-in source/evidence push.
# Fail closed: does not touch any Git submodule. No synthetic PASS receipts.
[CmdletBinding()]
param(
  [string]$RepoRoot='F:\rawrxd',
  [string]$GGUF='G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf',
  [string]$EvidenceDir='F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001',
  [string]$ReferenceDir='',
  [switch]$Apply,
  [switch]$Push
)
$ErrorActionPreference='Stop'
$branch='feat/hexmag-polymorphic-repeat-tuner-masm'
$repo=(Resolve-Path -LiteralPath $RepoRoot).Path
$kit=Join-Path $repo 'tools\parity_frontier'
$evidence=Join-Path $EvidenceDir 'parity_ir'
$runner=Join-Path $kit 'patch_numeric.py'
$trace=Join-Path $kit 'RawrXD_IR_Trace.hpp'
$targetTrace=Join-Path $repo 'tools\RawrXD_IR_Trace.hpp'
$instrument=Join-Path $kit 'instrument_ir.py'
$irSource=Join-Path $repo 'tools\rawrxd_modelgenie_ir_executor.cpp'
$exe=Join-Path $repo 'tmp_build\modelgenie_ir_executor.exe'
$log=Join-Path $EvidenceDir 'parity_ir_run.log'
$auditLog=Join-Path $EvidenceDir 'parity_q6_audit.log'
$summary=Join-Path $EvidenceDir 'parity_ir_summary.txt'
if (-not (Test-Path -LiteralPath $runner)) { throw 'KIT_MISSING: extract kit under tools/parity_frontier' }
$python='python'
if (Get-Command py -ErrorAction SilentlyContinue) { $python='py' }
elseif (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'PYTHON3_NOT_FOUND' }
$pyPre=@()
if ($python -eq 'py') { $pyPre=@('-3') }
function Invoke-Py([string[]]$CliArgs) {
  & $python @pyPre @CliArgs
  if ($LASTEXITCODE -ne 0) { throw "PYTHON_EXIT=${LASTEXITCODE}: $($CliArgs -join ' ')" }
}
function Invoke-Native([string]$program,[string[]]$CliArgs) {
  & $program @CliArgs
  if ($LASTEXITCODE -ne 0) { throw "NATIVE_EXIT=${LASTEXITCODE}: $program" }
}
function ParseGate([string]$Text,[string]$Name) {
  $match=[regex]::Matches($Text, "(?m)^$([regex]::Escape($Name))=([^`r`n]+)")
  if ($match.Count -eq 0) { return 'MISSING' }
  return $match[$match.Count-1].Groups[1].Value.Trim()
}
Invoke-Native -program 'git' -CliArgs @('-C',$repo,'rev-parse','--is-inside-work-tree')
$currentBranch=(& git -C $repo branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $currentBranch -ne $branch) { throw "BRANCH_MISMATCH=$currentBranch EXPECTED=$branch" }
$staged=@(& git -C $repo diff --cached --name-only)
if ($staged.Count -gt 0) { throw 'EXISTING_STAGED_CHANGES: refuse to include unrelated staged work' }
Invoke-Py -CliArgs @($runner,$repo)
if (-not $Apply) {
  Write-Host 'DRY_RUN=PASS; pass -Apply to patch, compile and run; optionally -Push to publish.'
  return
}
if (-not (Test-Path -LiteralPath $GGUF)) { throw "MODEL_MISSING=$GGUF" }
$size=(Get-Item -LiteralPath $GGUF).Length
if ($size -ne [long]10364416768) { throw "MODEL_SIZE_MISMATCH=$size EXPECTED=10364416768" }
Invoke-Py -CliArgs @($runner,$repo,'--apply')
if (-not (Test-Path -LiteralPath $targetTrace)) {
  Copy-Item -LiteralPath $trace -Destination $targetTrace
} elseif ((Get-FileHash -LiteralPath $trace -Algorithm SHA256).Hash -ne
          (Get-FileHash -LiteralPath $targetTrace -Algorithm SHA256).Hash) {
  throw 'TRACE_HEADER_CONFLICT: preserve existing header; manual reconciliation needed'
}
$sourceText=Get-Content -LiteralPath $irSource -Raw
if ($sourceText -notmatch 'RAWRXD_PARITY_TRACE_INJECTED') {
  Invoke-Py -CliArgs @($instrument,$irSource)
  Invoke-Py -CliArgs @($instrument,$irSource,'--apply')
} else { Write-Host 'TRACE_INSTRUMENTATION=ALREADY_PRESENT' }
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$env:RAWRXD_PARITY_DIR=$evidence
# Prevent stale op files from being mistaken for new ones.
Get-ChildItem -LiteralPath $evidence -Filter 'op_*.bin' -File | Remove-Item -Force
Write-Host 'Q6_AUDITOR_BUILD=START'
Invoke-Native -program 'cmd.exe' -CliArgs @('/d','/c',(Join-Path $kit 'build_probe.cmd'))
Write-Host 'IR_EXECUTOR_BUILD=START'
Invoke-Native -program 'cmd.exe' -CliArgs @('/d','/c',(Join-Path $kit 'build_executor.cmd'))
if (-not (Test-Path -LiteralPath $exe)) { throw "EXE_MISSING=$exe" }
Write-Host 'IR_EXECUTOR_REAL_MODEL_RUN=START'
# A model-run exit 1 is kept as a measured FAIL, not transformed to a fake PASS.
$oldPref=$ErrorActionPreference
$ErrorActionPreference='Continue'
try {
  & $exe $GGUF $EvidenceDir 2>&1 | Tee-Object -FilePath $log
  $runExit=$LASTEXITCODE
} finally { $ErrorActionPreference=$oldPref }
$runText=Get-Content -LiteralPath $log -Raw
$visited=ParseGate $runText 'IR_OPS_VISITED'
$executed=ParseGate $runText 'IR_OPS_EXECUTED'
$skipped=ParseGate $runText 'IR_OPS_SKIPPED'
$finite=ParseGate $runText 'LOGITS_FINITE'
$predicted=ParseGate $runText 'PREDICTED_TOKEN'
$verdict=ParseGate $runText 'VERDICT'
$structural=($visited -eq '300' -and $executed -eq '300' -and $skipped -eq '0' -and $finite -eq '1')
$targetMatch=($structural -and $predicted -eq '93633')
$auditExit=-1
$lmMatch='UNVERIFIED'
$numericClose='UNVERIFIED'
$hidden=Join-Path $evidence 'op_298.bin'
$logits=Join-Path $evidence 'op_299.bin'
if ($structural -and (Test-Path -LiteralPath $hidden) -and (Test-Path -LiteralPath $logits) -and
    (Get-Item -LiteralPath $hidden).Length -eq 8192 -and (Get-Item -LiteralPath $logits).Length -eq 409600) {
  $auditExe=Join-Path $kit 'rawrxd_q6_lmhead_audit.exe'
  & $auditExe $GGUF $hidden $logits 2>&1 | Tee-Object -FilePath $auditLog
  $auditExit=$LASTEXITCODE
  if ($auditExit -eq 0) {
    $auditText=Get-Content -LiteralPath $auditLog -Raw
    $lmMatch=ParseGate $auditText 'LMHEAD_ARGMAX_MATCH'
    $numericClose=ParseGate $auditText 'LMHEAD_NUMERIC_CLOSE'
  }
} else {
  Set-Content -LiteralPath $auditLog -Value 'AUDIT_NOT_RUN=1 MISSING_OR_INVALID_ACTIVATIONS=1' -Encoding utf8
}
$compareStatus='REFERENCE_NOT_SUPPLIED'
if ($ReferenceDir) {
  $compareLog=Join-Path $EvidenceDir 'parity_compare.log'
  & $python @pyPre (Join-Path $kit 'compare_traces.py') $evidence $ReferenceDir 2>&1 | Tee-Object -FilePath $compareLog
  $compareStatus=if ($LASTEXITCODE -eq 0) {'REFERENCE_COMPARISON_RUN'}else{'REFERENCE_COMPARISON_FAILED'}
}
$entries=@(
  "SOURCE_COMMIT=$((& git -C $repo rev-parse HEAD).Trim())",
  "BRANCH=$currentBranch",
  "GGUF_SIZE=$size",
  "GGUF_SHA256=$((Get-FileHash -LiteralPath $GGUF -Algorithm SHA256).Hash)",
  "RUN_EXIT=$runExit",
  "IR_OPS_VISITED=$visited",
  "IR_OPS_EXECUTED=$executed",
  "IR_OPS_SKIPPED=$skipped",
  "LOGITS_FINITE=$finite",
  "PREDICTED_TOKEN=$predicted",
  'EXPECTED_TOKEN=93633',
  "STRUCTURAL_GATE=$(if($structural){'PASS'}else{'FAIL'})",
  "TARGET_TOKEN_MATCH=$(if($targetMatch){1}else{0})",
  "LMHEAD_AUDIT_EXIT=$auditExit",
  "LMHEAD_ARGMAX_MATCH=$lmMatch",
  "LMHEAD_NUMERIC_CLOSE=$numericClose",
  "REFERENCE_STATUS=$compareStatus",
  "EXECUTOR_VERDICT=$verdict"
)
$entries | Set-Content -LiteralPath $summary -Encoding UTF8
Get-Content -LiteralPath $summary
if ($Push) {
  # Explicit allowlist; notably, do NOT stage the OrganizedPiProject submodule.
  $files=@(
    'tools/rawrxd_modelgenie_ir_executor.cpp',
    'tools/rawrxd_modelgenie_token0_execution.cpp',
    'tools/RawrXD_IR_Trace.hpp',
    'tools/parity_frontier/RawrXD_IR_Trace.hpp',
    'tools/parity_frontier/instrument_ir.py',
    'tools/parity_frontier/compare_traces.py',
    'tools/parity_frontier/rawrxd_q6_lmhead_audit.cpp',
    'tools/parity_frontier/build_probe.cmd',
    'tools/parity_frontier/build_executor.cmd',
    'tools/parity_frontier/patch_numeric.py',
    'tools/parity_frontier/test_patch_numeric.py',
    'tools/parity_frontier/run_parity.ps1',
    'tools/parity_frontier/README.md',
    'evidence/NUGVERSE_ESTIMATOR_001/parity_ir_run.log',
    'evidence/NUGVERSE_ESTIMATOR_001/parity_q6_audit.log',
    'evidence/NUGVERSE_ESTIMATOR_001/parity_ir_summary.txt'
  )
  if ($ReferenceDir) { $files+= 'evidence/NUGVERSE_ESTIMATOR_001/parity_compare.log' }
  Invoke-Native -program 'git' -CliArgs (@('-C',$repo,'add','--')+$files)
  $stagedNow=@(& git -C $repo diff --cached --name-only)
  if ($stagedNow | Where-Object { $_ -match '^OrganizedPiProject/' }) {
    throw 'SUBMODULE_IN_INDEX: refusing commit'
  }
  & git -C $repo diff --cached --quiet
  if ($LASTEXITCODE -eq 1) {
    Invoke-Native -program 'git' -CliArgs @('-C',$repo,'commit','-m','fix(modelgenie): correct GGML numerics and record live parity diagnostic')
  }
  Invoke-Native -program 'git' -CliArgs @('-C',$repo,'push','origin',"HEAD:refs/heads/$branch")
  Write-Host 'PUSH_RESULT=COMPLETE (check parity_ir_summary.txt for measured verdict)'
}
if (-not $structural -or $auditExit -ne 0 -or $lmMatch -ne '1' -or $numericClose -ne '1' -or -not $targetMatch) {
  throw 'PARITY_GATE_NOT_CLOSED: measured evidence saved; no PASS certificate issued'
}
Write-Host 'TARGET_TOKEN_GATE=PASS (independent reference still required for full model numerical equivalence)'
