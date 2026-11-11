# RAWRXD_MODELGENIE_DISPATCH_ORDER_001
# Uses the real 10.36 GB model and publishes ONLY measured evidence by opt-in.
[CmdletBinding()]
param(
    [string]$RepoRoot='F:\rawrxd',
    [string]$GGUF='G:\~dev\rawrxd\models\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf',
    [string]$EvidenceDir='F:\rawrxd\evidence\NUGVERSE_ESTIMATOR_001',
    [switch]$Apply,
    [switch]$Push
)
$ErrorActionPreference = 'Stop'
if ($Push -and -not $Apply) { throw 'PUSH_REQUIRES_APPLY=1' }
$branch = 'feat/hexmag-polymorphic-repeat-tuner-masm'
$repo = (Resolve-Path -LiteralPath $RepoRoot).Path
$src = Join-Path $repo 'tools\rawrxd_modelgenie_ir_executor.cpp'
$kit = Join-Path $repo 'tools\parity_frontier'
$patch = Join-Path $kit 'fix_dispatch_order.py'
$exe = Join-Path $repo 'tmp_build\modelgenie_ir_executor.exe'
$build = Join-Path $repo 'compile_ir_executor.bat'
$runLog = Join-Path $EvidenceDir 'parity_dispatch_order_run.log'
$summary = Join-Path $EvidenceDir 'parity_dispatch_order_summary.txt'
$audit = Join-Path $kit 'rawrxd_q6_lmhead_audit.exe'
$auditLog = Join-Path $EvidenceDir 'parity_dispatch_order_q6_audit.log'
$dumpDir = Join-Path $EvidenceDir 'parity_ir'

function Invoke-ExitChecked([string]$Exe, [string[]]$Argv) {
    & $Exe @Argv
    if ($LASTEXITCODE -ne 0) { throw "COMMAND_FAILED=$Exe EXIT=$LASTEXITCODE" }
}
function ReadGate([string]$Content, [string]$Name) {
    $matchesFound = [regex]::Matches($Content, "(?m)^$([regex]::Escape($Name))=([^`r`n]+)")
    if ($matchesFound.Count -ne 1) { return 'MISSING_OR_DUPLICATE' }
    return $matchesFound[0].Groups[1].Value.Trim()
}
function RunNativeCapture([string]$Program, [string[]]$Args, [string]$TargetLog) {
    $stdout = "$TargetLog.stdout.tmp"
    $stderr = "$TargetLog.stderr.tmp"
    if (Test-Path -LiteralPath $stdout) { Remove-Item -LiteralPath $stdout -Force }
    if (Test-Path -LiteralPath $stderr) { Remove-Item -LiteralPath $stderr -Force }
    try {
        # Start-Process returns the native process exit code independently of PowerShell pipes.
        $proc = Start-Process -FilePath $Program -ArgumentList $Args -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $err = if (Test-Path -LiteralPath $stderr) { Get-Content -LiteralPath $stderr -Raw } else { '' }
        $out = if (Test-Path -LiteralPath $stdout) { Get-Content -LiteralPath $stdout -Raw } else { '' }
        [System.IO.File]::WriteAllText($TargetLog, ($err + "`n" + $out))
        return [int]$proc.ExitCode
    } finally {
        Remove-Item -LiteralPath $stdout,$stderr -Force -ErrorAction SilentlyContinue
    }
}

if (-not (Test-Path -LiteralPath $patch)) { throw "KIT_MISSING=$patch" }
if (-not (Test-Path -LiteralPath $src)) { throw "SOURCE_MISSING=$src" }
if (-not (Test-Path -LiteralPath $build)) { throw "BUILD_SCRIPT_MISSING=$build" }
$actualBranch = (& git -C $repo branch --show-current).Trim()
if ($LASTEXITCODE -ne 0 -or $actualBranch -ne $branch) { throw "BRANCH_MISMATCH=$actualBranch EXPECTED=$branch" }
$index = @(& git -C $repo diff --cached --name-only)
if ($index.Count -ne 0) { throw 'REFUSE_PREEXISTING_STAGED_CHANGES=1' }

# Python launcher alternatives: use Python 3 directly, or 'py -3'.
$pythonCmd = 'python'
$pre = @()
if (Get-Command py -ErrorAction SilentlyContinue) { $pythonCmd='py'; $pre=@('-3') }
elseif (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw 'PYTHON3_MISSING=1' }
Invoke-ExitChecked $pythonCmd ($pre + @($patch,$src))
if (-not $Apply) {
    Write-Host 'DRY_RUN_ONLY=1 (add -Apply to compile and execute, optionally -Push to commit evidence)'
    return
}
if (-not (Test-Path -LiteralPath $GGUF)) { throw "MODEL_MISSING=$GGUF" }
$modelBytes = (Get-Item -LiteralPath $GGUF).Length
if ($modelBytes -ne 10364416768L) { throw "GGUF_SIZE_MISMATCH=$modelBytes" }
Invoke-ExitChecked $pythonCmd ($pre + @($patch,$src,'--apply'))
$sourceHash = (Get-FileHash -LiteralPath $src -Algorithm SHA256).Hash
$beforeTime = if (Test-Path -LiteralPath $exe) { (Get-Item -LiteralPath $exe).LastWriteTimeUtc } else { [datetime]::MinValue }

# Existing VS2022 toolchain and compiler configuration owned by the repository.
Push-Location -LiteralPath $repo
try { Invoke-ExitChecked 'cmd.exe' @('/d','/c',$build) }
finally { Pop-Location }
if (-not (Test-Path -LiteralPath $exe)) { throw "BINARY_MISSING=$exe" }
$afterTime = (Get-Item -LiteralPath $exe).LastWriteTimeUtc
if ($afterTime -le $beforeTime) { throw 'STALE_BINARY_DETECTED=1 (compile command did not update executor)' }
New-Item -ItemType Directory -Force -Path $EvidenceDir,$dumpDir | Out-Null
# Never reuse stale tensor dumps for a current numerical certificate.
Get-ChildItem -LiteralPath $dumpDir -Filter 'op_*.bin' -File -ErrorAction SilentlyContinue | Remove-Item -Force
$env:RAWRXD_PARITY_DIR = $dumpDir
Write-Host 'REAL_GGUF_RUN=START'
$runExit = RunNativeCapture $exe @($GGUF,$EvidenceDir) $runLog
$txt = Get-Content -LiteralPath $runLog -Raw
$v = ReadGate $txt 'IR_OPS_VISITED'
$x = ReadGate $txt 'IR_OPS_EXECUTED'
$s = ReadGate $txt 'IR_OPS_SKIPPED'
$f = ReadGate $txt 'LOGITS_FINITE'
$p = ReadGate $txt 'PREDICTED_TOKEN'
$verdict = ReadGate $txt 'VERDICT'
$structure = ($v -eq '300' -and $x -eq '300' -and $s -eq '0' -and $f -eq '1')
$parity = ($structure -and $p -eq '93633')

# Recheck packed Q6_K LM-head consistency with the NEW hidden state, not old evidence.
$auditExit = -1
$lmArgmax = 'UNVERIFIED'
$lmClose = 'UNVERIFIED'
$hidden = Join-Path $dumpDir 'op_298.bin'
$logits = Join-Path $dumpDir 'op_299.bin'
if ((Test-Path -LiteralPath $audit) -and (Test-Path -LiteralPath $hidden) -and `
    (Test-Path -LiteralPath $logits) -and (Get-Item -LiteralPath $hidden).Length -eq 8192 -and `
    (Get-Item -LiteralPath $logits).Length -eq 409600) {
    $auditExit = RunNativeCapture $audit @($GGUF,$hidden,$logits) $auditLog
    $auditText = Get-Content -LiteralPath $auditLog -Raw
    $lmArgmax = ReadGate $auditText 'LMHEAD_ARGMAX_MATCH'
    $lmClose = ReadGate $auditText 'LMHEAD_NUMERIC_CLOSE'
} else {
    Set-Content -LiteralPath $auditLog -Value 'AUDIT_NOT_RUN=1' -Encoding utf8
}
$items = @(
    "BRANCH=$actualBranch",
    "GIT_HEAD_BEFORE_RUN=$((& git -C $repo rev-parse HEAD).Trim())",
    "EXECUTOR_SOURCE_SHA256=$sourceHash",
    "GGUF_SIZE=$modelBytes",
    "RUN_EXIT=$runExit",
    "IR_OPS_VISITED=$v",
    "IR_OPS_EXECUTED=$x",
    "IR_OPS_SKIPPED=$s",
    "LOGITS_FINITE=$f",
    "PREDICTED_TOKEN=$p",
    'EXPECTED_TOKEN=93633',
    "STRUCTURAL_GATE=$(if($structure){'PASS'}else{'FAIL'})",
    "TARGET_TOKEN_MATCH=$(if($parity){1}else{0})",
    "LMHEAD_AUDIT_EXIT=$auditExit",
    "LMHEAD_ARGMAX_MATCH=$lmArgmax",
    "LMHEAD_NUMERIC_CLOSE=$lmClose",
    'INDEPENDENT_MODEL_REFERENCE=NOT_SUPPLIED',
    "EXECUTOR_VERDICT=$verdict"
)
$items | Set-Content -LiteralPath $summary -Encoding utf8
Get-Content -LiteralPath $summary
if ($Push) {
    # Deliberate allowlist: no recursive add and no changes to SaaSEncryptionSecurity.
    $allowed = @(
      'tools/rawrxd_modelgenie_ir_executor.cpp',
      'tools/parity_frontier/fix_dispatch_order.py',
      'tools/parity_frontier/test_dispatch_order.py',
      'tools/parity_frontier/verify_dispatch_order.ps1',
      'tools/parity_frontier/README_DISPATCH_ORDER.md',
      'evidence/NUGVERSE_ESTIMATOR_001/parity_dispatch_order_run.log',
      'evidence/NUGVERSE_ESTIMATOR_001/parity_dispatch_order_summary.txt',
      'evidence/NUGVERSE_ESTIMATOR_001/parity_dispatch_order_q6_audit.log'
    )
    Invoke-ExitChecked 'git' (@('-C',$repo,'add','--') + $allowed)
    $staged = @(& git -C $repo diff --cached --name-only)
    $notAllowed = @($staged | Where-Object { $allowed -notcontains $_ })
    if ($notAllowed.Count -gt 0 -or @($staged | Where-Object { $_ -like 'OrganizedPiProject/*' }).Count -gt 0) {
        throw 'REFUSE_UNAPPROVED_STAGE=1'
    }
    if ($staged.Count -gt 0) {
        Invoke-ExitChecked 'git' @('-C',$repo,'commit','-m','fix(modelgenie): sequence TopK/MoE activation allocation and record measured execution')
    }
    Invoke-ExitChecked 'git' @('-C',$repo,'push','origin',"HEAD:refs/heads/$branch")
    Write-Host 'PUSH_COMPLETED=1'
}
if (-not $structure -or $runExit -ne 0 -or $auditExit -ne 0 -or $lmArgmax -ne '1' -or $lmClose -ne '1' -or -not $parity) {
    throw 'FULL_PARITY_NOT_YET_VERIFIED: evidence saved (and published only if -Push requested)'
}
Write-Host 'TOKEN_GATE=PASS (independent model-reference equivalence requires its own check)'
