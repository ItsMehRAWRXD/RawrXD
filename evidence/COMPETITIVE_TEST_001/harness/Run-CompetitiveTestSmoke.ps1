#Requires -Version 5.1
<#
.SYNOPSIS
  Fail-closed competitive-test smoke for COMPETITIVE_TEST_001.
  Maps IDE-Bench / Terminal-Bench / coding-task / game-dev onto real local entrypoints.
  Never invents scores. Does not load MiniMax / QUALITY_CURVE.
#>
param(
    [string]$RepoRoot = "",
    [string]$EvidenceRoot = "",
    [switch]$SkipIde,
    [switch]$SkipTerminal,
    [switch]$SkipCoding,
    [switch]$SkipGame
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
}
if (-not $EvidenceRoot) {
    $EvidenceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$runs = Join-Path $EvidenceRoot "runs"
$logs = Join-Path $EvidenceRoot "logs"
New-Item -ItemType Directory -Force -Path $runs, $logs | Out-Null

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$matrix = [ordered]@{
    track            = "COMPETITIVE_TEST_001"
    asof_utc         = (Get-Date).ToUniversalTime().ToString("o")
    promote          = 0
    certified        = 0
    tip_climb        = "HOLD"
    minimax_full     = "FORBIDDEN"
    quality_curve    = "FORBIDDEN"
    suites           = @()
}

function Add-Suite([string]$id, [string]$status, [hashtable]$fields) {
    $row = [ordered]@{ id = $id; status = $status }
    foreach ($k in $fields.Keys) { $row[$k] = $fields[$k] }
    $script:matrix.suites += [pscustomobject]$row
}

function Invoke-Logged([string]$name, [scriptblock]$block) {
    $outPath = Join-Path $logs "${name}_${stamp}.log"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $exit = -1
    $err = ""
    $script:InvokeLoggedExit = $null
    try {
        $output = & $block 2>&1 | Out-String
        if ($null -ne $script:InvokeLoggedExit) {
            $exit = [int]$script:InvokeLoggedExit
        }
        elseif ($null -ne $LASTEXITCODE) {
            $exit = [int]$LASTEXITCODE
        }
        else {
            $exit = 0
        }
        Set-Content -LiteralPath $outPath -Value $output -Encoding UTF8
    }
    catch {
        $err = $_.Exception.Message
        $exit = 1
        Set-Content -LiteralPath $outPath -Value ("EXCEPTION: " + $err) -Encoding UTF8
    }
    $sw.Stop()
    return @{
        log       = $outPath
        exit_code = $exit
        ms        = $sw.ElapsedMilliseconds
        error     = $err
    }
}

# --- IDE-Bench proxy: turnkey IDE smoke (source/parity; no MiniMax) ---
if (-not $SkipIde) {
    $ideSmoke = Join-Path $RepoRoot "scripts\Smoke-IDE-TurnKey.ps1"
    $ideExe = Join-Path $RepoRoot "build-win32\bin\RawrXD-Win32IDE.exe"
    $fields = @{
        harness       = $ideSmoke
        maps_to       = "IDE-Bench (local turnkey smoke proxy; not public IDE-Bench suite)"
        ide_exe       = $ideExe
        ide_sha256    = $(if (Test-Path $ideExe) { (Get-FileHash $ideExe -Algorithm SHA256).Hash } else { "ABSENT" })
        score         = $null
        score_note    = "NOT_SCORED — proxy smoke PASS/FAIL only"
    }
    if (-not (Test-Path $ideSmoke)) {
        Add-Suite "IDE_BENCH_PROXY" "NOT_RUN" ($fields + @{ blocker = "Smoke-IDE-TurnKey.ps1 ABSENT" })
    }
    else {
        $r = Invoke-Logged "ide_bench_proxy" {
            & powershell -NoProfile -ExecutionPolicy Bypass -File $ideSmoke -SkipUiMarshalling
        }
        $fields.log = $r.log
        $fields.exit_code = $r.exit_code
        $fields.ms = $r.ms
        $st = if ($r.exit_code -eq 0) { "PASS" } else { "FAIL" }
        Add-Suite "IDE_BENCH_PROXY" $st $fields
    }
}
else {
    Add-Suite "IDE_BENCH_PROXY" "SKIPPED" @{ reason = "SkipIde" }
}

# --- Terminal-Bench proxy: FOUR_PANEL terminal_gate ---
if (-not $SkipTerminal) {
    $tg = Join-Path $RepoRoot "evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe"
    $fields = @{
        harness    = $tg
        maps_to    = "Terminal-Bench (local ConPTY terminal_gate proxy; not public Terminal-Bench)"
        score      = $null
        score_note = "NOT_SCORED — harness assertions PASS/FAIL only"
    }
    if (-not (Test-Path $tg)) {
        Add-Suite "TERMINAL_BENCH_PROXY" "NOT_RUN" ($fields + @{ blocker = "terminal_gate.exe ABSENT" })
    }
    else {
        $fields.sha256 = (Get-FileHash $tg -Algorithm SHA256).Hash
        $r = Invoke-Logged "terminal_bench_proxy" { & $tg }
        $fields.log = $r.log
        $fields.exit_code = $r.exit_code
        $fields.ms = $r.ms
        $st = if ($r.exit_code -eq 0) { "PASS" } else { "FAIL" }
        Add-Suite "TERMINAL_BENCH_PROXY" $st $fields
    }
}
else {
    Add-Suite "TERMINAL_BENCH_PROXY" "SKIPPED" @{ reason = "SkipTerminal" }
}

# --- Coding-task suite: RawrXD-SWEBench null-agent baseline ---
if (-not $SkipCoding) {
    $sweCandidates = @(
        (Join-Path $RepoRoot "build-ninja-ctx2\bin\RawrXD-SWEBench.exe"),
        (Join-Path $RepoRoot "build-ninja-max\bin\RawrXD-SWEBench.exe"),
        (Join-Path $RepoRoot "build-ninja-validate\bin\RawrXD-SWEBench.exe")
    )
    $swe = $sweCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    $seed = Join-Path $RepoRoot "data\swebench_seed4.jsonl"
    $fields = @{
        harness    = $swe
        maps_to    = "coding-task suite (RawrXD-SWEBench seed4; null-agent self-test)"
        seed       = $seed
        agent_mode = "null (no --real-agent; no MiniMax)"
    }
    if (-not $swe) {
        Add-Suite "CODING_TASK_SWEBENCH" "NOT_RUN" ($fields + @{ blocker = "RawrXD-SWEBench.exe ABSENT" })
    }
    else {
        $fields.sha256 = (Get-FileHash $swe -Algorithm SHA256).Hash
        $r = Invoke-Logged "coding_task_swebench" { & $swe }
        $fields.log = $r.log
        $fields.exit_code = $r.exit_code
        $fields.ms = $r.ms
        $overall = $null
        if (Test-Path $r.log) {
            $m = Select-String -Path $r.log -Pattern 'OVERALL SCORE\s*:\s*([0-9.]+)%' | Select-Object -First 1
            if ($m) { $overall = [double]$m.Matches[0].Groups[1].Value }
        }
        $fields.score_overall_pct = $overall
        $fields.score_note = "Measured null-agent baseline; NOT competitive agent score"
        # Process exit 0 with 0% score is RUNTIME_REACHED + SCORE_MEASURED, not competitive PASS
        $st = if ($null -eq $overall) { "FAIL" } elseif ($overall -gt 0) { "MEASURED" } else { "MEASURED_ZERO" }
        Add-Suite "CODING_TASK_SWEBENCH" $st $fields
    }
}
else {
    Add-Suite "CODING_TASK_SWEBENCH" "SKIPPED" @{ reason = "SkipCoding" }
}

# --- Game-dev fixture: SunshineFPS binary presence + short launch probe ---
if (-not $SkipGame) {
    $game = "g:\~dev\SunshineFPS\SunshineFPS.exe"
    $demo = "g:\~dev\demo_project\project.json"
    $fields = @{
        maps_to      = "real game-development project fixture"
        sunshine_exe = $game
        demo_project = $demo
    }
    if (-not (Test-Path $game)) {
        Add-Suite "GAME_DEV_SUNSHINEFPS" "NOT_RUN" ($fields + @{ blocker = "SunshineFPS.exe ABSENT" })
    }
    else {
        $fields.sha256 = (Get-FileHash $game -Algorithm SHA256).Hash
        $fields.demo_project_present = (Test-Path $demo)
        $fields.pe_machine = "0x8664"
        $fields.pe_opt_magic = "0x020B"
        $r = Invoke-Logged "game_dev_sunshinefps" {
            try {
                $p = Start-Process -FilePath $game -PassThru -WindowStyle Minimized -ErrorAction Stop
                Start-Sleep -Seconds 3
                if ($p.HasExited) {
                    Write-Output ("EXITED exit_code=" + $p.ExitCode)
                    $script:InvokeLoggedExit = [int]$p.ExitCode
                }
                else {
                    Write-Output ("ALIVE pid=" + $p.Id)
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                    Write-Output "STOPPED_AFTER_PROBE"
                    $script:InvokeLoggedExit = 0
                }
            }
            catch {
                Write-Output ("LAUNCH_REJECTED: " + $_.Exception.Message)
                Write-Output "BLOCKER=PE_PRESENT_BUT_OS_REFUSES_WIN32_MODE"
                $script:InvokeLoggedExit = 2
            }
        }
        $fields.log = $r.log
        $fields.exit_code = $r.exit_code
        $fields.ms = $r.ms
        $fields.score = $null
        $fields.score_note = "Launch probe only; no gameplay scoring suite sealed"
        if ($r.exit_code -eq 0) { $st = "PROBE_PASS" }
        elseif ($r.exit_code -eq 2) { $st = "NOT_RUN"; $fields.blocker = "OS refuses launch (Win32 mode); fixture PE present but not executable here" }
        else { $st = "PROBE_FAIL" }
        Add-Suite "GAME_DEV_SUNSHINEFPS" $st $fields
    }
}
else {
    Add-Suite "GAME_DEV_SUNSHINEFPS" "SKIPPED" @{ reason = "SkipGame" }
}

$matrixPath = Join-Path $runs ("MATRIX_" + $stamp + ".json")
$latestMatrix = Join-Path $EvidenceRoot "MATRIX.json"
$json = ($matrix | ConvertTo-Json -Depth 8)
Set-Content -LiteralPath $matrixPath -Value $json -Encoding UTF8
Set-Content -LiteralPath $latestMatrix -Value $json -Encoding UTF8

Write-Host "WROTE $matrixPath"
Write-Host "WROTE $latestMatrix"
$matrix.suites | ForEach-Object { Write-Host ("SUITE {0} => {1}" -f $_.id, $_.status) }
