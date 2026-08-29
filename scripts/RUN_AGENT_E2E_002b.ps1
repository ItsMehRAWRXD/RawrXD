<#
.SYNOPSIS
  AGENT-E2E-002b — GGUF-directed autonomous repair (no demo-break, no scripted runtime).

.DESCRIPTION
  Authority model: TinyLlama Q4_K_M (SHA256 recorded).
  Inference: Deep2 via RawrXD-Agentic / ide_agent_loop_cert --mode deep2.
  Forbidden: demo-break prepass, canned TOOL_CALL, FA-auto tip as pass/fail.
#>
param(
    [string]$Model = "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [string]$BuildBin = "F:\~dev\rawrxd\build-win32ide-fresh\bin",
    [string]$EvidenceRoot = "F:\~dev\rawrxd\evidence\AGENT_E2E_002b",
    [string]$FixtureRoot = "F:\~dev\rawrxd\fixtures\agent_e2e_002b",
    [string[]]$Cases = @("01_compile", "04_logic_bug"),
    [int]$MaxSteps = 12,
    [int]$MaxTokens = 512
)

$ErrorActionPreference = "Stop"
$exeAgent = Join-Path $BuildBin "RawrXD-Agentic.exe"
$exeCert  = Join-Path $BuildBin "ide_agent_loop_cert.exe"
if (-not (Test-Path -LiteralPath $exeAgent)) { throw "missing $exeAgent" }
if (-not (Test-Path -LiteralPath $Model)) { throw "missing $Model" }

New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$modelSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Model).Hash.ToLowerInvariant()

$caseMeta = @{
    "01_compile" = @{
        Prompt = @"
Fix the compile error in main.c so the program builds and prints hello from b01.
First line of your reply MUST be a TOOL_CALL.
Start with: TOOL_CALL: read_file {"path":"main.c"}
Then edit with replace_in_file (search/replace), build with run_command, and run the exe.
No markdown code fences. No canned repairs.
"@
        Expected = "hello from b01"
        Source = "main.c"
        ExeName = "b01.exe"
    }
    "04_logic_bug" = @{
        Prompt = @"
Fix the bug so add(2,3) returns 5, then print hello from b04.
First line of your reply MUST be a TOOL_CALL.
Start with: TOOL_CALL: read_file {"path":"main.c"}
Then edit with replace_in_file (search/replace), build with run_command, and run.
No markdown code fences. No canned repairs.
"@
        Expected = "hello from b04"
        Source = "main.c"
        ExeName = "b04.exe"
    }
}

function Copy-Fixture([string]$name, [string]$dest) {
    if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    $src = Join-Path $FixtureRoot $name
    Copy-Item -Path (Join-Path $src '*') -Destination $dest -Recurse -Force
}

function Invoke-IndependentProof([string]$work, [string]$exeName, [string]$expected) {
    $buildLog = Join-Path $work "_proof_build.txt"
    $runLog = Join-Path $work "_proof_run.txt"
    $buildDir = Join-Path $work "_proof_build"
    New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
    $cmake = @"
@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "$work"
cmake -S . -B "$buildDir" -G Ninja -DCMAKE_BUILD_TYPE=Release > "$buildLog" 2>&1
if errorlevel 1 exit /b 1
cmake --build "$buildDir" >> "$buildLog" 2>&1
if errorlevel 1 exit /b 1
exit /b 0
"@
    $bat = Join-Path $work "_proof_build.bat"
    Set-Content -LiteralPath $bat -Value $cmake -Encoding ASCII
    cmd /c $bat
    $buildExit = $LASTEXITCODE
    $stdout = ""
    $runExit = -1
    $exePath = Get-ChildItem -LiteralPath $buildDir -Recurse -Filter $exeName -EA SilentlyContinue | Select-Object -First 1
    if (-not $exePath) {
        $exePath = Get-ChildItem -LiteralPath $buildDir -Recurse -Filter "*.exe" -EA SilentlyContinue | Select-Object -First 1
    }
    if ($exePath -and $buildExit -eq 0) {
        $p = Start-Process -FilePath $exePath.FullName -WorkingDirectory $work -Wait -PassThru -NoNewWindow `
            -RedirectStandardOutput $runLog -RedirectStandardError (Join-Path $work "_proof_run.err.txt")
        $runExit = $p.ExitCode
        if (Test-Path -LiteralPath $runLog) { $stdout = (Get-Content -LiteralPath $runLog -Raw).Trim() }
    } else {
        Set-Content -LiteralPath $runLog -Value "NO_EXE" -Encoding ASCII
        $stdout = "NO_EXE"
    }
    [pscustomobject]@{
        build_exit = $buildExit
        run_exit = $runExit
        stdout = $stdout
        expected = $expected
        pass = ($buildExit -eq 0 -and $runExit -eq 0 -and $stdout -eq $expected)
    }
}

$suite = [ordered]@{
    id = "AGENT-E2E-002b"
    started_utc = (Get-Date).ToUniversalTime().ToString("o")
    model_path = $Model
    model_sha256 = $modelSha
    demo_break = $false
    scripted_runtime = $false
    fa_auto_authority = $false
    hexmag_status = "frozen_out_of_chase"
    deep2_inference = "authority"
    cases = @()
}

foreach ($name in $Cases) {
    if (-not $caseMeta.ContainsKey($name)) { throw "unknown case $name" }
    $meta = $caseMeta[$name]
    $caseEv = Join-Path $EvidenceRoot $name
    $work = Join-Path $EvidenceRoot ("work_" + $name)
    New-Item -ItemType Directory -Force -Path $caseEv | Out-Null
    Copy-Fixture $name $work

    $before = Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $work $meta.Source)
    $promptPath = Join-Path $caseEv "prompt.txt"
    Set-Content -LiteralPath $promptPath -Value $meta.Prompt -Encoding utf8
    $taskArg = ($meta.Prompt -replace "`r`n", " " -replace "`n", " ").Trim()

    $env:RAWRXD_GREEDY = "1"
    Remove-Item Env:RAWRXD_DEEP2_LAYER_PROBE -EA SilentlyContinue
    Remove-Item Env:RAWRXD_B3_TRACE -EA SilentlyContinue
    Remove-Item Env:RAWRXD_LINEARW_TRACE -EA SilentlyContinue
    Remove-Item Env:RAWRXD_KERNEL_TRACE -EA SilentlyContinue

    $console = Join-Path $caseEv "agent.console.txt"
    $bat = Join-Path $caseEv "run_agent.bat"
    # Write task to a file to avoid bat quoting hell; agentic requires --task so pass via delayed expansion from file
    $taskFile = Join-Path $caseEv "task_oneline.txt"
    Set-Content -LiteralPath $taskFile -Value $taskArg -Encoding ascii
    @"
@echo off
set RAWRXD_GREEDY=1
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "$work"
set /p TASK=<"$taskFile"
"$exeAgent" --model "$Model" --workspace "$work" --max-steps $MaxSteps --max-tokens $MaxTokens --no-stream --task "%TASK%" > "$console" 2>&1
echo AGENT_EXIT=%ERRORLEVEL%>> "$console"
set AGENT_EC=%ERRORLEVEL%
exit /b %AGENT_EC%
"@ | Set-Content -LiteralPath $bat -Encoding ASCII

    $sw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c $bat
    $agentExit = $LASTEXITCODE
    # Prefer AGENT_EXIT= from console if bat propagation failed historically
    if (Test-Path -LiteralPath $console) {
        $m = Select-String -Path $console -Pattern '^AGENT_EXIT=(-?\d+)\s*$' | Select-Object -Last 1
        if ($m) { $agentExit = [int]$m.Matches[0].Groups[1].Value }
    }    $elapsed = $sw.ElapsedMilliseconds

    if (Test-Path -LiteralPath (Join-Path $work "RAWRXD_AGENT_TRANSCRIPT.json")) {
        Copy-Item (Join-Path $work "RAWRXD_AGENT_TRANSCRIPT.json") (Join-Path $caseEv "RAWRXD_AGENT_TRANSCRIPT.json") -Force
    }

    $afterPath = Join-Path $work $meta.Source
    $after = Get-FileHash -Algorithm SHA256 -LiteralPath $afterPath
    $sourceMutated = ($before.Hash -ne $after.Hash)

    # workspace snapshots
    $wb = Join-Path $caseEv "workspace_before"
    $wa = Join-Path $caseEv "workspace_after"
    if (Test-Path $wb) { Remove-Item $wb -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $wb | Out-Null
    Copy-Item -Path (Join-Path (Join-Path $FixtureRoot $name) '*') -Destination $wb -Recurse -Force
    if (Test-Path $wa) { Remove-Item $wa -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $wa | Out-Null
    Copy-Item -Path (Join-Path $work '*') -Destination $wa -Recurse -Force -ErrorAction SilentlyContinue

    $proof = Invoke-IndependentProof -work $work -exeName $meta.ExeName -expected $meta.Expected
    Copy-Item (Join-Path $work "_proof_build.txt") (Join-Path $caseEv "proof_build.txt") -Force -EA SilentlyContinue
    Copy-Item (Join-Path $work "_proof_run.txt") (Join-Path $caseEv "proof_run.txt") -Force -EA SilentlyContinue

    $transcriptHasTools = $false
    $tpath = Join-Path $caseEv "RAWRXD_AGENT_TRANSCRIPT.json"
    if (Test-Path $tpath) {
        $tj = Get-Content -LiteralPath $tpath -Raw
        $transcriptHasTools = $tj -match '"tool_calls"\s*:\s*\[\s*\{'
    }

    $goalSatisfied = [bool]($proof.pass -and $sourceMutated -and $transcriptHasTools -and ($agentExit -eq 0))
    # Hard fail substitutions
    $scripted = $false
    $demoBreak = $false
    if ((Get-Content $console -Raw -EA SilentlyContinue) -match 'scripted_tool_runtime|INTENTIONAL BREAK|demo.?break') {
        $goalSatisfied = $false
    }

    $summary = @"
# AGENT-E2E-002b / $name

agent_exit=$agentExit
elapsed_ms=$elapsed
demo_break=$demoBreak
scripted_runtime=$scripted
model=$Model
model_sha256=$modelSha
source_before_sha256=$($before.Hash.ToLowerInvariant())
source_after_sha256=$($after.Hash.ToLowerInvariant())
source_mutated=$sourceMutated
transcript_has_tool_calls=$transcriptHasTools
build_exit=$($proof.build_exit)
run_exit=$($proof.run_exit)
stdout=$($proof.stdout)
expected=$($proof.expected)
goal.satisfied=$goalSatisfied
PASS=$goalSatisfied
"@
    Set-Content -LiteralPath (Join-Path $caseEv "RUN_SUMMARY.txt") -Value $summary -Encoding utf8

    $suite.cases += [ordered]@{
        name = $name
        agent_exit = $agentExit
        elapsed_ms = $elapsed
        source_mutated = $sourceMutated
        transcript_has_tool_calls = $transcriptHasTools
        build_exit = $proof.build_exit
        run_exit = $proof.run_exit
        stdout = $proof.stdout
        expected = $proof.expected
        goal_satisfied = $goalSatisfied
        PASS = $goalSatisfied
    }
}

$suite.finished_utc = (Get-Date).ToUniversalTime().ToString("o")
$suite.any_pass = [bool](@($suite.cases | Where-Object { $_.PASS }).Count -gt 0)
$suite.all_pass = [bool](@($suite.cases | Where-Object { -not $_.PASS }).Count -eq 0)
$suite | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $EvidenceRoot "SUITE_RESULTS.json") -Encoding utf8

Write-Host "AGENT-E2E-002b suite written -> $EvidenceRoot\SUITE_RESULTS.json"
Write-Host "all_pass=$($suite.all_pass) any_pass=$($suite.any_pass)"
if (-not $suite.all_pass) { exit 2 }
exit 0
