<#
.SYNOPSIS
  AGENT-MULTIERROR-001 - model-driven multi-file repair (no scripted patches).
#>
param(
    [string]$Model = "F:\~dev\tinyllama_fresh.gguf",
    [string]$RepoRoot = "F:\~dev\rawrxd",
    [string]$AgentExe = "",
    [int]$MaxSteps = 24,
    [int]$MaxTokens = 2048,
    [switch]$SkipSecondRun
)

$ErrorActionPreference = "Stop"
$Evidence = Join-Path $RepoRoot "evidence\AGENT_MULTIERROR_001"
$FixtureSrc = Join-Path $RepoRoot "fixtures\agent_multierror_calc"
if (-not $AgentExe) {
    $AgentExe = Join-Path $RepoRoot "build-ninja\bin\RawrXD-Agentic.exe"
}

New-Item -ItemType Directory -Force -Path $Evidence | Out-Null

function Get-Sha256([string]$Path) {
    if (-not (Test-Path $Path)) { return "MISSING" }
    return (Get-FileHash -Algorithm SHA256 -Path $Path).Hash
}

function Seed-Workspace([string]$Dest) {
    if (Test-Path $Dest) { Remove-Item -Recurse -Force $Dest }
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    Copy-Item -Recurse -Force (Join-Path $FixtureSrc "*") $Dest
}

function Invoke-Verify([string]$Work) {
    Push-Location $Work
    try {
        $exe = Join-Path $Work "calc_ok.exe"
        if (-not (Test-Path $exe)) {
            return @{ ok = $false; stdout = ""; reason = "calc_ok.exe missing"; exit = -1 }
        }
        $out = & $exe 2>&1 | Out-String
        $code = $LASTEXITCODE
        $ok = ($code -eq 0) -and ($out -match "calc_ok 14")
        return @{
            ok = $ok
            stdout = $out.Trim()
            exit = $code
            reason = $(if ($ok) { "PASS" } else { "stdout/exit mismatch" })
        }
    } finally {
        Pop-Location
    }
}

function Invoke-AgentRun([string]$Label, [string]$Work) {
    $runDir = Join-Path $Evidence $Label
    New-Item -ItemType Directory -Force -Path $runDir | Out-Null
    Seed-Workspace $Work

    $task = 'Fix all compile and runtime defects in this workspace so that: (1) cl /nologo /EHsc /std:c++20 add.cpp mul.cpp main.cpp /Fe:calc_ok.exe succeeds (2) calc_ok.exe prints exactly: calc_ok 14 (3) calc_ok.exe exits 0. Inspect sources and build failures yourself. Use tools to read, edit, build, and run. Prefer run_command with cl, then run_command with cmd /c calc_ok.exe. When finished, briefly report what you fixed.'
    Set-Content -Encoding ascii -Path (Join-Path $runDir "prompt.txt") -Value $task
    Copy-Item -Recurse -Force $Work (Join-Path $runDir "workspace_before")

    $vs = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path $vs)) {
        $vs = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
    }

    $agentLog = Join-Path $runDir "agent.console.txt"
    $bat = Join-Path $runDir "run_agent.bat"
    $taskEsc = $task.Replace('"', '\"')
    @(
        "@echo off",
        "call `"$vs`" >nul",
        "cd /d `"$Work`"",
        "`"$AgentExe`" --model `"$Model`" --workspace `"$Work`" --max-steps $MaxSteps --max-tokens $MaxTokens --no-stream --task `"$taskEsc`""
    ) | Set-Content -Encoding ascii $bat

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    cmd /c "`"$bat`" > `"$agentLog`" 2>&1"
    $agentExit = $LASTEXITCODE
    $sw.Stop()

    $transcriptSrc = Join-Path $Work "RAWRXD_AGENT_TRANSCRIPT.json"
    if (Test-Path $transcriptSrc) {
        Copy-Item -Force $transcriptSrc (Join-Path $runDir "RAWRXD_AGENT_TRANSCRIPT.json")
    }
    Copy-Item -Recurse -Force $Work (Join-Path $runDir "workspace_after")

    $verify = Invoke-Verify $Work
    ($verify | ConvertTo-Json) | Set-Content -Encoding utf8 (Join-Path $runDir "verify.json")

    $toolCalls = 0
    $transcriptPath = Join-Path $runDir "RAWRXD_AGENT_TRANSCRIPT.json"
    if (Test-Path $transcriptPath) {
        try {
            $tj = Get-Content -Raw $transcriptPath | ConvertFrom-Json
            foreach ($s in $tj.steps) {
                if ($s.tool_calls) { $toolCalls += @($s.tool_calls).Count }
            }
        } catch {}
    }

    $result = [ordered]@{
        label              = $Label
        agent_exit         = $agentExit
        elapsed_ms         = $sw.ElapsedMilliseconds
        model_path         = $Model
        model_sha256       = Get-Sha256 $Model
        agent_exe          = $AgentExe
        agent_exe_sha256   = Get-Sha256 $AgentExe
        tool_calls_total   = $toolCalls
        model_used_tools   = ($toolCalls -gt 0)
        verify_ok          = [bool]$verify.ok
        verify_stdout      = $verify.stdout
        verify_reason      = $verify.reason
        scripted_patches   = $false
    }
    ($result | ConvertTo-Json) | Set-Content -Encoding utf8 (Join-Path $runDir "run_summary.json")
    return $result
}

Write-Host "AGENT-MULTIERROR-001"
Write-Host "model=$Model"
Write-Host "agent=$AgentExe"

if (-not (Test-Path $AgentExe)) { throw "RawrXD-Agentic.exe missing: $AgentExe - rebuild it first" }
if (-not (Test-Path $Model)) { throw "Model missing: $Model" }
if (-not (Test-Path $FixtureSrc)) { throw "Fixture missing: $FixtureSrc" }

$work1 = Join-Path $env:TEMP "rawrxd_agent_multierror_run1"
$r1 = Invoke-AgentRun "run1" $work1

$r2 = $null
if (-not $SkipSecondRun) {
    $work2 = Join-Path $env:TEMP "rawrxd_agent_multierror_run2"
    $r2 = Invoke-AgentRun "run2" $work2
}

$pass = $r1.verify_ok -and $r1.model_used_tools -and (-not $r1.scripted_patches)
if ($r2) {
    $pass = $pass -and $r2.verify_ok -and $r2.model_used_tools
}

$lines = @()
$lines += "AGENT-MULTIERROR-001"
$lines += "authority=NOT_CERTIFIED"
$lines += "baseline_commit=d7651c5f0"
$lines += "date=$(Get-Date -Format o)"
$lines += "model=$Model"
$lines += "model_sha256=$(Get-Sha256 $Model)"
$lines += "agent_exe=$AgentExe"
$lines += "agent_sha256=$(Get-Sha256 $AgentExe)"
$lines += "scripted_action_selection=NO"
$lines += "ollama_daemon=NONE"
$lines += ""
$lines += "RUN1:"
$lines += "  tool_calls=$($r1.tool_calls_total)"
$lines += "  model_used_tools=$($r1.model_used_tools)"
$lines += "  verify_ok=$($r1.verify_ok)"
$lines += "  stdout=$($r1.verify_stdout)"
$lines += "  agent_exit=$($r1.agent_exit)"
$lines += "  elapsed_ms=$($r1.elapsed_ms)"
$lines += ""
if ($r2) {
    $lines += "RUN2 (fresh fixture copy):"
    $lines += "  tool_calls=$($r2.tool_calls_total)"
    $lines += "  model_used_tools=$($r2.model_used_tools)"
    $lines += "  verify_ok=$($r2.verify_ok)"
    $lines += "  stdout=$($r2.verify_stdout)"
    $lines += "  agent_exit=$($r2.agent_exit)"
    $lines += "  elapsed_ms=$($r2.elapsed_ms)"
} else {
    $lines += "RUN2=SKIPPED"
}
$lines += ""
$lines += "PASS_CONDITION=model independently repairs multiple unrelated compile/runtime defects from build feedback, reaches clean build, executes calc_ok 14, reproduces from fresh fixture without scripted patch knowledge."
$lines += ""
if ($pass) { $lines += "VERDICT=CANDIDATE_PASS" } else { $lines += "VERDICT=INCOMPLETE_OR_FAIL" }

$verdictPath = Join-Path $Evidence "AGENT_MULTIERROR_VERDICT.txt"
$lines | Set-Content -Encoding utf8 $verdictPath
$lines | ForEach-Object { Write-Host $_ }

if ($pass) { exit 0 } else { exit 2 }
