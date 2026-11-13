# Run-CompetitiveBench.ps1
# Minimal competitive harness stubs: invoke real CLI/IDE/terminal entrypoints.
# No fake scores. PROMOTE=0. NOT_RUN != PASS.
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$EvidenceDir = $null
)

$ErrorActionPreference = 'Continue'
if (-not $EvidenceDir) {
    $EvidenceDir = Join-Path $RepoRoot 'evidence\COMPETITIVE_BENCH_001'
}
$logs = Join-Path $EvidenceDir 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null

function Get-Sha256([string]$p) {
    if (Test-Path $p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash } else { 'MISSING' }
}

function Invoke-Tracked {
    param(
        [string]$Suite,
        [string]$Exe,
        # Do not name this $Args — conflicts with PowerShell automatic $args.
        [string[]]$ArgList = @(),
        [int]$TimeoutSec = 120,
        [string]$WorkDir = $null
    )
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outPath = Join-Path $logs "${Suite}_${stamp}_out.txt"
    $errPath = Join-Path $logs "${Suite}_${stamp}_err.txt"
    $meta = [ordered]@{
        SUITE          = $Suite
        COMMAND        = if ($ArgList.Count) { "$Exe $($ArgList -join ' ')" } else { $Exe }
        EXE_PATH       = $Exe
        EXE_SHA256     = (Get-Sha256 $Exe)
        EXE_EXISTS     = (Test-Path $Exe)
        STARTED_UTC    = (Get-Date).ToUniversalTime().ToString('o')
        PROMOTE        = 0
    }
    if (-not (Test-Path $Exe)) {
        $meta.RESULT = 'NOT_RUN'
        $meta.REASON = 'EXE_ABSENT'
        $meta | ConvertTo-Json | Set-Content (Join-Path $logs "${Suite}_${stamp}_meta.json") -Encoding ASCII
        return $meta
    }
    $wd = if ($WorkDir) { $WorkDir } else { Split-Path $Exe }
    # Start-Process rejects -ArgumentList @() / $null; omit when no args.
    $sp = @{
        FilePath               = $Exe
        WorkingDirectory       = $wd
        NoNewWindow            = $true
        PassThru               = $true
        RedirectStandardOutput = $outPath
        RedirectStandardError  = $errPath
    }
    if ($ArgList -and $ArgList.Count -gt 0) { $sp.ArgumentList = $ArgList }
    $p = Start-Process @sp
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        $meta.RESULT = 'FAIL'
        $meta.REASON = 'TIMEOUT'
        $meta.EXIT_CODE = -1
    } else {
        # Start-Process PassThru can leave ExitCode null until Refresh; poll briefly.
        $exitCode = $null
        for ($i = 0; $i -lt 20 -and $null -eq $exitCode; $i++) {
            $p.Refresh()
            $exitCode = $p.ExitCode
            if ($null -eq $exitCode) { Start-Sleep -Milliseconds 25 }
        }
        $meta.EXIT_CODE = $exitCode
        if ($null -eq $exitCode) {
            $meta.RESULT = 'EXIT_UNKNOWN'
            $meta.NOTE = 'ExitCode stayed null after WaitForExit+Refresh; use STDOUT_LOG for content disposition. COMPETITIVE_PASS=0.'
        } else {
            # EXIT=0 is process success only — not a competitive leaderboard PASS.
            $meta.RESULT = if ($exitCode -eq 0) { 'EXIT_0' } else { 'EXIT_NONZERO' }
            $meta.NOTE = 'RESULT is process exit class only; COMPETITIVE_PASS=0 unless separately sealed.'
        }
    }
    $meta.ENDED_UTC = (Get-Date).ToUniversalTime().ToString('o')
    $meta.STDOUT_LOG = $outPath
    $meta.STDERR_LOG = $errPath
    $meta | ConvertTo-Json | Set-Content (Join-Path $logs "${Suite}_${stamp}_meta.json") -Encoding ASCII
    Write-Host "[$Suite] RESULT=$($meta.RESULT) EXIT=$($meta.EXIT_CODE) SHA=$($meta.EXE_SHA256)"
    return $meta
}

Write-Host 'COMPETITIVE_BENCH_001 runner PROMOTE=0'
Write-Host "REPO=$RepoRoot EVIDENCE=$EvidenceDir"

$results = @()
$results += Invoke-Tracked -Suite 'terminal_bench' `
    -Exe (Join-Path $RepoRoot 'evidence\FOUR_PANEL_COMPLETION_001\bin\terminal_gate.exe') `
    -TimeoutSec 180
$results += Invoke-Tracked -Suite 'cli_status' `
    -Exe (Join-Path $RepoRoot 'bin\SovereignCLI.exe') -ArgList @('status')
$results += Invoke-Tracked -Suite 'cli_validate' `
    -Exe (Join-Path $RepoRoot 'bin\SovereignCLI.exe') -ArgList @('validate')
$results += Invoke-Tracked -Suite 'cli_benchmark' `
    -Exe (Join-Path $RepoRoot 'bin\SovereignCLI.exe') -ArgList @('benchmark', '--iter', '100')
$results += Invoke-Tracked -Suite 'cli_health' `
    -Exe (Join-Path $RepoRoot 'bin\SovereignCLI_Complete.exe') -ArgList @('health')
$results += Invoke-Tracked -Suite 'ide_entrypoint_present' `
    -Exe (Join-Path $RepoRoot 'bin\RawrXD-Win32IDE.exe') -ArgList @('--help') -TimeoutSec 5

# IDE GUI: presence+SHA only; --help may timeout (no invented PASS)
$ide = Join-Path $RepoRoot 'bin\RawrXD-Win32IDE.exe'
$ideMeta = [ordered]@{
    SUITE       = 'ide_bench'
    COMMAND     = "Test-Path + SHA256 $ide (GUI; no automated IDE-Bench suite)"
    EXE_PATH    = $ide
    EXE_SHA256  = (Get-Sha256 $ide)
    EXE_EXISTS  = (Test-Path $ide)
    RESULT      = if (Test-Path $ide) { 'PRESENCE_OK' } else { 'ABSENT' }
    NOTE        = 'Binary presence gate only. Full IDE-Bench tasks NOT_RUN (no harness fixtures). COMPETITIVE_PASS=0.'
    PROMOTE     = 0
}
$ideMeta | ConvertTo-Json | Set-Content (Join-Path $logs 'ide_bench_presence_meta.json') -Encoding ASCII
$results += $ideMeta

# Coding-task: require fixtures; invoke real cl via vcvars if available
$fx = Join-Path $RepoRoot 'fixtures\agent_multierror_calc'
if (Test-Path $fx) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vs = if (Test-Path $vswhere) {
        & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    } else { $null }
    $vcvars = if ($vs) { Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat' } else { $null }
    if ($vcvars -and (Test-Path $vcvars)) {
        $codingLog = Join-Path $logs 'coding_task_multierror_calc.txt'
        $cmd = "call `"$vcvars`" >nul && cd /d `"$fx`" && cl /nologo /EHsc /std:c++20 add.cpp mul.cpp main.cpp /Fe:calc_ok.exe && calc_ok.exe"
        cmd /c $cmd > $codingLog 2>&1
        $codingExit = $LASTEXITCODE
        $coding = [ordered]@{
            SUITE      = 'coding_task'
            COMMAND    = $cmd
            FIXTURE    = $fx
            RESULT     = if ($codingExit -eq 0) { 'PASS' } else { 'FAIL' }
            EXIT_CODE  = $codingExit
            NOTE       = 'Fixture is intentionally broken (agent autofix). Exit!=0 expected until agent repairs.'
            LOG        = $codingLog
            PROMOTE    = 0
        }
    } else {
        $coding = [ordered]@{
            SUITE   = 'coding_task'
            RESULT  = 'NOT_RUN'
            REASON  = 'MSVC_VCVARS_ABSENT'
            FIXTURE = $fx
            PROMOTE = 0
        }
    }
} else {
    $coding = [ordered]@{
        SUITE   = 'coding_task'
        RESULT  = 'NOT_RUN'
        REASON  = 'FIXTURE_ABSENT'
        PROMOTE = 0
    }
}
$coding | ConvertTo-Json | Set-Content (Join-Path $logs 'coding_task_meta.json') -Encoding ASCII
$results += $coding

$game = [ordered]@{
    SUITE   = 'game_dev'
    RESULT  = 'NOT_RUN'
    REASON  = 'NO_GAME_FIXTURES (fixtures/ has agent_e2e + ASM objs only; no game-dev bench fixtures)'
    PATH    = 'docs/REVERSE_ENGINEERING_GAME_DEVELOPMENT.md (docs only)'
    PROMOTE = 0
}
$game | ConvertTo-Json | Set-Content (Join-Path $logs 'game_dev_meta.json') -Encoding ASCII
$results += $game

Write-Host ''
Write-Host 'SUITE MATRIX (this run):'
foreach ($r in $results) {
    Write-Host ("  {0,-24} {1}" -f $r.SUITE, $r.RESULT)
}
Write-Host 'PROMOTE=0 TIP_CLIMB=HOLD'
