# RAWRXD_DEEP2_D035_TEARDOWN_AUTHORITY_001
# Certification ladder: 10 independent process launches
# Run AFTER reboot/driver reset.
# Requires: F:\~dev\build_streaming\Release\deep2_185in30_gate.exe
#           F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf

param(
    [int]$Runs = 10,
    [string]$Exe = "F:\~dev\build_streaming\Release\deep2_185in30_gate.exe",
    [string]$Model = "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf",
    [string]$OutDir = "F:\~dev\d035_cert"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$report = @()
$clean = 0
$crash = 0
$oom   = 0

for ($i = 1; $i -le $Runs; $i++) {
    $std = "$OutDir\run_$($i.ToString('00'))_stderr.txt"
    $out = "$OutDir\run_$($i.ToString('00'))_stdout.txt"

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $proc = Start-Process -FilePath $Exe -ArgumentList @($Model, "185", "30") `
        -RedirectStandardOutput $out -RedirectStandardError $std -PassThru -Wait
    $sw.Stop()
    $ec = $proc.ExitCode

    # Extract metrics from stderr
    $lines = Get-Content $std -ErrorAction SilentlyContinue
    $wallTps = ($lines | Select-String "WALL_TPS=") | ForEach-Object { ($_ -split "=")[1] } | Select-Object -First 1
    $decTps  = ($lines | Select-String "DECODE_TPS_ENGINE=") | ForEach-Object { ($_ -split "=")[1] } | Select-Object -First 1
    $cbTok   = ($lines | Select-String "CALLBACK_TOKENS=") | ForEach-Object { ($_ -split "=")[1] } | Select-Object -First 1
    $dup     = ($lines | Select-String "DUPLICATE_DESTROY_ATTEMPTS=") | ForEach-Object { ($_ -split "=")[1] } | Select-Object -First 1
    $verdict = ($lines | Select-String "VERDICT=") | ForEach-Object { ($_ -split "=")[1] } | Select-Object -First 1
    $cleanup  = ($lines | Select-String "CLEANUP_INVOCATION=") | ForEach-Object { ($_ -split "=")[1] } | Select-Object -First 1
    $pass     = ($lines | Select-String "TEARDOWN=PASS") | Select-Object -First 1
    $oomErr   = ($lines | Select-String "VK_ERROR_OUT_OF_DEVICE_MEMORY|rc=-2") | Select-Object -First 1

    $hasCleanup = [bool]$cleanup
    $hasPass    = [bool]$pass
    $hasOom     = [bool]$oomErr
    $hasDup0    = ($dup -eq "0")
    $hasCb      = [int]$cbTok -gt 0

    # Gate exit codes: 0 = PASS, 13 = HOLD (both normal); negative = crash/OOM
    $normalExit  = ($ec -eq 0) -or ($ec -eq 13)
    $ok = $normalExit -and $hasCleanup -and $hasPass -and (-not $hasOom) -and $hasDup0 -and $hasCb

    if ($ok) { $clean++ } elseif ($hasOom) { $oom++ } else { $crash++ }

    $report += [PSCustomObject]@{
        Run              = $i
        ExitCode         = $ec
        WallTps          = $wallTps
        DecodeTps        = $decTps
        CallbackTokens   = $cbTok
        DuplicateDestroy = $dup
        CleanupInvoked   = $hasCleanup
        TeardownPass     = $hasPass
        OomDetected      = $hasOom
        OK               = $ok
        StderrPath       = $std
    }

    Write-Host ("RUN {0,2} | EC={1,11} | WALL_TPS={2,10} | CB_TOK={3,3} | DUP={4,3} | CLEANUP={5} | PASS={6} | OOM={7} | OK={8}" -f `
        $i, $ec, $wallTps, $cbTok, $dup, $hasCleanup, $hasPass, $hasOom, $ok)
}

Write-Host ""
Write-Host "========================================"
Write-Host "D035 CERTIFICATION SUMMARY"
Write-Host "========================================"
Write-Host "CLEAN_RUNS    = $clean / $Runs"
Write-Host "CRASH_RUNS     = $crash"
Write-Host "OOM_RUNS       = $oom"
Write-Host ""

if ($clean -eq $Runs) {
    Write-Host "RESULT: PASS — All $Runs runs certified clean."
    Write-Host "ACTION: Freeze teardown code. Proceed to D04."
} else {
    Write-Host "RESULT: FAIL — $($Runs - $clean) runs did not certify."
    Write-Host "ACTION: Inspect failing stderr logs in $OutDir"
}

$csv = "$OutDir\d035_certification_report.csv"
$report | Export-Csv -Path $csv -NoTypeInformation
Write-Host "Report saved to: $csv"
