# B012 Amortization Crossover Experiment Runner
# Runs b012_amortization_test.exe for decode lengths 1,2,8,16,32,64,128,256
# in both B010 (mode=0) and B011 (mode=1) configurations.
# Results are appended to B012/performance/b012_raw_results.jsonl

$modelPath = "F:\Franken\BackwardsUnlock\1b\unlock-1B-Q4_K_M.gguf"
$exePath = "d:\rawrxd\build-pmm-validate\bin\b012_amortization_test.exe"
$resultsFile = "d:\rawrxd\B012\performance\b012_raw_results.jsonl"

$decodeLengths = @(1, 2, 8, 16, 32, 64, 128, 256)

if (!(Test-Path $exePath)) {
    Write-Error "Binary not found: $exePath"
    exit 1
}

# Clear previous results
if (Test-Path $resultsFile) {
    Remove-Item $resultsFile
}

foreach ($len in $decodeLengths) {
    foreach ($mode in @(0, 1)) {
        $modeName = if ($mode -eq 0) { "B010" } else { "B011" }
        Write-Host "Running decode_length=$len mode=$modeName ..."

        $env:RAWRXD_TEST_MODEL = $modelPath
        $proc = Start-Process -FilePath $exePath -ArgumentList "$len $mode" -PassThru -Wait -RedirectStandardOutput "d:\rawrxd\B012\logs\tmp_stdout.txt" -RedirectStandardError "d:\rawrxd\B012\logs\tmp_stderr.txt"
        $exitCode = $proc.ExitCode

        if ($exitCode -ne 0) {
            Write-Warning "  FAILED with exit code $exitCode (len=$len mode=$modeName)"
            $stderr = Get-Content "d:\rawrxd\B012\logs\tmp_stderr.txt" -Raw
            Write-Warning "  stderr: $stderr"
            continue
        }

        $stdout = Get-Content "d:\rawrxd\B012\logs\tmp_stdout.txt" -Raw
        # Extract JSON block (everything between first { and last })
        $jsonStart = $stdout.IndexOf("{")
        $jsonEnd = $stdout.LastIndexOf("}")
        if ($jsonStart -ge 0 -and $jsonEnd -gt $jsonStart) {
            $jsonBlock = $stdout.Substring($jsonStart, $jsonEnd - $jsonStart + 1)
            Add-Content -Path $resultsFile -Value $jsonBlock
            Write-Host "  OK — result captured"
        } else {
            Write-Warning "  Could not extract JSON from stdout"
            Write-Host $stdout
        }
    }
}

Write-Host "Sweep complete. Results saved to $resultsFile"
