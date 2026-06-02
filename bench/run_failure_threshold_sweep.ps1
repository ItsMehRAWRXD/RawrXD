#requires -Version 5.1
param(
    [string]$BenchPath = 'D:\llama-vulkan\build\bin\llama-bench.exe',
    [string]$OutRoot = 'D:\rawrxd\bench\threshold_sweep'
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path $BenchPath)) {
    Write-Error "llama-bench not found: $BenchPath"
    exit 2
}

$benchDir = Split-Path -Parent $BenchPath
if (-not (Test-Path $benchDir)) {
    Write-Error "llama-bench directory not found: $benchDir"
    exit 3
}

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Join-Path $OutRoot $timestamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Models currently known to fail in the Vulkan sweep.
$models = @(
    @{ Name='TinyLlama-1.1B-Q4_0'; Path='D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf' },
    @{ Name='ministral3'; Path='D:\ministral3.gguf' },
    @{ Name='gptoss20b'; Path='D:\gptoss20b.gguf' }
)

# Lower ngl and smaller prompt/gen reduce working-set pressure.
$profiles = @(
    @{ Name='full'; Ngl=99; Prompt=512; Gen=128 },
    @{ Name='mid';  Ngl=48; Prompt=256; Gen=64  },
    @{ Name='low';  Ngl=24; Prompt=128; Gen=32  },
    @{ Name='cpu';  Ngl=0;  Prompt=128; Gen=32  }
)

$rows = @()

Push-Location $benchDir
try {
foreach ($m in $models) {
    if (-not (Test-Path $m.Path)) {
        $rows += [pscustomobject]@{
            Model = $m.Name; Profile='missing'; Ngl=''; Prompt=''; Gen=''; ExitCode='MISSING';
            Status='MISSING'; AssertHit=''; AvgPromptTs=''; AvgGenTs=''; Notes='model missing'
        }
        continue
    }

    foreach ($p in $profiles) {
        $tag = "{0}_{1}" -f $m.Name, $p.Name
        $jsonPath = Join-Path $outDir ("{0}.json" -f $tag)
        $logPath = Join-Path $outDir ("{0}.log" -f $tag)

        $args = @(
            '-m', $m.Path,
            '-ngl', "$($p.Ngl)",
            '-r', '2',
            '-o', 'json',
            '-p', "$($p.Prompt)",
            '-n', "$($p.Gen)",
            '--progress'
        )

        & $BenchPath @args 1> $jsonPath 2> $logPath
        $exitCode = $LASTEXITCODE

        $assertHit = $false
        $notes = ''
        if (Test-Path $logPath) {
            $logTxt = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
            if ($logTxt -match 'GGML_ASSERT\(prev != ggml_uncaught_exception\) failed') {
                $assertHit = $true
                $notes = 'GGML_ASSERT(prev != ggml_uncaught_exception)'
            } elseif ($logTxt -match 'error|failed|abort|exception') {
                $err = ($logTxt -split "`r?`n" | Select-String -Pattern 'error|failed|abort|exception' | Select-Object -First 1)
                if ($err) { $notes = $err.Line.Trim() }
            }
        }

        $avgPrompt = $null
        $avgGen = $null
        if ((Test-Path $jsonPath) -and ((Get-Item $jsonPath).Length -gt 0)) {
            try {
                $j = Get-Content $jsonPath -Raw | ConvertFrom-Json
                foreach ($r in $j) {
                    if (($r.n_prompt -gt 0) -and ($r.n_gen -eq 0)) { $avgPrompt = [double]$r.avg_ts }
                    if (($r.n_prompt -eq 0) -and ($r.n_gen -gt 0)) { $avgGen = [double]$r.avg_ts }
                }
            } catch {
                if ([string]::IsNullOrWhiteSpace($notes)) {
                    $notes = 'json parse failed'
                }
            }
        }

        $status = if ($exitCode -eq 0) { 'OK' } else { 'FAIL' }
        $rows += [pscustomobject]@{
            Model = $m.Name
            Profile = $p.Name
            Ngl = $p.Ngl
            Prompt = $p.Prompt
            Gen = $p.Gen
            ExitCode = $exitCode
            Status = $status
            AssertHit = $assertHit
            AvgPromptTs = if ($avgPrompt -ne $null) { [math]::Round($avgPrompt, 2) } else { $null }
            AvgGenTs = if ($avgGen -ne $null) { [math]::Round($avgGen, 2) } else { $null }
            Notes = $notes
        }
    }
}
}
finally {
    Pop-Location
}

$csvPath = Join-Path $outDir 'threshold_summary.csv'
$jsonPath = Join-Path $outDir 'threshold_summary.json'
$mdPath = Join-Path $outDir 'threshold_summary.md'

$rows | Export-Csv -NoTypeInformation -Path $csvPath
$rows | ConvertTo-Json -Depth 5 | Set-Content -Path $jsonPath -Encoding UTF8

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine('# Vulkan Failure Threshold Sweep')
[void]$md.AppendLine('')
[void]$md.AppendLine(('Run: {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')))
[void]$md.AppendLine(('Bench: {0}' -f $BenchPath))
[void]$md.AppendLine('')
[void]$md.AppendLine('| Model | Profile | ngl | p | n | Status | Exit | Assert | pp t/s | tg t/s | Notes |')
[void]$md.AppendLine('|---|---|---:|---:|---:|---|---:|---|---:|---:|---|')
foreach ($r in $rows) {
    [void]$md.AppendLine(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} | {7} | {8} | {9} | {10} |" -f `
        $r.Model, $r.Profile, $r.Ngl, $r.Prompt, $r.Gen, $r.Status, $r.ExitCode, $r.AssertHit, $r.AvgPromptTs, $r.AvgGenTs, $r.Notes))
}
[IO.File]::WriteAllText($mdPath, $md.ToString(), [Text.UTF8Encoding]::new($false))

Write-Host "Threshold sweep complete."
Write-Host "OutDir: $outDir"
Write-Host "CSV:    $csvPath"
Write-Host "JSON:   $jsonPath"
Write-Host "MD:     $mdPath"
