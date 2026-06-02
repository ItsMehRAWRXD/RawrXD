#requires -Version 5.1
# TPS Benchmark Sweep — Vulkan llama-bench against all real GGUF models on D:\.
# Captures: load success, pp512 (prefill), tg128 (decode), VRAM behavior.
# Output: per-model JSON + a consolidated markdown summary.

$ErrorActionPreference = 'Continue'
$bench = 'D:\llama-vulkan\build\bin\llama-bench.exe'
$llamaCli = 'D:\llama-vulkan\build\bin\llama-cli.exe'
$verifyScript = 'D:\rawrxd\scripts\verify_models.ps1'
$manifestPath = 'D:\rawrxd\scripts\model_compatibility_manifest.json'
$out   = 'd:\rawrxd\bench\out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

$models = @(
    @{ Name='TinyLlama-1.1B-Q4_0';    Path='D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf';   Ngl=99 },
    @{ Name='tinyllama_fresh';        Path='D:\tinyllama_fresh.gguf';                 Ngl=99 },
    @{ Name='phi3mini';               Path='D:\phi3mini.gguf';                        Ngl=99 },
    @{ Name='ministral3';             Path='D:\ministral3.gguf';                      Ngl=99 },
    @{ Name='Qwen3.5-40B-Q4_K_M';     Path='D:\Qwen3.5-40B-Q4_K_M.gguf';              Ngl=99 },
    @{ Name='codestral22b';           Path='D:\codestral22b.gguf';                    Ngl=99 },
    @{ Name='gptoss20b';              Path='D:\gptoss20b.gguf';                       Ngl=99 }
)

$summary = @()

function Invoke-ModelPreflight {
    param(
        [string]$ModelName,
        [string]$ModelPath
    )

    if (-not (Test-Path $verifyScript)) {
        return @{ Valid = $true; Reason = 'validator script missing (soft-pass)' }
    }

    try {
        $verifyJson = & $verifyScript -ModelPath $ModelPath -ModelName $ModelName -LlamaCliPath $llamaCli -ManifestPath $manifestPath -AsJson
        if ($LASTEXITCODE -ne 0) {
            if ($verifyJson) {
                $v = $verifyJson | ConvertFrom-Json
                return @{ Valid = $false; Reason = [string]$v.Reason }
            }
            return @{ Valid = $false; Reason = 'preflight failed (no details)' }
        }

        $v = $verifyJson | ConvertFrom-Json
        return @{ Valid = [bool]$v.Valid; Reason = [string]$v.Reason }
    } catch {
        return @{ Valid = $false; Reason = "preflight exception: $($_.Exception.Message)" }
    }
}

$benchDir = Split-Path -Parent $bench
Push-Location $benchDir
try {

foreach ($m in $models) {
    $name = $m.Name
    $path = $m.Path
    $ngl  = $m.Ngl
    Write-Host "`n=========================================================="
    Write-Host "[BENCH] $name  ($path)  ngl=$ngl"
    Write-Host "=========================================================="

    if (-not (Test-Path $path)) {
        Write-Host "  SKIP: file missing"
        $summary += [pscustomobject]@{
            Model=$name; Status='MISSING'; pp512=$null; tg128=$null; LoadMs=$null; Backend=$null; Notes='file not found'
        }
        continue
    }

    $preflight = Invoke-ModelPreflight -ModelName $name -ModelPath $path
    if (-not $preflight.Valid) {
        Write-Host "  SKIP: preflight failed ($($preflight.Reason))"
        $summary += [pscustomobject]@{
            Model=$name; Status='PRECHECK_FAIL'; pp512=$null; tg128=$null; LoadMs=$null; Backend=$null; Notes=$preflight.Reason
        }
        continue
    }

    $jsonPath = Join-Path $out ("{0}.json" -f $name)
    $logPath  = Join-Path $out ("{0}.log"  -f $name)

    # device 0 = RX 7800 XT (16 GB dGPU)
    $args = @('-m', $path, '-ngl', "$ngl", '-r', '3', '-o', 'json', '-p', '512', '-n', '128', '--progress')

    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $bench @args 1>$jsonPath 2>$logPath
    $ec = $LASTEXITCODE
    $sw.Stop()

    $status = if ($ec -eq 0) { 'OK' } else { "EXIT=$ec" }
    Write-Host "  exit=$ec  wall=$([math]::Round($sw.Elapsed.TotalSeconds,1))s"

    $pp = $null; $tg = $null; $backend=$null; $loadMs=$null; $notes=$null
    if ((Test-Path $jsonPath) -and ((Get-Item $jsonPath).Length -gt 0)) {
        try {
            $j = Get-Content $jsonPath -Raw | ConvertFrom-Json
            foreach ($row in $j) {
                $tps = [double]$row.avg_ts
                if ($row.n_prompt -gt 0 -and $row.n_gen -eq 0) { $pp = $tps }
                if ($row.n_gen    -gt 0 -and $row.n_prompt -eq 0) { $tg = $tps }
                if (-not $backend) { $backend = $row.backends -join '/' }
            }
        } catch {
            $notes = "json parse failed: $($_.Exception.Message)"
        }
    }

    # Try to lift "load time" from stderr log
    if (Test-Path $logPath) {
        $logTxt = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
        if ($logTxt -match 'load time\s*=\s*([\d\.]+)\s*ms') { $loadMs = [double]$matches[1] }
        if (-not $notes -and $logTxt -match 'error|failed|abort|exception') {
            $errLine = ($logTxt -split "`n" | Select-String -Pattern 'error|failed|abort|exception' | Select-Object -First 1)
            if ($errLine) { $notes = ($errLine.Line.Trim()) }
        }
    }

    $summary += [pscustomobject]@{
        Model   = $name
        Status  = $status
        pp512   = if ($pp) { [math]::Round($pp,2) } else { $null }
        tg128   = if ($tg) { [math]::Round($tg,2) } else { $null }
        LoadMs  = if ($loadMs) { [math]::Round($loadMs,0) } else { $null }
        Backend = $backend
        Notes   = $notes
    }
}
}
finally {
    Pop-Location
}

# Write consolidated CSV + Markdown table
$summary | Export-Csv -NoTypeInformation -Path (Join-Path $out 'summary.csv')

$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# Sovereign Model Load + TPS Audit (Vulkan, RX 7800 XT)")
[void]$md.AppendLine("")
[void]$md.AppendLine("Run: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$md.AppendLine("Backend: llama-bench Vulkan build (`$bench`)")
[void]$md.AppendLine("")
[void]$md.AppendLine("| Model | Status | pp512 (t/s) | tg128 (t/s) | Load (ms) | Notes |")
[void]$md.AppendLine("|---|---|---:|---:|---:|---|")
foreach ($r in $summary) {
    [void]$md.AppendLine("| $($r.Model) | $($r.Status) | $($r.pp512) | $($r.tg128) | $($r.LoadMs) | $($r.Notes) |")
}
$mdPath = Join-Path $out 'summary.md'
[IO.File]::WriteAllText($mdPath, $md.ToString(), [Text.UTF8Encoding]::new($false))

Write-Host "`n========== SUMMARY =========="
$summary | Format-Table -AutoSize | Out-String -Width 200
Write-Host "Wrote: $mdPath"
