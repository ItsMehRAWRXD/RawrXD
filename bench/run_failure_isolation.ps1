#requires -Version 5.1
param(
    [string]$BenchPath = 'D:\llama-vulkan\build\bin\llama-bench.exe',
    [string]$OutRoot = 'D:\rawrxd\bench\failure_isolation',
    [string[]]$CtxSizes = @('512', '1024', '2048', '4096'),
    [string[]]$NglValues = @('0', '10', '20', '33', '99'),
    [int]$PromptTokens = 256,
    [int]$GenTokens = 64,
    [int]$Repeats = 1,
    [int]$TimeoutSec = 180
)

$ErrorActionPreference = 'Continue'

if (-not (Test-Path $BenchPath)) {
    Write-Error "llama-bench not found: $BenchPath"
    exit 2
}

$models = @(
    @{ Name='gptoss20b'; Path='D:\gptoss20b.gguf' },
    @{ Name='TinyLlama-1.1B-Q4_0'; Path='D:\TinyLlama-1.1B-Chat-v1.0.Q4_0.gguf' },
    @{ Name='tinyllama_fresh'; Path='D:\tinyllama_fresh.gguf' }
)

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$outDir = Join-Path $OutRoot $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$thresholdMapPath = Join-Path $outDir 'threshold_map.txt'
$summaryCsvPath = Join-Path $outDir 'threshold_summary.csv'
$summaryJsonPath = Join-Path $outDir 'threshold_summary.json'

$rows = [System.Collections.Generic.List[object]]::new()

function Convert-ToIntList {
    param([string[]]$InputValues)

    $out = [System.Collections.Generic.List[int]]::new()
    foreach ($v in $InputValues) {
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $parts = $v -split ','
        foreach ($p in $parts) {
            $trimmed = $p.Trim()
            if ($trimmed -eq '') { continue }
            $n = 0
            if ([int]::TryParse($trimmed, [ref]$n)) {
                $out.Add($n)
            }
        }
    }
    return $out
}

$ctxList = Convert-ToIntList -InputValues $CtxSizes
$nglList = Convert-ToIntList -InputValues $NglValues
if ($ctxList.Count -eq 0) { $ctxList = [System.Collections.Generic.List[int]]::new(); $ctxList.Add(512); $ctxList.Add(1024) }
if ($nglList.Count -eq 0) { $nglList = [System.Collections.Generic.List[int]]::new(); $nglList.Add(0); $nglList.Add(33) }

function Parse-Results {
    param([string]$JsonPath)

    $pp = $null
    $tg = $null
    if ((Test-Path $JsonPath) -and ((Get-Item $JsonPath).Length -gt 0)) {
        try {
            $j = Get-Content $JsonPath -Raw | ConvertFrom-Json
            foreach ($r in $j) {
                if (($r.n_prompt -gt 0) -and ($r.n_gen -eq 0)) { $pp = [double]$r.avg_ts }
                if (($r.n_prompt -eq 0) -and ($r.n_gen -gt 0)) { $tg = [double]$r.avg_ts }
            }
        } catch {
        }
    }

    return @($pp, $tg)
}

foreach ($m in $models) {
    if (-not (Test-Path $m.Path)) {
        $row = [pscustomobject]@{
            Model = $m.Name
            CtxSize = $null
            Ngl = $null
            Repeat = $null
            ExitCode = 'MISSING'
            Status = 'MISSING'
            AssertHit = $false
            AvgPromptTs = $null
            AvgGenTs = $null
            Notes = 'model file missing'
            OutLog = $null
            ErrLog = $null
            JsonOut = $null
        }
        $rows.Add($row)
        Add-Content -Path $thresholdMapPath -Value ("MISSING: {0} file={1}" -f $m.Name, $m.Path)
        continue
    }

    foreach ($ctx in $ctxList) {
        foreach ($ngl in $nglList) {
            for ($rep = 1; $rep -le $Repeats; $rep++) {
                $tag = "{0}_ctx{1}_ngl{2}_r{3}" -f $m.Name, $ctx, $ngl, $rep
                Write-Host "`n[SWEEP] $tag" -ForegroundColor Cyan

                $jsonPath = Join-Path $outDir ("{0}.json" -f $tag)
                $outPath = Join-Path $outDir ("{0}_out.log" -f $tag)
                $errPath = Join-Path $outDir ("{0}_err.log" -f $tag)

                # This llama-bench build does not accept -c. Model ctx pressure through prompt tokens.
                $effectivePrompt = [Math]::Max(1, $ctx - $GenTokens)
                $argList = @(
                    '-m', $m.Path,
                    '-ngl', "$ngl",
                    '-p', "$effectivePrompt",
                    '-n', "$GenTokens",
                    '-r', '1',
                    '-o', 'json'
                )

                $proc = Start-Process -FilePath $BenchPath -ArgumentList $argList -RedirectStandardOutput $jsonPath -RedirectStandardError $errPath -PassThru
                $timedOut = $false
                try {
                    Wait-Process -Id $proc.Id -Timeout $TimeoutSec
                } catch {
                    $timedOut = $true
                    try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
                }

                if (-not $timedOut) {
                    $proc.Refresh()
                    $exit = $proc.ExitCode
                } else {
                    $exit = -99999
                }

                if (Test-Path $jsonPath) {
                    Copy-Item -Path $jsonPath -Destination $outPath -Force
                }

                $assertHit = $false
                $notes = ''
                if (Test-Path $errPath) {
                    $errTxt = Get-Content $errPath -Raw -ErrorAction SilentlyContinue
                    if ($errTxt -match 'GGML_ASSERT\(prev != ggml_uncaught_exception\) failed') {
                        $assertHit = $true
                        $notes = 'GGML_ASSERT(prev != ggml_uncaught_exception)'
                    } elseif ($timedOut) {
                        $notes = 'timeout'
                    } elseif ($errTxt -match 'error|failed|abort|exception|assert') {
                        $line = ($errTxt -split "`r?`n" | Select-String -Pattern 'error|failed|abort|exception|assert' | Select-Object -First 1)
                        if ($line) { $notes = $line.Line.Trim() }
                    }
                } elseif ($timedOut) {
                    $notes = 'timeout'
                }

                $parsed = Parse-Results -JsonPath $jsonPath
                $pp = $parsed[0]
                $tg = $parsed[1]

                $status = if ($exit -eq 0) { 'PASS' } elseif ($timedOut) { 'TIMEOUT' } else { 'FAIL' }
                if ($status -eq 'PASS') {
                    Write-Host "  [PASS] $tag" -ForegroundColor Green
                } else {
                    Write-Host "  [FAIL] $tag (Exit: $exit)" -ForegroundColor Red
                }

                Add-Content -Path $thresholdMapPath -Value ("{0}: {1} Exit={2} Assert={3} Notes={4}" -f $status, $tag, $exit, $assertHit, $notes)

                $rows.Add([pscustomobject]@{
                    Model = $m.Name
                    CtxSize = $ctx
                    Ngl = $ngl
                    Repeat = $rep
                    ExitCode = $exit
                    Status = $status
                    AssertHit = $assertHit
                    AvgPromptTs = if ($pp -ne $null) { [math]::Round($pp, 2) } else { $null }
                    AvgGenTs = if ($tg -ne $null) { [math]::Round($tg, 2) } else { $null }
                    Notes = $notes
                    PromptTokens = $effectivePrompt
                    GenTokens = $GenTokens
                    OutLog = $outPath
                    ErrLog = $errPath
                    JsonOut = $jsonPath
                })
            }
        }
    }
}

$rows | Export-Csv -Path $summaryCsvPath -NoTypeInformation
$rows | ConvertTo-Json -Depth 5 | Set-Content -Path $summaryJsonPath -Encoding UTF8

Write-Host "`nFailure isolation sweep complete." -ForegroundColor Green
Write-Host "OutDir: $outDir" -ForegroundColor Green
Write-Host "Threshold map: $thresholdMapPath" -ForegroundColor Green
Write-Host "Summary CSV : $summaryCsvPath" -ForegroundColor Green
Write-Host "Summary JSON: $summaryJsonPath" -ForegroundColor Green
