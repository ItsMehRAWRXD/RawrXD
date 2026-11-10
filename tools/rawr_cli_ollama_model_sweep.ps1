[CmdletBinding()]
param(
    [string]$Root = 'F:\rawrxd',
    [string]$BaseUrl = 'http://127.0.0.1:11434',
    [int]$TimeoutSeconds = 120,
    [string]$OutputPath = 'F:\rawrxd\evidence\RAWRXD_OLLAMA_CLI_MODEL_SWEEP_20261028.json'
)

$ErrorActionPreference = 'Stop'
$exe = Join-Path $Root 'build_ide\bin-msvc\rawr.exe'
if (-not (Test-Path -LiteralPath $exe)) { throw "Missing canonical CLI: $exe" }

function Get-ModelSpec([string]$Name) {
    try {
        return Invoke-RestMethod -Uri "$BaseUrl/api/show" -Method Post -ContentType 'application/json' `
            -Body (@{ model = $Name } | ConvertTo-Json -Compress) -TimeoutSec 15
    } catch {
        return $null
    }
}

function Test-CompletionCapable($Spec) {
    if ($null -eq $Spec) { return $false }
    $caps = @($Spec.capabilities | ForEach-Object { [string]$_ })
    return -not (($caps -contains 'embedding') -and -not ($caps -contains 'completion'))
}

function Invoke-RawrModel([string]$Name) {
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.WorkingDirectory = $Root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $psi.Environment['RAWRXD_OLLAMA_ENDPOINT'] = $BaseUrl
    if ($env:RAWRXD_OLLAMA_NUM_GPU) {
        $psi.Environment['RAWRXD_OLLAMA_NUM_GPU'] = $env:RAWRXD_OLLAMA_NUM_GPU
    }
    foreach ($arg in @('run', $Name, '--backend', 'ollama', '--workspace', $Root,
                       '--mode', 'ask', '--fresh-session', '--esp=tps', '--prompt',
                       'Reply exactly RAWRXD_MODEL_SMOKE')) {
        [void]$psi.ArgumentList.Add($arg)
    }

    $p = [Diagnostics.Process]::new()
    $p.StartInfo = $psi
    $watch = [Diagnostics.Stopwatch]::StartNew()
    [void]$p.Start()
    $stdoutTask = $p.StandardOutput.ReadToEndAsync()
    $stderrTask = $p.StandardError.ReadToEndAsync()
    $timedOut = -not $p.WaitForExit($TimeoutSeconds * 1000)
    if ($timedOut) {
        try { $p.Kill($true) } catch { }
        $p.WaitForExit()
    }
    $watch.Stop()
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    $combined = ($stdout + "`n" + $stderr).Trim()
    $exitCode = if ($timedOut) { -1 } else { $p.ExitCode }
    $heartbeat = [regex]::Matches($combined, '(?m)^\[ESP\].*kind=heartbeat.*$') |
        Where-Object { $_.Value -match 'eval_duration_ns=' } |
        Select-Object -Last 1 -ExpandProperty Value
    $finished = [regex]::Match($combined, '(?m)^\[ESP\].*kind=finished.*$').Value
    $responseMarker = $combined -match 'RAWRXD_MODEL_SMOKE'
    $failureMarker = $combined -match '\[error\]|EMPTY_MODEL_RESPONSE|inference_failed|MODEL_LOAD_FAILED'
    $nativeMetrics = $null
    if ($heartbeat) {
        $nativeMetrics = [ordered]@{}
        foreach ($name in @('prompt_eval_count','eval_count','total_duration_ns','load_duration_ns','prompt_eval_duration_ns','eval_duration_ns','eval_tps')) {
            $m = [regex]::Match($heartbeat, "(?:^| )$name=([^ ]+)")
            if ($m.Success) {
                $raw = $m.Groups[1].Value
                if ($name -eq 'eval_tps') { $nativeMetrics[$name] = [double]$raw }
                else { $nativeMetrics[$name] = [UInt64]$raw }
            }
        }
    }
    $nativeMetricsValid = $null -ne $nativeMetrics -and
        $nativeMetrics.Contains('eval_count') -and
        $nativeMetrics.Contains('eval_duration_ns') -and
        [UInt64]$nativeMetrics.eval_count -gt 0 -and
        [UInt64]$nativeMetrics.eval_duration_ns -gt 0
    $status = if ($timedOut) { 'TIMEOUT' }
              elseif ($exitCode -ne 0) { 'FAIL_EXIT' }
              elseif ($failureMarker) { 'FAIL_RUNTIME' }
              elseif (-not $nativeMetricsValid) { 'FAIL_NO_NATIVE_METRICS' }
              elseif (-not $responseMarker) { 'FAIL_EMPTY_OR_WRONG_RESPONSE' }
              else { 'PASS' }

    [pscustomobject]@{
        model = $Name
        status = $status
        elapsed_ms = $watch.ElapsedMilliseconds
        exit_code = $exitCode
        response_marker = $responseMarker
        heartbeat = [string]$heartbeat
        native_metrics_valid = $nativeMetricsValid
        native_metrics = $nativeMetrics
        finished = [string]$finished
        stdout = $stdout
        stderr = $stderr
    }
}

$tagResponse = Invoke-RestMethod -Uri "$BaseUrl/api/tags" -TimeoutSec 15
$inventory = @($tagResponse.models | Where-Object {
    $name = [string]$_.name
    $name -notmatch '(:cloud$|-cloud$)'
})

$results = [System.Collections.Generic.List[object]]::new()
$index = 0
foreach ($entry in $inventory) {
    $index++
    $name = [string]$entry.name
    $spec = Get-ModelSpec $name
    if ($null -eq $spec) {
        $results.Add([pscustomobject]@{ model=$name; status='MODEL_METADATA_UNAVAILABLE'; elapsed_ms=0; exit_code=-1; response_marker=$false; heartbeat=''; finished=''; stdout=''; stderr='api/show failed' })
        Write-Output "[$index/$($inventory.Count)] $name | MODEL_METADATA_UNAVAILABLE"
        continue
    }
    if (-not (Test-CompletionCapable $spec)) {
        $results.Add([pscustomobject]@{ model=$name; status='UNSUPPORTED_COMPLETION'; elapsed_ms=0; exit_code=0; response_marker=$false; heartbeat=''; finished=''; stdout=''; stderr='embedding-only model' })
        Write-Output "[$index/$($inventory.Count)] $name | UNSUPPORTED_COMPLETION"
        continue
    }
    $result = Invoke-RawrModel $name
    $results.Add($result)
    Write-Output "[$index/$($inventory.Count)] $name | $($result.status) | $($result.elapsed_ms)ms | exit=$($result.exit_code)"
}

$receipt = [ordered]@{
    schema = 'RAWRXD_OLLAMA_CLI_MODEL_SWEEP_001'
    timestamp_utc = [DateTime]::UtcNow.ToString('o')
    root = $Root
    cli = $exe
    cli_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    backend = 'ollama'
    base_url = $BaseUrl
    prompt = 'Reply exactly RAWRXD_MODEL_SMOKE'
    timeout_seconds = $TimeoutSeconds
    local_model_count = $inventory.Count
    results = @($results)
    pass = @($results | Where-Object status -eq 'PASS').Count
    nonpass = @($results | Where-Object status -ne 'PASS').Count
}

$parent = Split-Path -Parent $OutputPath
New-Item -ItemType Directory -Force -Path $parent | Out-Null
$receipt | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
Write-Output "OLLAMA_RAWR_CLI_SWEEP_TOTAL=$($inventory.Count) PASS=$($receipt.pass) NONPASS=$($receipt.nonpass)"
Write-Output "RECEIPT=$OutputPath"
