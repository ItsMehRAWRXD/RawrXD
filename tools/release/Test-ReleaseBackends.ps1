#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PackageDirectory,
    [Parameter(Mandatory = $true)][string]$ModelPath,
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [string]$OllamaModel = 'llama3.2:3b',
    [int]$TimeoutSeconds = 180
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseHash.ps1')
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Use a new evidence directory for every run.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$evidence = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$model = (Resolve-Path -LiteralPath $ModelPath).Path
& (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $package | Out-Null
$exe = Join-Path $package 'deep2_agentic_loop.exe'
$result = [ordered]@{
    schema_version = 1; started_utc = [DateTime]::UtcNow.ToString('o')
    package = $package
    ide_sha256 = (Get-FileHash -LiteralPath (Join-Path $package 'RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash
    deep2_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
    model = $model; model_sha256 = (Get-FileHash -LiteralPath $model -Algorithm SHA256).Hash
    scope = 'Backend subprocess and local HTTP probes; IDE integration requires separate UI evidence.'
}
function Save-Result {
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'backend-results.json') -Encoding UTF8
}
function Invoke-Deep2Probe([string]$Name, [string[]]$ProbeArguments) {
    $stdout = Join-Path $evidence ($Name + '.stdout.log')
    $stderr = Join-Path $evidence ($Name + '.stderr.log')
    # Arguments are passed directly to the process, never through a command shell.
    foreach ($argument in $ProbeArguments) {
        if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Unsupported probe argument quoting.' }
    }
    $commandLine = ($ProbeArguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $process = Start-Process -FilePath $exe -ArgumentList $commandLine -WorkingDirectory $evidence `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden -PassThru
    $completed = $process.WaitForExit($TimeoutSeconds * 1000)
    if (-not $completed) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit()
    }
    $process.Refresh()
    $timer.Stop()
    $output = [IO.File]::ReadAllText($stdout) + [IO.File]::ReadAllText($stderr)
    $tokens = 0
    if ($output -match '\[plain\] greedy (\d+) tokens') { $tokens = [int]$Matches[1] }
    $gpu = 0L; $cpu = 0L
    if ($output -match 'PLAIN_FIRST_TOKEN[^\r\n]*gpu=(\d+) cpu=(\d+)') {
        $gpu = [long]$Matches[1]; $cpu = [long]$Matches[2]
    }
    $ok = $completed -and $process.ExitCode -eq 0 -and $tokens -gt 0 -and
          $output -match 'nonfinite=0' -and $output -notmatch 'EXEC_FAIL|INGEST_FAIL|BIND_FAIL|PLAIN_FAIL'
    if ($Name -eq 'deep2-gpu') { $ok = $ok -and $gpu -gt 0 }
    [ordered]@{ status = $(if ($ok) { 'PASS' } else { 'FAIL' });
        exited = $completed; exit_code = $process.ExitCode; process_id = $process.Id;
        elapsed_seconds = [math]::Round($timer.Elapsed.TotalSeconds, 3);
        generated_tokens = $tokens; gpu_dispatches_at_first_token = $gpu;
        cpu_calls_at_first_token = $cpu; stdout = $stdout; stderr = $stderr }
}
try {
    $result.vulkan_inventory = (& vulkaninfo --summary 2>&1 | Out-String)
    $result.vulkan_inventory | Set-Content -LiteralPath (Join-Path $evidence 'vulkan-summary.txt') -Encoding UTF8
    Save-Result
    foreach ($mode in @('gpu', 'cpu')) {
        $probeArguments = @('--model', $model, '--workdir', $evidence,
            '--plain', 'Write a short C function that adds two integers.',
            '--plain-tokens', '16', '--temperature', '0')
        if ($mode -eq 'cpu') { $probeArguments += '--cpu' }
        $result[('deep2_' + $mode)] = Invoke-Deep2Probe ('deep2-' + $mode) $probeArguments
        Save-Result
        Write-Output ('Deep2 {0}: {1}' -f $mode, $result[('deep2_' + $mode)].status)
    }
    $request = @{model = $OllamaModel; stream = $false; prompt = 'Reply with exactly READY.';
        options = @{temperature = 0; num_predict = 16; num_ctx = 2048}} | ConvertTo-Json -Depth 4
    $response = Invoke-RestMethod -Uri 'http://localhost:11434/api/generate' -Method Post `
        -ContentType 'application/json' -Body $request -TimeoutSec $TimeoutSeconds
    $response | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $evidence 'ollama-response.json') -Encoding UTF8
    $ollamaOk = $response.done -and $response.eval_count -gt 0 -and $response.response -match 'READY'
    $result.ollama = [ordered]@{ status = $(if ($ollamaOk) { 'PASS' } else { 'FAIL' });
        model = $response.model; generated_tokens = $response.eval_count;
        response = $response.response; total_duration_ns = $response.total_duration;
        eval_duration_ns = $response.eval_duration }
    $result.ollama_running = (Invoke-RestMethod -Uri 'http://localhost:11434/api/ps' -TimeoutSec 15).models
    $result.finished_utc = [DateTime]::UtcNow.ToString('o')
    Save-Result
    Write-Output ('Ollama: ' + $result.ollama.status)
    if ($result.deep2_gpu.status -ne 'PASS' -or $result.deep2_cpu.status -ne 'PASS' -or -not $ollamaOk) { exit 1 }
} catch {
    $result.error = $_.Exception.Message
    $result.finished_utc = [DateTime]::UtcNow.ToString('o')
    Save-Result
    throw
}
