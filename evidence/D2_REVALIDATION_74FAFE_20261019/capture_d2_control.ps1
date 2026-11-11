param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('serial', 'batched')]
    [string]$Mode
)

$ErrorActionPreference = 'Stop'
$PSScriptRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$EvidenceDir = $PSScriptRoot
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $EvidenceDir '..\..'))
$Executable = 'F:\rawrxd\.build_d2_revalidate_74fafe\deep2_bench_tps.exe'
$BuildRoot = 'F:\rawrxd\.build_d2_revalidate_74fafe'
$Model = 'F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$CompetitorExe = 'F:\wt_ide1\_s12_parity_build\bin\deep2_end_to_end_bench.exe'
$CompetitorModel = 'F:\~dev\qwen2.5-coder-1.5b-base.gguf'
$TokenFile = Join-Path $EvidenceDir 'tokens.txt'
$Tokens = (Get-Content -LiteralPath $TokenFile -Raw).Trim()
$Prefix = $Mode + '_pair_final'
$Log = Join-Path $EvidenceDir ($Prefix + '.log')
$StdoutLog = Join-Path $EvidenceDir ($Prefix + '.stdout.log')
$StderrLog = Join-Path $EvidenceDir ($Prefix + '.stderr.log')
$LogitsDir = Join-Path $EvidenceDir ($Prefix + '_logits')
$CommandFile = Join-Path $EvidenceDir ($Prefix + '_command.txt')
$PreFile = Join-Path $EvidenceDir ('processes_before_' + $Prefix + '.json')
$PostFile = Join-Path $EvidenceDir ('processes_after_' + $Prefix + '.json')
$SamplesFile = Join-Path $EvidenceDir ('process_samples_' + $Prefix + '.json')
$EventsFile = Join-Path $EvidenceDir ('process_events_' + $Prefix + '.json')
$SummaryFile = Join-Path $EvidenceDir ($Prefix + '_summary.json')
$ExitFile = Join-Path $EvidenceDir ($Prefix + '_exit.txt')

function Get-CompetingProcesses {
    $all = @(Get-CimInstance Win32_Process)
    $selected = @($all | Where-Object {
        if ($_.ProcessId -eq $PID) {
            $false
        } else {
            $isQwenBench = ($_.ExecutablePath -ieq $CompetitorExe) -and
                ($_.CommandLine -match '(?i)--strict-vulkan') -and
                ($_.CommandLine -match [regex]::Escape($CompetitorModel))
            $isQwenWrapper = ($_.Name -ieq 'pwsh.exe') -and
                ($_.CommandLine -match '(?i)deep2_gpu_flight_recorder\.ps1') -and
                ($_.CommandLine -match '(?i)_s12_parity_build[\\/]bin[\\/]deep2_end_to_end_bench\.exe') -and
                ($_.CommandLine -match [regex]::Escape($CompetitorModel))
            $isQwenMutationGate = ($_.Name -ieq 'pwsh.exe') -and
                ($_.CommandLine -match '(?i)deep2_tps_mutation_gate\.ps1') -and
                ($_.CommandLine -match [regex]::Escape($CompetitorModel))
            $isOtherDeep2Bench = ($_.Name -match '(?i)^deep2.*\.exe$') -and
                ($_.ExecutablePath -ine $Executable)
            $isQwenBench -or $isQwenWrapper -or $isQwenMutationGate -or $isOtherDeep2Bench
        }
    } | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CreationDate, CommandLine)
    return $selected
}

function Write-JsonFile([string]$Path, $Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 12
    [System.IO.File]::WriteAllText($Path, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
}

if (-not (Test-Path -LiteralPath $Executable)) { throw "Missing test executable: $Executable" }
if (-not (Test-Path -LiteralPath $Model)) { throw "Missing model: $Model" }
if (-not (Test-Path -LiteralPath $TokenFile)) { throw "Missing token input: $TokenFile" }
if (Test-Path -LiteralPath $LogitsDir) { Remove-Item -LiteralPath $LogitsDir -Recurse -Force }
New-Item -ItemType Directory -Path $LogitsDir | Out-Null

$pre = @(Get-CompetingProcesses)
Write-JsonFile $PreFile ([ordered]@{ CapturedAt = (Get-Date -Format o); Processes = $pre })
if ($pre.Count -ne 0) {
    Write-Output "PRECHECK_BLOCKED: competing process inventory has $($pre.Count) entries; no run launched."
    exit 3
}

$NativeArgs = [System.Collections.Generic.List[string]]::new()
if ($Mode -eq 'serial') { $NativeArgs.Add('--no-batch') }
$NativeArgs.Add('--model'); $NativeArgs.Add($Model)
$NativeArgs.Add('--tokens'); $NativeArgs.Add($Tokens)
$NativeArgs.Add('--decode'); $NativeArgs.Add('1')
$NativeArgs.Add('--dump-logits'); $NativeArgs.Add($LogitsDir)

$display = @()
$display += '"' + $Executable + '"'
foreach ($arg in $NativeArgs) {
    if ($arg -match '\s') { $display += '"' + $arg.Replace('"', '\"') + '"' }
    else { $display += $arg }
}
[System.IO.File]::WriteAllText($CommandFile, ($display -join ' ') + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))

$psi = [System.Diagnostics.ProcessStartInfo]::new()
$psi.FileName = $Executable
$psi.WorkingDirectory = $RepoRoot
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
foreach ($arg in $NativeArgs) { [void]$psi.ArgumentList.Add($arg) }
$psi.Environment['PATH'] = $BuildRoot + '\ggml\bin\Release;' + $BuildRoot + ';' + $env:PATH
if ($psi.Environment.ContainsKey('DEEP2_GPU_TIMING')) { [void]$psi.Environment.Remove('DEEP2_GPU_TIMING') }
if ($psi.Environment.ContainsKey('DEEP2_NO_DOT_BATCH')) { [void]$psi.Environment.Remove('DEEP2_NO_DOT_BATCH') }

$events = [System.Collections.Generic.List[object]]::new()
$samples = [System.Collections.Generic.List[object]]::new()
$handledPids = [System.Collections.Generic.HashSet[int]]::new()
$proc = [System.Diagnostics.Process]::new()
$proc.StartInfo = $psi
$startedAt = Get-Date
if (-not $proc.Start()) { throw 'Process.Start returned false.' }
$testPid = $proc.Id
$stdoutTask = $proc.StandardOutput.ReadToEndAsync()
$stderrTask = $proc.StandardError.ReadToEndAsync()
$testProcess = Get-CimInstance Win32_Process -Filter "ProcessId = $testPid"
$events.Add([ordered]@{
    Type = 'test_started'
    ObservedAt = (Get-Date -Format o)
    ProcessId = $testPid
    CreationDate = $testProcess.CreationDate
    CommandLine = $testProcess.CommandLine
})

while (-not $proc.HasExited) {
    $capturedAt = Get-Date -Format o
    $current = @(Get-CompetingProcesses)
    $samples.Add([ordered]@{ CapturedAt = $capturedAt; Processes = $current })
    foreach ($candidate in $current) {
        $isExactQwenChild = ($candidate.ExecutablePath -ieq $CompetitorExe) -and
            ($candidate.CommandLine -match '(?i)--strict-vulkan') -and
            ($candidate.CommandLine -match [regex]::Escape($CompetitorModel))
        if ($isExactQwenChild -and -not $handledPids.Contains([int]$candidate.ProcessId)) {
            [void]$handledPids.Add([int]$candidate.ProcessId)
            $events.Add([ordered]@{
                Type = 'authorized_qwen_benchmark_child_detected'
                ObservedAt = (Get-Date -Format o)
                ProcessId = $candidate.ProcessId
                ParentProcessId = $candidate.ParentProcessId
                CreationDate = $candidate.CreationDate
                ExecutablePath = $candidate.ExecutablePath
                CommandLine = $candidate.CommandLine
            })
            $wrapper = Get-CimInstance Win32_Process -Filter "ProcessId = $($candidate.ParentProcessId)" -ErrorAction SilentlyContinue
            $isExactWrapper = $wrapper -and ($wrapper.Name -ieq 'pwsh.exe') -and
                ($wrapper.CommandLine -match '(?i)deep2_gpu_flight_recorder\.ps1') -and
                ($wrapper.CommandLine -match [regex]::Escape($CompetitorModel))
            if ($isExactWrapper) {
                $events.Add([ordered]@{
                    Type = 'authorized_qwen_flight_recorder_wrapper_stopped'
                    ObservedAt = (Get-Date -Format o)
                    ProcessId = $wrapper.ProcessId
                    ParentProcessId = $wrapper.ParentProcessId
                    CreationDate = $wrapper.CreationDate
                    CommandLine = $wrapper.CommandLine
                })
                Stop-Process -Id $wrapper.ProcessId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 200
            }
            $liveChild = Get-CimInstance Win32_Process -Filter "ProcessId = $($candidate.ProcessId)" -ErrorAction SilentlyContinue
            if ($liveChild) {
                Stop-Process -Id $candidate.ProcessId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 300
            }
            $stillAlive = Get-CimInstance Win32_Process -Filter "ProcessId = $($candidate.ProcessId)" -ErrorAction SilentlyContinue
            $events.Add([ordered]@{
                Type = 'authorized_qwen_benchmark_child_exit_observed'
                ObservedAt = (Get-Date -Format o)
                ProcessId = $candidate.ProcessId
                StillAlive = [bool]$stillAlive
                CreationDate = $candidate.CreationDate
            })
        } elseif (-not $isExactQwenChild) {
            $events.Add([ordered]@{
                Type = 'external_process_observed'
                ObservedAt = $capturedAt
                ProcessId = $candidate.ProcessId
                ParentProcessId = $candidate.ParentProcessId
                Name = $candidate.Name
                CreationDate = $candidate.CreationDate
                ExecutablePath = $candidate.ExecutablePath
                CommandLine = $candidate.CommandLine
            })
        }
    }
    Start-Sleep -Milliseconds 500
    $proc.Refresh()
}

$proc.WaitForExit()
$finishedAt = Get-Date
$stdout = $stdoutTask.Result
$stderr = $stderrTask.Result
$code = $proc.ExitCode
[System.IO.File]::WriteAllText($StdoutLog, $stdout, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($StderrLog, $stderr, [System.Text.UTF8Encoding]::new($false))
$combined = $stdout
if ($stderr.Length -gt 0) { $combined += [Environment]::NewLine + '--- STDERR ---' + [Environment]::NewLine + $stderr }
[System.IO.File]::WriteAllText($Log, $combined, [System.Text.UTF8Encoding]::new($false))
[System.IO.File]::WriteAllText($ExitFile, [string]$code + [Environment]::NewLine, [System.Text.Encoding]::ASCII)
$post = @(Get-CompetingProcesses)
Write-JsonFile $PostFile ([ordered]@{ CapturedAt = $finishedAt.ToString('o'); Processes = $post })
Write-JsonFile $SamplesFile @($samples)
Write-JsonFile $EventsFile @($events)
$summary = [ordered]@{
    Mode = $Mode
    BaseCommit = '74fafe258498749cbd22d443752f8cc792ac31f9'
    StartedAt = $startedAt.ToString('o')
    FinishedAt = $finishedAt.ToString('o')
    DurationSeconds = ($finishedAt - $startedAt).TotalSeconds
    ExitCode = $code
    TestPid = $testPid
    Command = [System.IO.File]::ReadAllText($CommandFile).Trim()
    ModelPath = $Model
    ModelSizeBytes = (Get-Item -LiteralPath $Model).Length
    ModelSha256 = (Get-FileHash -LiteralPath $Model -Algorithm SHA256).Hash
    ExecutablePath = $Executable
    ExecutableSha256 = (Get-FileHash -LiteralPath $Executable -Algorithm SHA256).Hash
    TokenFileSha256 = (Get-FileHash -LiteralPath $TokenFile -Algorithm SHA256).Hash
    TokenCount = @($Tokens -split '\s+' | Where-Object { $_ -ne '' }).Count
    Device = 'AMD Radeon AI PRO R9700 (verified from executor log)'
    PreProcessCount = $pre.Count
    PostProcessCount = $post.Count
    ExternalProcessEvents = @($events | Where-Object { $_.Type -like 'external_process_observed' -or $_.Type -like 'authorized_qwen*' }).Count
    Samples = $samples.Count
}
Write-JsonFile $SummaryFile $summary
Write-Output "MODE=$Mode EXIT_CODE=$code PID=$testPid"
Write-Output "LOG=$Log"
Write-Output "PRE=$PreFile POST=$PostFile SAMPLES=$SamplesFile"
if ($code -ne 0) { exit $code }
