# Dot-source this file in PowerShell to expose rawr run immediately without
# changing or replacing the existing rawr.exe:
# . F:\rawrxd\tools\rawr_run_dropin\activate.ps1
# This session-local function is a bridge; native CLI integration is documented.
$global:RawrAgentExecutable = Join-Path (Split-Path -Parent $PSCommandPath) 'build\Release\rawr_run.exe'
if (-not (Test-Path $global:RawrAgentExecutable)) {
    $global:RawrAgentExecutable = Join-Path (Split-Path -Parent $PSCommandPath) 'build\rawr_run.exe'
}
if (-not (Test-Path $global:RawrAgentExecutable)) {
    $global:RawrAgentExecutable = Join-Path (Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))) 'build_rawr_run\Release\rawr_run.exe'
}
if (-not (Test-Path $global:RawrAgentExecutable)) {
    throw "Build rawr_run.exe first with CMake (see INTEGRATE_INTO_RAWR.md) or update RawrAgentExecutable."
}
# Ensure every GPU/display adapter is active before `rawr run <model> '<task>'`
# launches rawr_run.exe. A secondary card that Windows disabled (Device Manager
# Code 31 "the drivers required for this device cannot be loaded", Code 22
# "this device is disabled", or Code 43 "Windows stopped this device") breaks
# dual-card inference, so reset/re-enable it here instead of requiring manual
# Device Manager intervention.
#
# Production safeguards:
#   * RAWR_PRIMARY_GPU_ID MUST be set before any automatic recovery occurs;
#     no recovery is attempted if the primary is not explicitly identified
#   * Code 10 (power failure) is reported as an unsupported recovery condition
#     and never automatically restarted
#   * Only one controlled restart attempt per GPU per invocation
#   * Only target explicitly configured secondary GPU instance IDs
#       (RAWR_SECONDARY_GPU_IDS env var, comma-separated, or gpu_config.json
#        secondaryGpuInstanceIds)
#   * Never disrupt a GPU with active Deep2/rawr inference work
#   * Poll PnP state until healthy or timeout (no fixed blind delay)
#   * Validate the *recovered* GPU's specific identity in Vulkan output
#   * Fail closed: if admission fails, rawr run is aborted
#   * Emit gpu_recovery_attempted / gpu_recovery_result / gpu_admission_result
#     telemetry to evidence\gpu_recovery_telemetry.json
#
# Environment:
#   RAWR_DISABLE_GPU_RESET=1     skip all GPU recovery
#   RAWR_PRIMARY_GPU_ID=<instance id>   REQUIRED - GPU instance ID to never touch
#   RAWR_SECONDARY_GPU_IDS=<id1>,<id2>  eligible secondary GPU instance IDs
#   RAWR_GPU_RESET_TIMEOUT_MS    PnP poll timeout in ms (default 30000)
function global:Reset-RawrGpuDevices {
    param([switch]$Quiet)

    if ($env:RAWR_DISABLE_GPU_RESET -eq '1') {
        if (-not $Quiet) { Write-Host "[rawr] GPU reset skipped (RAWR_DISABLE_GPU_RESET=1)" }
        return @{ attempted=$false; recovery_result="skipped"; admission_result="not_evaluated"; devices=@() }
    }

    $result = @{
        attempted           = $false
        recovery_result     = "none"
        admission_result    = "not_evaluated"
        devices             = @()
    }

    # --- Resolve paths ---
    $dropRoot = Split-Path -Parent $PSCommandPath
    $repoRoot = (Resolve-Path (Join-Path $dropRoot '..\..\..')).Path
    $telemetryDir = Join-Path $repoRoot 'evidence'
    $telemetryPath = Join-Path $telemetryDir 'gpu_recovery_telemetry.json'

    $timeoutMs = 30000
    $tmp = 0
    if ($env:RAWR_GPU_RESET_TIMEOUT_MS -and [int]::TryParse($env:RAWR_GPU_RESET_TIMEOUT_MS, [ref]$tmp)) {
        $timeoutMs = $tmp
    }

    # --- 0. Require explicit primary GPU ID before any recovery ---
    # gpu_config.json is an explicit hardware binding, not autodetection.
    $configPath = Join-Path $repoRoot 'gpu_config.json'
    $cfg = $null
    if (Test-Path $configPath) {
        try { $cfg = Get-Content $configPath -Raw | ConvertFrom-Json } catch { $cfg = $null }
    }
    $primaryId = $env:RAWR_PRIMARY_GPU_ID
    if (-not $primaryId -and $cfg -and $cfg.PSObject.Properties.Name -contains 'primaryGpuInstanceId') {
        $primaryId = [string]$cfg.primaryGpuInstanceId
    }
    if (-not $primaryId) {
        if (-not $Quiet) { Write-Host "[rawr] GPU reset skipped: RAWR_PRIMARY_GPU_ID not set - refusing to guess primary GPU" -ForegroundColor Yellow }
        $result.admission_result = "skipped_no_primary_configured"
        return $result
    }

    # --- 1. GPU inventory ---
    $devices = @()
    try {
        $devices = Get-CimInstance Win32_PnPEntity -Filter 'PNPClass = "Display"' -ErrorAction SilentlyContinue |
            Select-Object -Unique
    } catch {
        if (-not $Quiet) { Write-Host "[rawr] WMI display enumeration failed: $_" -ForegroundColor Yellow }
    }

    # --- 2. Configured secondary GPU instance IDs ---
    $configuredIds = @()
    $rawIds = $env:RAWR_SECONDARY_GPU_IDS
    if ($rawIds) {
        $configuredIds += $rawIds.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    if ($cfg -and $cfg.PSObject.Properties.Name -contains 'secondaryGpuInstanceIds') {
        $configuredIds += @($cfg.secondaryGpuInstanceIds)
    }
    $configuredIds = $configuredIds | Select-Object -Unique

    # --- 2b. Vulkan inventory (detects a present-but-not-visible GPU) ---
    $vkOut = @()
    $vulkanAvailable = $false
    try {
        $vkOut = @(vulkaninfo --summary 2>$null)
        $vulkanAvailable = ($LASTEXITCODE -eq 0 -and $vkOut.Count -gt 0)
    } catch {}

    # --- 3. Active inference detection (Deep2 + rawr runners + CLI workloads) ---
    $inferenceRunning = $false
    try {
        $inferenceNames = @('deep2_strata_bench', 'deep2_bench_tps', 'deep2_parity_trace',
                            'deep2_spec_bench', 'deep2_runtime_dispatch', 'deep2_engine',
                            'deep2_cert', 'deep2_smoke', 'rawr_run', 'rawr', 'python', 'ollama', 'ollama app')
        foreach ($name in $inferenceNames) {
            $procs = Get-CimInstance Win32_Process -Filter "Name = '$name.exe'" -ErrorAction SilentlyContinue
            if ($procs) { $inferenceRunning = $true; break }
        }
    } catch {}

    # --- 4. Process each candidate ---
    foreach ($d in $devices) {
        $id   = $d.DeviceID
        $name = $d.Name
        $origCode = $d.ConfigManagerErrorCode
        $origStatus = $d.Status

        # Explicit primary GPU protection - never touch the primary
        if ($id -eq $primaryId) {
            if (-not $Quiet) { Write-Host "[rawr] skipping primary GPU $name ($id) - RAWR_PRIMARY_GPU_ID protected" -ForegroundColor Cyan }
            continue
        }

        # Only target explicitly configured secondary GPUs
        if ($configuredIds.Count -and ($configuredIds -notcontains $id)) {
            if (-not $Quiet) { Write-Host "[rawr] skipping $name ($id) - not in RAWR_SECONDARY_GPU_IDS / gpu_config.json" -ForegroundColor Cyan }
            continue
        }

        # Skip healthy secondary GPUs only when Vulkan also exposes them.
        $vulkanVisible = $true
        if ($vulkanAvailable) {
            $vulkanVisible = [bool]($vkOut | Where-Object { $_ -match [regex]::Escape($name) })
        }
        if ($origCode -eq 0 -and $origStatus -eq 'OK' -and $vulkanVisible) {
            continue
        }

        if ($origCode -eq 0 -and $origStatus -eq 'OK' -and -not $vulkanVisible -and -not $Quiet) {
            Write-Host "[rawr] GPU $name ($id) is absent from Vulkan; attempting controlled recovery" -ForegroundColor Yellow
        }

        # --- 5. Code 10 is explicitly unsupported ---
        if ($origCode -eq 10) {
            if (-not $Quiet) { Write-Host "[rawr] GPU $name ($id) Code=10 (STATUS_DEVICE_POWER_FAILURE) - unsupported recovery condition, denial recorded" -ForegroundColor Yellow }
            $result.devices += @{
                id=$id; name=$name; originalCode=$origCode; action="denied_code10";
                reason="unsupported_power_failure"; finalCode=$origCode
            }
            continue
        }

        # Recover explicit fault/disabled codes (31, 22, and 43). A healthy
        # WMI device missing from Vulkan is also a recovery target.
        if ($origCode -ne 31 -and $origCode -ne 22 -and $origCode -ne 43 -and $vulkanVisible) {
            if (-not $Quiet) { Write-Host "[rawr] skipping $name ($id) - Code $origCode is not a recoverable target (22/31/43 only)" -ForegroundColor Cyan }
            continue
        }

        # --- 6. Active inference guard ---
        if ($inferenceRunning) {
            if (-not $Quiet) { Write-Host "[rawr] skipping $name ($id) - active inference detected, refusing disruptive reset" -ForegroundColor Yellow }
            $result.attempted = $true
            $result.recovery_result = "blocked_active_inference"
            $result.devices += @{
                id=$id; name=$name; originalCode=$origCode; action="skipped";
                reason="active_inference"; finalCode=$origCode
            }
            continue
        }

        # --- 7. Controlled single restart (max one attempt per GPU) ---
        $result.attempted = $true
        if (-not $Quiet) { Write-Host "[rawr] GPU faulted: $name ($id) Code=$origCode - controlled restart (attempt 1/1)" -ForegroundColor Yellow }

        $restarted = $false
        pnputil /restart-device $id 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $restarted = $true }
        else {
            if (-not $Quiet) { Write-Host "[rawr] restart-device failed for $id; trying enable-device" -ForegroundColor Yellow }
            pnputil /enable-device $id 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $restarted = $true }
        }

        if (-not $restarted) {
            $result.recovery_result = "failed"
            $result.devices += @{
                id=$id; name=$name; originalCode=$origCode; action="restart_failed";
                finalCode=$origCode
            }
            continue
        }

        # --- 8. Poll PnP state until healthy or timeout ---
        $pollMs = 0
        $pollIntervalMs = 1000
        $recovered = $false
        $finalCode = $null
        $finalStatus = $null

        while ($pollMs -lt $timeoutMs) {
            Start-Sleep -Milliseconds $pollIntervalMs
            $pollMs += $pollIntervalMs

            $d2 = Get-CimInstance Win32_PnPEntity -Filter "DeviceID = '$id'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($d2) {
                $finalCode   = $d2.ConfigManagerErrorCode
                $finalStatus = $d2.Status
                if ($finalCode -eq 0 -and $finalStatus -eq 'OK') {
                    $recovered = $true
                    break
                }
            }
        }

        if (-not $recovered) {
            $result.recovery_result = "failed"
            $result.devices += @{
                id=$id; name=$name; originalCode=$origCode; action="restarted_but_unhealthy";
                finalCode=$finalCode
            }
            continue
        }

        $result.recovery_result = "succeeded"
        $result.devices += @{
            id=$id; name=$name; originalCode=$origCode; action="restarted";
            finalCode=$finalCode; recoveredName=$name
        }
    }

    # A configured secondary that disappeared from WMI cannot be reset by
    # instance ID until Windows rescans the PCIe bus. Request one rescan and
    # record the missing identity without guessing at another device.
    if ($configuredIds.Count) {
        $seenIds = @($devices | ForEach-Object { $_.DeviceID })
        foreach ($missingId in ($configuredIds | Where-Object { $seenIds -notcontains $_ })) {
            $result.attempted = $true
            if (-not $Quiet) { Write-Host "[rawr] configured GPU is not enumerated: $missingId; requesting PCIe rescan" -ForegroundColor Yellow }
            pnputil /scan-devices 2>&1 | Out-Null
            $result.devices += @{ id=$missingId; name=''; originalCode=$null; action='missing'; finalCode=$null }
        }
    }

    # --- 9. Vulkan identity validation (match every configured secondary) ---
    $vulkanOk = $true
    if ($configuredIds.Count -and $vulkanAvailable) {
        foreach ($dev in $devices) {
            if ($configuredIds -contains $dev.DeviceID -and $dev.Name) {
                if (-not ($vkOut | Where-Object { $_ -match [regex]::Escape($dev.Name) })) {
                    $vulkanOk = $false
                }
            }
        }
        if ($result.devices | Where-Object { $_.action -eq 'missing' }) { $vulkanOk = $false }
    } elseif ($configuredIds.Count -and -not $vulkanAvailable) {
        $vulkanOk = $false
        if (-not $result.attempted) {
            $result.attempted = $true
            $result.recovery_result = "vulkan_validation_unavailable"
        }
    }

    # --- 10. Admission decision ---
    if ($result.attempted -and $result.recovery_result -eq 'succeeded' -and $vulkanOk) {
        $result.admission_result = "admitted"
    } elseif ($result.attempted -and $result.recovery_result -ne 'succeeded') {
        $result.admission_result = "denied_recovery_failed"
    } elseif ($result.attempted -and -not $vulkanOk) {
        $result.admission_result = "denied_no_vulkan"
    } else {
        $result.admission_result = "no_recovery_needed"
    }

    # --- 11. ESP telemetry (non-fatal) ---
    try {
        if (-not (Test-Path $telemetryDir)) { New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null }
        $telemetry = @{
            timestamp             = (Get-Date -Format "o")
            event                 = "gpu_recovery"
            gpu_recovery_attempted = $result.attempted
            gpu_recovery_result    = $result.recovery_result
            gpu_admission_result   = $result.admission_result
            devices                = $result.devices
            vulkan_available       = $vulkanAvailable
            primary_gpu_id         = $primaryId
        }
        $telemetry | ConvertTo-Json -Depth 3 | Out-File $telemetryPath -Encoding UTF8
    } catch {
        # Telemetry must not block inference
    }

    if (-not $Quiet) {
        Write-Host "[rawr] GPU recovery: attempted=$($result.attempted) result=$($result.recovery_result) admission=$($result.admission_result)" -ForegroundColor Cyan
    }

    return $result
}

$original = Get-Command rawr.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$global:RawrOriginalExecutable = if ($original) { $original.Source } else { $null }
function global:rawr {
    if ($args.Count -gt 0 -and $args[0] -eq 'run') {
        # GPU admission control: reset/re-enable faulted secondary GPUs before
        # the model run starts. Fail closed if admission cannot be granted.
        $gpuResult = Reset-RawrGpuDevices
        if ($gpuResult.admission_result -notin @('admitted', 'no_recovery_needed')) {
            throw "GPU admission failed: $($gpuResult.admission_result). Aborting rawr run."
        }
        $runExit = 0
        try {
            & $global:RawrAgentExecutable @args
            if ($null -ne $LASTEXITCODE) { $runExit = $LASTEXITCODE }
        } finally {
            # Re-check after the task exits, when no runner process is holding
            # a Vulkan context, and record any recovery attempt.
            $postGpuResult = Reset-RawrGpuDevices
            if ($postGpuResult.attempted -and $postGpuResult.admission_result -in @('denied_recovery_failed', 'denied_no_vulkan')) {
                Write-Warning "GPU post-run admission failed: $($postGpuResult.admission_result)"
            }
        }
        $global:LASTEXITCODE = $runExit
        return
    }
    if ($global:RawrOriginalExecutable) {
        & $global:RawrOriginalExecutable @args
        return
    }
    throw 'Original rawr.exe not available; only rawr run is supported.'
}
Write-Host "RawrXD agent session command ready: rawr run <model> '<task>'"
