#!/usr/bin/env pwsh
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$DDUPath = "D:\DDU\DDU.exe",
    [string]$DriverPackagePath = "D:\rawrxd\drivers\AMD",
    [string]$LogRoot = "D:\rawrxd\logs",
    [string]$StatePath = "D:\rawrxd\logs\cleanroom_state.json",
    [switch]$SkipReboot,
    [switch]$SkipDriverGate
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param(
        [Parameter(Mandatory)] [string]$Level,
        [Parameter(Mandatory)] [string]$Message
    )

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $line = "[$ts] [$Level] $Message"
    Write-Host $line
    if ($script:LogPath) {
        Add-Content -Path $script:LogPath -Value $line -ErrorAction SilentlyContinue
    }
}

function Resolve-FirstExistingPath {
    param(
        [Parameter(Mandatory)] [string[]]$Candidates
    )

    foreach ($candidate in $Candidates) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }

        if (Test-Path -LiteralPath $candidate) {
            try {
                return (Resolve-Path -LiteralPath $candidate).Path
            } catch {
                return $candidate
            }
        }
    }

    return $null
}

function Get-DefaultDduCandidates {
    return @(
        $DDUPath,
        'D:\DDU\DDU.exe',
        'C:\DDU\DDU.exe',
        'D:\Tools\DDU\DDU.exe',
        'C:\Tools\DDU\DDU.exe',
        'C:\Users\HiH8e\Downloads\DDU\DDU.exe',
        'C:\Users\HiH8e\Desktop\DDU\DDU.exe'
    )
}

function Get-DefaultDriverPackageCandidates {
    return @(
        $DriverPackagePath,
        'D:\rawrxd\drivers\AMD',
        'D:\AMD',
        'C:\AMD',
        'C:\Users\HiH8e\Downloads\AMD',
        'C:\Users\HiH8e\Desktop\AMD'
    )
}

function Test-IsSafeMode {
    $optionPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option"
    try {
        if (Test-Path $optionPath) {
            $option = Get-ItemProperty -Path $optionPath -Name OptionValue -ErrorAction SilentlyContinue
            if ($null -ne $option -and $option.OptionValue -in 1, 2) {
                return $true
            }
        }
    } catch {
    }

    return $false
}

function Read-State {
    if (Test-Path $script:StatePath) {
        try {
            $raw = Get-Content -Path $script:StatePath -Raw
            if ($raw.Trim()) {
                return $raw | ConvertFrom-Json
            }
        } catch {
        }
    }

    return [pscustomobject]@{
        Stage = "Start"
        UpdatedUtc = (Get-Date).ToUniversalTime().ToString("o")
    }
}

function Save-State {
    param(
        [Parameter(Mandatory)] [string]$Stage,
        [Parameter(Mandatory)] [string]$Note
    )

    $state = [ordered]@{
        Stage = $Stage
        Note = $Note
        UpdatedUtc = (Get-Date).ToUniversalTime().ToString("o")
    }

    $state | ConvertTo-Json -Depth 4 | Set-Content -Path $script:StatePath -Encoding UTF8
}

function Clear-SafeBootFlag {
    Write-Log "INFO" "Clearing Safe Mode boot flag..."
    & bcdedit /deletevalue '{current}' safeboot | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "WARN" "bcdedit returned $LASTEXITCODE while clearing safeboot."
    }
}

New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
$script:LogPath = Join-Path $LogRoot ("cleanroom_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

Write-Log "INFO" "=== CleanRoom Pipeline Initiated ==="
Write-Log "INFO" "DDU Target: $DDUPath"
Write-Log "INFO" "Driver Package: $DriverPackagePath"
Write-Log "INFO" "State Path: $StatePath"

$resolvedDduPath = Resolve-FirstExistingPath -Candidates (Get-DefaultDduCandidates)
if ($resolvedDduPath) {
    Write-Log "INFO" "Resolved DDU path: $resolvedDduPath"
} else {
    Write-Log "WARN" "DDU not found in default locations. Pass -DDUPath to the actual executable path."
}

$resolvedDriverRoot = Resolve-FirstExistingPath -Candidates (Get-DefaultDriverPackageCandidates)
if ($resolvedDriverRoot) {
    Write-Log "INFO" "Resolved driver package root: $resolvedDriverRoot"
} else {
    Write-Log "WARN" "Driver package root not found in default locations. Pass -DriverPackagePath to the extracted AMD driver-only package."
}

$state = Read-State
$safeMode = Test-IsSafeMode
Write-Log "INFO" "Detected stage: $($state.Stage)"
Write-Log "INFO" "Safe Mode detected: $safeMode"

if ($state.Stage -eq "Start" -and -not $safeMode) {
    Write-Log "INFO" "Setting Safe Mode flag for next reboot..."
    & bcdedit /set '{current}' safeboot minimal | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to set Safe Mode boot flag."
    }

    Save-State -Stage "AwaitingSafeMode" -Note "Safe Mode flag set; reboot to launch DDU."
    Write-Log "INFO" "Reboot required to enter Safe Mode."

    if (-not $SkipReboot) {
        Write-Log "INFO" "Rebooting now..."
        & shutdown /r /t 0 | Out-Null
    }

    exit 0
}

if ($safeMode -and ($state.Stage -in @("AwaitingSafeMode", "Start"))) {
    if (-not $resolvedDduPath) {
        Write-Log "FATAL" "DDU not found at any candidate path."
        Write-Log "FATAL" "Extract DDU or pass -DDUPath to the actual executable path."
        exit 1
    }

    Save-State -Stage "AwaitingPostDdu" -Note "DDU launched in Safe Mode. Run Clean and Restart manually."
    Write-Log "INFO" "Launching DDU in Safe Mode. Use Clean and Restart in the GUI."
    Write-Log "INFO" "This script will resume after the reboot into normal Windows."
    Start-Process -FilePath $resolvedDduPath -ErrorAction Stop | Out-Null
    exit 0
}

if ($state.Stage -eq "AwaitingPostDdu") {
    Clear-SafeBootFlag
    Save-State -Stage "AwaitingDriverGate" -Note "Safe Mode cleared; ready for driver-only install gate."

    if ($safeMode) {
        Write-Log "INFO" "Safe Mode flag cleared while still in Safe Mode. Rebooting to normal Windows..."
        if (-not $SkipReboot) {
            & shutdown /r /t 0 | Out-Null
        }

        exit 0
    }
}

if ($state.Stage -eq "AwaitingDriverGate" -or $state.Stage -eq "AwaitingPostDdu" -or $state.Stage -eq "Start") {
    if ($SkipDriverGate) {
        Write-Log "INFO" "Driver gate skipped by request."
        exit 0
    }

    if (-not $resolvedDriverRoot) {
        Write-Log "FATAL" "Driver package root not found at any candidate path."
        Write-Log "FATAL" "Extract the driver-only package to that path or pass -DriverPackagePath."
        exit 1
    }

    $setupExe = Get-ChildItem -Path $resolvedDriverRoot -Filter "setup.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    $infFiles = Get-ChildItem -Path $resolvedDriverRoot -Filter "*.inf" -Recurse -ErrorAction SilentlyContinue

    Write-Log "INFO" "Driver gate reached. Use the vendor's driver-only installer from $resolvedDriverRoot."

    if ($setupExe) {
        Write-Log "INFO" "Found installer: $($setupExe.FullName)"
        Write-Log "INFO" "Launch the installer and choose Driver Only if the GUI prompts for that option."
        Start-Process -FilePath $setupExe.FullName -ErrorAction Stop | Out-Null
    } elseif ($infFiles) {
        $primaryInf = $infFiles | Select-Object -First 1
        Write-Log "INFO" "Found INF: $($primaryInf.FullName)"
        Write-Log "INFO" "Use pnputil /add-driver '$($primaryInf.FullName)' /install if you want a silent INF-based path."
    } else {
        Write-Log "WARN" "No setup.exe or INF files were found."
    }

    Save-State -Stage "Complete" -Note "Driver gate executed. Rerun the contamination gate after installation."
    Write-Log "INFO" "=== CleanRoom Pipeline Complete ==="
    exit 0
}

Write-Log "WARN" "State file indicates an unrecognized stage: $($state.Stage)"
Write-Log "WARN" "Delete $StatePath to restart the pipeline from the beginning."