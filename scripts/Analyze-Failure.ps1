#!/usr/bin/env pwsh
param(
    [Parameter(Mandatory = $true)]
    [string]$LogPath,
    [string]$OutReportPath
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $LogPath)) {
    throw "Log file not found: $LogPath"
}

$content = Get-Content -Path $LogPath -Raw
$lines = Get-Content -Path $LogPath

$leaf = Split-Path -Path $LogPath -Leaf
$lastEvent = ($lines | Where-Object { $_ -like "Last event:*" } | Select-Object -Last 1)
if (-not $lastEvent) {
    $lastEvent = ""
}

$exceptionCode = ""
$exceptionType = "Unknown"

# WinDbg first-chance line patterns.
$evtMatches = [regex]::Matches($content, "\):\s+(.+?)\s+-\s+code\s+([0-9a-fA-F]{8})")
if ($evtMatches.Count -gt 0) {
    $m = $evtMatches[$evtMatches.Count - 1]
    $exceptionType = $m.Groups[1].Value.Trim()
    $exceptionCode = ("0x{0}" -f $m.Groups[2].Value.ToLowerInvariant())
}

if (-not $exceptionCode -and $content -match "ExceptionCode:\s*(0x[0-9A-Fa-f]+)") {
    $exceptionCode = $Matches[1].ToLowerInvariant()
}

$faultingIp = ""
if ($content -match '\brip=([0-9a-fA-F`]+)') {
    $faultingIp = ("0x{0}" -f ($Matches[1] -replace '`', ''))
}

$faultingSymbol = ""
$symbolLine = ($lines | Where-Object { $_ -match "!" } | Select-Object -Last 1)
if ($symbolLine) {
    # Example: ntdll!NtTerminateProcess+0x14:
    $s = [regex]::Match($symbolLine, "([A-Za-z0-9_.-]+![A-Za-z0-9_<>.$@?]+)")
    if ($s.Success) {
        $faultingSymbol = $s.Groups[1].Value
    }
}

$obsInjected = $content -match "graphics-hook64\.dll"

$firstNonSystemFrame = ""
$stackFrames = $lines | Where-Object {
    $_ -match '^\s*[0-9a-fA-F`]+\s+[0-9a-fA-F`]+\s+'
}
foreach ($frame in $stackFrames) {
    if ($frame -match "\s+([A-Za-z0-9_.-]+![A-Za-z0-9_<>.$@?]+)") {
        $sym = $Matches[1]
        $mod = ($sym -split "!")[0].ToLowerInvariant()
        if ($mod -notin @("ntdll", "kernel32", "kernelbase", "ucrtbase")) {
            $firstNonSystemFrame = $sym
            break
        }
    }
}

$faultingModule = "Unknown"
$sourceSymbol = if ($firstNonSystemFrame) { $firstNonSystemFrame } else { $faultingSymbol }
if ($sourceSymbol) {
    $mod = ($sourceSymbol -split "!")[0]
    if ($mod -match "(?i)RawrXD_VulkanValidationTax|RawrXD-VulkanValidationTax") {
        $faultingModule = "RawrXD"
    } elseif ($mod -match "(?i)graphics-hook64") {
        $faultingModule = "OBS_HOOK"
    } elseif ($mod -match "(?i)amdihk64|amdvlk64") {
        $faultingModule = "AMD_HOOK"
    } elseif ($mod -match "(?i)ntdll|kernel32|kernelbase|ucrtbase") {
        $faultingModule = "SystemRuntime"
    } else {
        $faultingModule = $mod
    }
} elseif ($content -match "(?i)graphics-hook64") {
    $faultingModule = "OBS_HOOK"
}

$isCleanExit = $lastEvent -match "Exit process .* code 0"
$isFatal = (-not $isCleanExit) -and ($lastEvent -ne "")

if ($isCleanExit) {
    $exceptionCode = ""
    $exceptionType = "CleanExit"
}

$verdict = if ($isFatal) {
    if ($exceptionCode -eq "0xc0000005") {
        "AccessViolation"
    } elseif ($lastEvent -match "Exit process .* code ffffffff") {
        "ProcessAbort"
    } elseif ($exceptionCode -in @("0xc0000409", "0x80000003")) {
        "FastFailOrBreakpoint"
    } elseif ($exceptionCode) {
        "FatalException"
    } else {
        "FatalEvent"
    }
} else {
    "CleanExitOrNoSignal"
}

$report = [PSCustomObject]@{
    Attempt = $leaf
    LogPath = $LogPath
    TimestampUtc = (Get-Date).ToUniversalTime().ToString("o")
    LastEvent = $lastEvent
    IsFatalEvent = $isFatal
    ExceptionCode = $exceptionCode
    ExceptionType = $exceptionType
    FaultingIP = $faultingIp
    FaultingSymbol = $faultingSymbol
    FaultingModule = $faultingModule
    FirstNonSystemFrame = $firstNonSystemFrame
    OBSInjected = $obsInjected
    Verdict = $verdict
}

if ($OutReportPath) {
    $existing = @()
    if (Test-Path $OutReportPath) {
        $raw = Get-Content -Path $OutReportPath -Raw
        if ($raw.Trim()) {
            try {
                $parsed = $raw | ConvertFrom-Json
                if ($parsed -is [System.Array]) {
                    $existing = @($parsed)
                } else {
                    $existing = @($parsed)
                }
            } catch {
                $existing = @()
            }
        }
    }

    $combined = @($existing + $report)
    $combined | ConvertTo-Json -Depth 6 | Set-Content -Path $OutReportPath -Encoding UTF8
}

$report
