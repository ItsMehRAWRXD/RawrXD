# STATIC_DEP_001 — static scan on frozen shipping RawrXD-Win32IDE.exe
# Usage: .\scan_static_dep.ps1 -ExePath "F:\~dev\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe"
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ExePath)) {
    Write-Error "EXE not found: $ExePath"
}

$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$sha = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
$bytes = (Get-Item -LiteralPath $ExePath).Length

$report = @()
$report += "STATIC_DEP_001 SCAN"
$report += "TIMESTAMP_UTC=$stamp"
$report += "EXE_PATH=$ExePath"
$report += "SHA256=$sha"
$report += "BYTES=$bytes"
$report += ""

# --- Imports (dumpbin) ---
$dumpbin = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

$importsFile = Join-Path $outDir "DUMPBIN_IMPORTS_$sha.Substring(0,8).txt"
if ($dumpbin) {
    & $dumpbin /IMPORTS $ExePath 2>&1 | Out-File -FilePath $importsFile -Encoding utf8
    $importLines = Get-Content $importsFile -ErrorAction SilentlyContinue
    $networkDlls = $importLines | Select-String -Pattern "WINHTTP|WININET|WS2_32|URLMON|libcurl|CURL" -AllMatches
    $report += "DUMPBIN_IMPORTS=$importsFile"
    $report += "NETWORK_IMPORT_HITS=$($networkDlls.Count)"
    foreach ($h in $networkDlls) { $report += "  IMPORT: $($h.Line.Trim())" }
} else {
    $report += "DUMPBIN_IMPORTS=SKIPPED (dumpbin not found)"
}

$report += ""

# --- String literals (UTF-8 + ASCII scan) ---
$patterns = @(
    @{ Name = "PORT_11434"; Regex = "11434" },
    @{ Name = "PORT_11435"; Regex = "11435" },
    @{ Name = "PORT_9999";  Regex = ":9999|9999" },
    @{ Name = "PORT_8005";  Regex = ":8005|8005" },
    @{ Name = "LOCALHOST";  Regex = "localhost" },
    @{ Name = "OLLAMA";     Regex = "ollama" },
    @{ Name = "OPENAI";     Regex = "api\.openai\.com|openai\.com/v1" },
    @{ Name = "ANTHROPIC";  Regex = "api\.anthropic\.com|anthropic\.com" },
    @{ Name = "MOONSHOT";   Regex = "moonshot\.ai|api\.moonshot" },
    @{ Name = "DEEPSEEK";   Regex = "deepseek\.com/api" },
    @{ Name = "HF_HUB";     Regex = "huggingface\.co" }
)

$raw = [System.IO.File]::ReadAllBytes($ExePath)
$ascii = -join ($raw | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { "`n" } })
$stringsFile = Join-Path $outDir "STRINGS_HITS_$sha.Substring(0,8).txt"
$hitLines = New-Object System.Collections.Generic.List[string]

foreach ($p in $patterns) {
    $matches = [regex]::Matches($ascii, $p.Regex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $count = $matches.Count
    $report += "STRING_$($p.Name)_COUNT=$count"
    if ($count -gt 0 -and $count -le 20) {
        foreach ($m in $matches) {
            $start = [Math]::Max(0, $m.Index - 40)
            $len = [Math]::Min(120, $ascii.Length - $start)
            $ctx = $ascii.Substring($start, $len) -replace "`n", " "
            $hitLines.Add("$($p.Name): $ctx")
        }
    } elseif ($count -gt 20) {
        $hitLines.Add("$($p.Name): $($count) hits (truncated)")
    }
}

$hitLines | Out-File -FilePath $stringsFile -Encoding utf8
$report += "STRINGS_DETAIL=$stringsFile"
$report += ""

# --- Verdict helper (informational — human reviews hits) ---
$failPorts = @("PORT_11434", "PORT_9999", "PORT_8005")
$portFail = $false
foreach ($line in $report) {
    foreach ($fp in $failPorts) {
        if ($line -match "^STRING_${fp}_COUNT=(\d+)$" -and [int]$Matches[1] -gt 0) {
            $portFail = $true
        }
    }
}
$report += "AUTOMATED_PORT_LITERAL_FAIL=$portFail"
$report += "NOTE=Review STRINGS_HITS for benign UI/docs vs live endpoint defaults"

$reportPath = Join-Path $outDir "SCAN_RESULT_$sha.Substring(0,8).txt"
$report | Out-File -FilePath $reportPath -Encoding utf8
Write-Output ($report -join "`n")
Write-Output "WROTE $reportPath"
