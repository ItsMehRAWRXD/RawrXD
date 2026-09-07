# STATIC_DEP_001 — fast binary literal scan (chunked, no full ASCII materialization)
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path -LiteralPath $ExePath)) { throw "EXE not found: $ExePath" }

$outDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$stamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
$sha = (Get-FileHash -LiteralPath $ExePath -Algorithm SHA256).Hash
$bytes = (Get-Item -LiteralPath $ExePath).Length

function Count-AsciiLiteral([byte[]]$hay, [string]$needle) {
    $n = [System.Text.Encoding]::ASCII.GetBytes($needle)
    $count = 0
    $limit = $hay.Length - $n.Length
    for ($i = 0; $i -le $limit; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $n.Length; $j++) {
            if ($hay[$i + $j] -ne $n[$j]) { $ok = $false; break }
        }
        if ($ok) { $count++ }
    }
    return $count
}

$literals = @(
    "11434", "11435", ":9999", ":8005",
    "localhost", "ollama", "api.openai.com", "api.anthropic.com",
    "moonshot.ai", "huggingface.co", "deepseek.com"
)

$fs = [System.IO.File]::OpenRead($ExePath)
$chunkSize = 8MB
$overlap = 64
$buf = New-Object byte[] $chunkSize
$totals = @{}
foreach ($lit in $literals) { $totals[$lit] = 0 }

try {
    $carry = New-Object byte[] 0
    while (($read = $fs.Read($buf, 0, $chunkSize)) -gt 0) {
        $segment = if ($carry.Length -gt 0) {
            $tmp = New-Object byte[] ($carry.Length + $read)
            [Array]::Copy($carry, 0, $tmp, 0, $carry.Length)
            [Array]::Copy($buf, 0, $tmp, $carry.Length, $read)
            $tmp
        } else {
            $buf[0..($read - 1)]
        }
        foreach ($lit in $literals) {
            $totals[$lit] += Count-AsciiLiteral $segment $lit
        }
        if ($segment.Length -gt $overlap) {
            $carry = $segment[($segment.Length - $overlap)..($segment.Length - 1)]
        } else {
            $carry = $segment
        }
    }
} finally {
    $fs.Close()
}

$report = @(
    "STATIC_DEP_001 FAST SCAN",
    "TIMESTAMP_UTC=$stamp",
    "EXE_PATH=$ExePath",
    "SHA256=$sha",
    "BYTES=$bytes",
    ""
)
foreach ($lit in $literals) {
    $report += "LITERAL_$lit=$($totals[$lit])"
}

$dumpbin = @(
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe",
    "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if ($dumpbin) {
    $importsFile = Join-Path $outDir "DUMPBIN_IMPORTS_$($sha.Substring(0,8)).txt"
    & $dumpbin /IMPORTS $ExePath 2>&1 | Out-File -FilePath $importsFile -Encoding utf8
    $hits = (Get-Content $importsFile | Select-String -Pattern "WINHTTP|WININET|WS2_32|URLMON|libcurl")
    $report += ""
    $report += "DUMPBIN_IMPORTS=$importsFile"
    $report += "NETWORK_IMPORT_HITS=$($hits.Count)"
    foreach ($h in $hits) { $report += "  $($h.Line.Trim())" }
}

$report += ""
$report += "STATUS=INFORMATIONAL - review non-zero literals for benign strings vs live defaults"
$out = Join-Path $outDir "SCAN_RESULT_$($sha.Substring(0,8)).txt"
$report | Out-File -FilePath $out -Encoding utf8
Write-Output ($report -join "`n")
Write-Output "WROTE $out"
