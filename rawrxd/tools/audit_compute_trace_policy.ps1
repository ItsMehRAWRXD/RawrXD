# Compute trace audit tool
# This PowerShell script audits compute trace policies for contamination

param(
    [string]$OutputPath = "F:\~dev\_compute_trace_audit.txt"
)

$auditResults = @()
$auditResults += "=== COMPUTE TRACE AUDIT ==="
$auditResults += "Timestamp: $(Get-Date)"
$auditResults += ""

# Check for unconditional hotpath traces in compute files
$computeFiles = Get-ChildItem -Path "F:\~dev\rawrxd\src\compute" -Filter "*.cpp" -ErrorAction SilentlyContinue
$hotpathTraces = @()

foreach ($file in $computeFiles) {
    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
    if ($content -match "DEEP2_TRACE_FORWARD|RAWRXD_VERBOSE|RAWRXD_TRACE_TOKEN.*=.*1") {
        $hotpathTraces += $file.Name
    }
}

$auditResults += "Found files with unconditional hotpath traces: $($hotpathTraces.Count)"
if ($hotpathTraces.Count -gt 0) {
    $auditResults += "Files: $($hotpathTraces -join ", ")"
}
$auditResults += ""

# Check for silent returns in compute files
$silentReturns = @()
foreach ($file in $computeFiles) {
    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
    if ($content -match "return;\s*//.*silent" -or $content -match "void.*\(\)\s*\{\s*return;\s*\}") {
        $silentReturns += $file.Name
    }
}

$auditResults += "Found files with silent returns: $($silentReturns.Count)"
if ($silentReturns.Count -gt 0) {
    $auditResults += "Files: $($silentReturns -join ", ")"
}
$auditResults += ""

# Check for empty gates in compute files
$emptyGates = @()
foreach ($file in $computeFiles) {
    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
    if ($content -match "//.*EMPTY_GATE" -or $content -match "TODO.*GATE") {
        $emptyGates += $file.Name
    }
}

$auditResults += "Found files with empty gates: $($emptyGates.Count)"
if ($emptyGates.Count -gt 0) {
    $auditResults += "Files: $($emptyGates -join ", ")"
}
$auditResults += ""

# Check for trace spam in compute files
$traceSpam = @()
foreach ($file in $computeFiles) {
    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
    if ($content -match "std::cout.*<<.*TRACE.*<<.*std::endl" -and $content.CountMatch("std::cout.*<<.*TRACE.*<<.*std::endl") -gt 10) {
        $traceSpam += "$($file.Name) (count: $( $content.CountMatch("std::cout.*<<.*TRACE.*<<.*std::endl") ))"
    }
}

$auditResults += "Found files with trace spam: $($traceSpam.Count)"
if ($traceSpam.Count -gt 0) {
    $auditResults += "Files: $($traceSpam -join ", ")"
}
$auditResults += ""

# Check for missing receipt in compute files
$missingReceipts = @()
foreach ($file in $computeFiles) {
    $content = Get-Content $file.FullName -ErrorAction SilentlyContinue
    if ($content -match "write.*Receipt" -and !$content -match "write.*Receipt.*\(\)") {
        $missingReceipts += $file.Name
    }
}

$auditResults += "Found compute files with potentially missing receipt calls: $($missingReceipts.Count)"
if ($missingReceipts.Count -gt 0) {
    $auditResults += "Files: $($missingReceipts -join ", ")"
}
$auditResults += ""

# Write audit results
$auditResults | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Compute trace audit completed. Results written to $OutputPath"
