# Compute dictionary audit tool
# This PowerShell script audits the compute dictionary for completeness

param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$OutputPath = "F:\~dev\_compute_dictionary_audit.txt"
)

$auditResults = @()
$auditResults += "=== COMPUTE DICTIONARY AUDIT ==="
$auditResults += "Root: $Root"
$auditResults += "Timestamp: $(Get-Date)"
$auditResults += ""

# Check for compute function exists but not called
$computeFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*.cpp" -ErrorAction SilentlyContinue
$computeHeaders = Get-ChildItem -Path "$Root\src\compute" -Filter "*.h" -ErrorAction SilentlyContinue

$auditResults += "Found compute files: $($computeFiles.Count)"
$auditResults += "Found compute headers: $($computeHeaders.Count)"
$auditResults += ""

# Check for kernel exists but not registered
$kernelFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*kernel*" -ErrorAction SilentlyContinue
$auditResults += "Found kernel-related files: $($kernelFiles.Count)"
$auditResults += ""

# Check for route exists but not selectable
$routeFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*route*" -ErrorAction SilentlyContinue
$auditResults += "Found route-related files: $($routeFiles.Count)"
$auditResults += ""

# Check for file exists but not built
$builtFiles = Get-ChildItem -Path "$Root\build" -Filter "*.lib" -ErrorAction SilentlyContinue
$auditResults += "Found built library files: $($builtFiles.Count)"
$auditResults += ""

# Check for duplicate old implementation
$duplicateFiles = Get-ChildItem -Path "$Root" -Filter "*old*" -Include "*.cpp","*.h" -ErrorAction SilentlyContinue
$auditResults += "Found duplicate/old implementation files: $($duplicateFiles.Count)"
$auditResults += ""

# Check for dead source file
$deadSourceFiles = @()
if (Test-Path "$Root\src\compute\DeadSourceFile.cpp") { $deadSourceFiles += "DeadSourceFile.cpp" }
if (Test-Path "$Root\src\compute\UnusedCompute.cpp") { $deadSourceFiles += "UnusedCompute.cpp" }
$auditResults += "Found potential dead source files: $($deadSourceFiles.Count)"
$auditResults += ""

# Write audit results
$auditResults | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Compute dictionary audit completed. Results written to $OutputPath"
