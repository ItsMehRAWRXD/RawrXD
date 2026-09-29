# Compute build inclusion audit tool
# This PowerShell script audits compute build inclusion for completeness

param(
    [string]$Root = "F:\~dev\rawrxd",
    [string]$OutputPath = "F:\~dev\_compute_build_inclusion_audit.txt"
)

$auditResults = @()
$auditResults += "=== COMPUTE BUILD INCLUSION AUDIT ==="
$auditResults += "Root: $Root"
$auditResults += "Timestamp: $(Get-Date)"
$auditResults += ""

# Check for *.asm not in CMake
$asmFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*.asm" -ErrorAction SilentlyContinue
$missingCMakeAsm = @()
foreach ($asmFile in $asmFiles) {
    # Check if there's a corresponding CMakeLists.txt entry
    $cmakeContent = Get-Content "$Root\CMakeLists.txt" -ErrorAction SilentlyContinue
    if (-not $cmakeContent -or $cmakeContent -notmatch $asmFile.Name) {
        $missingCMakeAsm += $asmFile.Name
    }
}

$auditResults += "Found .asm files not in CMake: $($missingCMakeAsm.Count)"
if ($missingCMakeAsm.Count -gt 0) {
    $auditResults += "Files: $($missingCMakeAsm -join ", ")"
}
$auditResults += ""

# Check for kernel cpp not in target
$kernelCppFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*kernel*.cpp" -ErrorAction SilentlyContinue
$missingTargets = @()
foreach ($kernelCpp in $kernelCppFiles) {
    # Check if the file is referenced in CMake targets
    $cmakeContent = Get-Content "$Root\CMakeLists.txt" -ErrorAction SilentlyContinue
    if (-not $cmakeContent -or $cmakeContent -notmatch "kernel.*$kernelCpp") {
        $missingTargets += $kernelCpp.Name
    }
}

$auditResults += "Found kernel .cpp files not in CMake targets: $($missingTargets.Count)"
if ($missingTargets.Count -gt 0) {
    $auditResults += "Files: $($missingTargets -join ", ")"
}
$auditResults += ""

# Check for duplicate old implementation
$duplicateImplementations = @()
$oldImplFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*old*.cpp" -ErrorAction SilentlyContinue
foreach ($oldImpl in $oldImplFiles) {
    $similarFiles = Get-ChildItem -Path "$Root\src\compute" -Filter "*.cpp" -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne $oldImpl.Name -and $_.Name -match "similar.*pattern" }
    if ($similarFiles.Count -gt 0) {
        $duplicateImplementations += "$($oldImpl.Name) -> $($similarFiles.Name -join ", ")"
    }
}

$auditResults += "Found duplicate old implementations: $($duplicateImplementations.Count)"
if ($duplicateImplementations.Count -gt 0) {
    $auditResults += "Pairs: $($duplicateImplementations -join ", ")"
}
$auditResults += ""

# Check for dead source file
$deadSourceFiles = @()
$deadCandidates = Get-ChildItem -Path "$Root\src\compute" -Filter "*dead*.cpp" -ErrorAction SilentlyContinue
foreach ($dead in $deadCandidates) {
    $content = Get-Content $dead.FullName -ErrorAction SilentlyContinue
    if ($content -match "//.*DEAD.*SOURCE.*DEBT" -or $content -match "TODO.*REMOVE") {
        $deadSourceFiles += $dead.Name
    }
}

$auditResults += "Found dead source files: $($deadSourceFiles.Count)"
if ($deadSourceFiles.Count -gt 0) {
    $auditResults += "Files: $($deadSourceFiles -join ", ")"
}
$auditResults += ""

# Write audit results
$auditResults | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "Compute build inclusion audit completed. Results written to $OutputPath"
