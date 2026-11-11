# ============================================================================
# RawrXD Feature Verification Script
# ============================================================================
# Purpose: Launch IDE and monitor FMF logs for feature classification
# Usage:   .\verify_features.ps1
# Output:  feature_verification_matrix.json
# ============================================================================

param(
    [string]$BinaryPath = "d:\rawrxd\build-ninja\bin\RawrXD-Win32IDE.exe",
    [string]$LogPath = "d:\rawrxd\__ide_fmf_verification.log",
    [string]$OutputPath = "d:\rawrxd\feature_verification_matrix.json",
    [int]$StartupWaitSeconds = 5
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Feature Verification Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Expected FMF signatures for each feature category
$ExpectedSignatures = @{
    # AI Features
    "AI.Init" = @{ Category = "AI"; Feature = "Initialize"; Expected = "STUB" }
    "AI.Shutdown" = @{ Category = "AI"; Feature = "Shutdown"; Expected = "STUB" }
    "AI.ExplainCode" = @{ Category = "AI"; Feature = "Explain Code"; Expected = "STUB" }
    "AI.GenerateTests" = @{ Category = "AI"; Feature = "Generate Tests"; Expected = "STUB" }
    "AI.SuggestRefactoring" = @{ Category = "AI"; Feature = "Suggest Refactoring"; Expected = "STUB" }
    "AI.FixError" = @{ Category = "AI"; Feature = "Fix Error"; Expected = "STUB" }
    "AI.GenerateFromDescription" = @{ Category = "AI"; Feature = "Generate From Description"; Expected = "STUB" }
    "AI.CodeReview" = @{ Category = "AI"; Feature = "Code Review"; Expected = "STUB" }
    "AI.Cmd.ExplainSelection" = @{ Category = "AI"; Feature = "Command: Explain Selection"; Expected = "STUB" }
    "AI.Cmd.GenerateTests" = @{ Category = "AI"; Feature = "Command: Generate Tests"; Expected = "STUB" }
    "AI.Cmd.RefactorSelection" = @{ Category = "AI"; Feature = "Command: Refactor Selection"; Expected = "STUB" }
    "AI.Cmd.FixCurrentError" = @{ Category = "AI"; Feature = "Command: Fix Current Error"; Expected = "STUB" }
    "AI.Cmd.GenerateFromPrompt" = @{ Category = "AI"; Feature = "Command: Generate From Prompt"; Expected = "STUB" }
    "AI.Cmd.CodeReview" = @{ Category = "AI"; Feature = "Command: Code Review"; Expected = "STUB" }
    
    # Code Actions
    "CodeActions.Query" = @{ Category = "CodeActions"; Feature = "Query"; Expected = "STUB" }
    "CodeActions.Apply" = @{ Category = "CodeActions"; Feature = "Apply"; Expected = "STUB" }
    "CodeActions.ApplyTextEdit" = @{ Category = "CodeActions"; Feature = "Apply Text Edit"; Expected = "STUB" }
    "CodeActions.Cmd.FixAll" = @{ Category = "CodeActions"; Feature = "Command: Fix All"; Expected = "STUB" }
    "CodeActions.Cmd.OrganizeImports" = @{ Category = "CodeActions"; Feature = "Command: Organize Imports"; Expected = "STUB" }
    "CodeActions.ShowUI" = @{ Category = "CodeActions"; Feature = "Show UI"; Expected = "STUB" }
    "CodeActions.ExecuteLSPCommand" = @{ Category = "CodeActions"; Feature = "Execute LSP Command"; Expected = "STUB" }
    
    # Call Hierarchy
    "CallHierarchy.Prepare" = @{ Category = "Hierarchy"; Feature = "Call Hierarchy Prepare"; Expected = "STUB" }
    "CallHierarchy.IncomingCalls" = @{ Category = "Hierarchy"; Feature = "Incoming Calls"; Expected = "STUB" }
    "CallHierarchy.OutgoingCalls" = @{ Category = "Hierarchy"; Feature = "Outgoing Calls"; Expected = "STUB" }
    "CallHierarchy.Cmd.Show" = @{ Category = "Hierarchy"; Feature = "Show Call Hierarchy"; Expected = "STUB" }
    
    # Type Hierarchy
    "TypeHierarchy.Prepare" = @{ Category = "Hierarchy"; Feature = "Type Hierarchy Prepare"; Expected = "STUB" }
    "TypeHierarchy.Supertypes" = @{ Category = "Hierarchy"; Feature = "Supertypes"; Expected = "STUB" }
    "TypeHierarchy.Subtypes" = @{ Category = "Hierarchy"; Feature = "Subtypes"; Expected = "STUB" }
    "TypeHierarchy.Cmd.Show" = @{ Category = "Hierarchy"; Feature = "Show Type Hierarchy"; Expected = "STUB" }
}

# Check if binary exists
if (-not (Test-Path $BinaryPath)) {
    Write-Error "Binary not found: $BinaryPath"
    exit 1
}

Write-Host "Binary: $BinaryPath" -ForegroundColor Gray
Write-Host "Log:    $LogPath" -ForegroundColor Gray
Write-Host "Output: $OutputPath" -ForegroundColor Gray
Write-Host ""

# Clear previous log
if (Test-Path $LogPath) {
    Remove-Item $LogPath -Force
    Write-Host "Cleared previous log" -ForegroundColor DarkGray
}

# Launch IDE with FMF logging (use cmd.exe to avoid PowerShell redirection limitations)
Write-Host "Launching IDE..." -ForegroundColor Yellow
$cmd = "`"$BinaryPath`" > `"$LogPath`" 2>&1"
$process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $cmd -PassThru -WindowStyle Hidden

Write-Host "Waiting $StartupWaitSeconds seconds for startup..." -ForegroundColor Yellow
Start-Sleep -Seconds $StartupWaitSeconds

# Check if process is still running
if ($process.HasExited) {
    Write-Host "IDE exited early (exit code: $($process.ExitCode))" -ForegroundColor Red
} else {
    Write-Host "IDE running (PID: $($process.Id))" -ForegroundColor Green
    
    # Give it a bit more time to initialize
    Start-Sleep -Seconds 2
    
    # Terminate gracefully
    Write-Host "Terminating IDE..." -ForegroundColor Yellow
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

# Wait for log file to be written
Start-Sleep -Seconds 1

# Parse FMF signatures from log
$DetectedSignatures = @{}
if (Test-Path $LogPath) {
    $logContent = Get-Content $LogPath -Raw
    
    # Extract FMF signatures
    $pattern = '\[FMF\]\s+(STUB|REAL):?\s*([\w\.]+)'
    $matches = [regex]::Matches($logContent, $pattern)
    
    foreach ($match in $matches) {
        $type = $match.Groups[1].Value
        $signature = $match.Groups[2].Value
        $DetectedSignatures[$signature] = $type
    }
    
    Write-Host ""
    Write-Host "Detected FMF Signatures: $($DetectedSignatures.Count)" -ForegroundColor Cyan
}

# Build verification matrix
$Matrix = @{
    generatedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    binaryPath = $BinaryPath
    totalExpected = $ExpectedSignatures.Count
    totalDetected = $DetectedSignatures.Count
    categories = @{}
    features = @()
}

# Group by category
foreach ($sig in $ExpectedSignatures.Keys) {
    $info = $ExpectedSignatures[$sig]
    $category = $info.Category
    $feature = $info.Feature
    $expected = $info.Expected
    
    if ($DetectedSignatures.ContainsKey($sig)) {
        $actual = $DetectedSignatures[$sig]
        $status = $(if ($actual -eq $expected) { "VERIFIED" } else { "MISMATCH" }
    } else {
        $actual = "NOT_INVOKED"
        $status = "PENDING"
    }
    
    $featureEntry = @{
        signature = $sig
        category = $category
        feature = $feature
        expected = $expected
        actual = $actual
        status = $status
    }
    
    $Matrix.features += $featureEntry
    
    # Category stats
    if (-not $Matrix.categories.ContainsKey($category)) {
        $Matrix.categories[$category] = @{
            total = 0
            verified = 0
            pending = 0
            mismatch = 0
        }
    }
    
    $Matrix.categories[$category].total++
    switch ($status) {
        "VERIFIED" { $Matrix.categories[$category].verified++ }
        "PENDING" { $Matrix.categories[$category].pending++ }
        "MISMATCH" { $Matrix.categories[$category].mismatch++ }
    }
}

# Calculate summary
$verifiedCount = ($Matrix.features | Where-Object { $_.status -eq "VERIFIED" }).Count
$pendingCount = ($Matrix.features | Where-Object { $_.status -eq "PENDING" }).Count
$mismatchCount = ($Matrix.features | Where-Object { $_.status -eq "MISMATCH" }).Count

$Matrix.summary = @{
    totalFeatures = $Matrix.features.Count
    verified = $verifiedCount
    pending = $pendingCount
    mismatch = $mismatchCount
    completionRate = $(if ($Matrix.features.Count -gt 0) { [math]::Round($verifiedCount / $Matrix.features.Count, 4) } else { 0 }
}

# Export to JSON
$json = $Matrix | ConvertTo-Json -Depth 10
$json | Out-File -FilePath $OutputPath -Encoding UTF8

# Display results
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Verification Results" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Category Summary:" -ForegroundColor White
foreach ($cat in $Matrix.categories.Keys | Sort-Object) {
    $stats = $Matrix.categories[$cat]
    $color = $(if ($stats.pending -eq $stats.total) { "DarkGray" } elseif ($stats.verified -eq $stats.total) { "Green" } else { "Yellow" }
    Write-Host "  $cat`: $($stats.verified)/$($stats.total) verified, $($stats.pending) pending" -ForegroundColor $color
}

Write-Host ""
Write-Host "Overall: $verifiedCount/$($Matrix.features.Count) verified ($([math]::Round($verifiedCount / $Matrix.features.Count * 100, 1))%)" -ForegroundColor $(if ($verifiedCount -eq $Matrix.features.Count) { "Green" } else { "Yellow" })

Write-Host ""
Write-Host "Pending Features (require manual UI interaction):" -ForegroundColor Yellow
$pendingFeatures = $Matrix.features | Where-Object { $_.status -eq "PENDING" } | Group-Object -Property category
foreach ($group in $pendingFeatures) {
    Write-Host "  $($group.Name):" -ForegroundColor White
    foreach ($feat in $group.Group) {
        Write-Host "    - $($feat.feature) [$($feat.signature)]" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Output written to: $OutputPath" -ForegroundColor Green
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Launch IDE manually" -ForegroundColor White
Write-Host "  2. Invoke each pending feature from UI" -ForegroundColor White
Write-Host "  3. Re-run this script to capture FMF signatures" -ForegroundColor White
Write-Host "  4. Update AUDIT_TRACKER.json with verified status" -ForegroundColor White
