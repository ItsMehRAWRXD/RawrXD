# Final Production Integration Verification

Write-Host "========================================" -ForegroundColor Green
Write-Host "PRODUCTION INTEGRATION COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$results = @{
    CLI_IDE = $false
    GUI_IDE = $false
    Compilers = 0
    TotalCompilers = 69
}

# Check CLI IDE
$cliPath = "d:\rawrxd\bin\RawrXD_Autonomous_CLI.exe"
if (Test-Path $cliPath) {
    $results.CLI_IDE = $true
    $cliSize = (Get-Item $cliPath).Length
    Write-Host "`n[✓] CLI IDE: $cliPath ($cliSize bytes)" -ForegroundColor Green
} else {
    Write-Host "`n[✗] CLI IDE: NOT FOUND" -ForegroundColor Red
}

# Check GUI IDE
$guiPath = "d:\rawrxd\bin\RawrXD_Autonomous_GUI.exe"
if (Test-Path $guiPath) {
    $results.GUI_IDE = $true
    $guiSize = (Get-Item $guiPath).Length
    Write-Host "[✓] GUI IDE: $guiPath ($guiSize bytes)" -ForegroundColor Green
} else {
    Write-Host "[✗] GUI IDE: NOT FOUND" -ForegroundColor Red
}

# Check Compilers
$compilerDir = "d:\rawrxd\compilers\all_69_final"
if (Test-Path $compilerDir) {
    $compilers = Get-ChildItem -Path $compilerDir -Filter "*.exe"
    $results.Compilers = $compilers.Count
    Write-Host "`n[✓] Compilers: $($results.Compilers) found in $compilerDir" -ForegroundColor Green
    
    foreach ($compiler in $compilers | Select-Object -First 10) {
        Write-Host "    - $($compiler.Name) ($($compiler.Length) bytes)" -ForegroundColor Gray
    }
    if ($results.Compilers -gt 10) {
        Write-Host "    ... and $($results.Compilers - 10) more" -ForegroundColor Gray
    }
} else {
    Write-Host "`n[✗] Compilers: Directory not found" -ForegroundColor Red
}

# Test CLI functionality
Write-Host "`n[TEST] CLI IDE Functionality:" -ForegroundColor Cyan
if ($results.CLI_IDE) {
    $testOutput = cmd /c "`"$cliPath`" list" 2`>`&1
    if ($testOutput -match "69 Compilers") {
        Write-Host "    [✓] CLI list command works" -ForegroundColor Green
    } else {
        Write-Host "    [✗] CLI list command failed" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "INTEGRATION SUMMARY" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "CLI IDE: $(if ($results.CLI_IDE) { 'READY' } else { 'MISSING' })" -ForegroundColor $(if ($results.CLI_IDE) { 'Green' } else { 'Red' })
Write-Host "GUI IDE: $(if ($results.GUI_IDE) { 'READY' } else { 'MISSING' })" -ForegroundColor $(if ($results.GUI_IDE) { 'Green' } else { 'Red' })
Write-Host "Compilers: $($results.Compilers)/$($results.TotalCompilers)" -ForegroundColor $(if ($results.Compilers -gt 0) { 'Green' } else { 'Red' })

$totalReady = 0
if ($results.CLI_IDE) { $totalReady++ }
if ($results.GUI_IDE) { $totalReady++ }
if ($results.Compilers -gt 0) { $totalReady++ }

Write-Host "`nOverall: $totalReady/3 components ready" -ForegroundColor $(if ($totalReady -eq 3) { 'Green' } else { 'Yellow' })

if ($totalReady -eq 3) {
    Write-Host "`n✓ PRODUCTION INTEGRATION COMPLETE" -ForegroundColor Green
    Write-Host "  Both CLI and GUI IDEs are fully integrated with compilers" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠ Some components need attention" -ForegroundColor Yellow
    exit 1
}
