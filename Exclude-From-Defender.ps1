#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Add RawrXD EXEs to Windows Defender exclusions
.DESCRIPTION
    Adds RawrXD-Agentic.exe and RawrXD.exe to Windows Defender to prevent false positives
#>

Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Adding RawrXD to Windows Defender Exclusions" -ForegroundColor Cyan
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$exeFiles = @(
    "C:\Users\HiH8e\OneDrive\Desktop\Powershield\RawrXD-Agentic.exe",
    "C:\Users\HiH8e\OneDrive\Desktop\Powershield\RawrXD.exe",
    "C:\Users\HiH8e\OneDrive\Desktop\Powershield\Launch-RawrXD-Agentic.ps1",
    "C:\Users\HiH8e\OneDrive\Desktop\Powershield\RawrXD.ps1"
)

foreach ($file in $exeFiles) {
    if (Test-Path $file) {
        try {
            Add-MpPreference -ExclusionPath $file -ErrorAction Stop
            Write-Host "✅ Added to exclusions: $file" -ForegroundColor Green
        } catch {
            Write-Host "⚠️  Could not add exclusion (may already exist): $file" -ForegroundColor Yellow
        }
    } else {
        Write-Host "❌ File not found: $file" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "✅ Exclusions applied!" -ForegroundColor Green
Write-Host "════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "You can now run RawrXD-Agentic.exe without antivirus interference." -ForegroundColor Cyan
