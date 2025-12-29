# BigDaddyG Extension Cleanup Script
# Run this AFTER closing Cursor IDE completely

Write-Host "`n════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  BigDaddyG Extension Cleanup" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

# Check if Cursor is running
$cursorProcess = Get-Process -Name "Cursor" -ErrorAction SilentlyContinue
if ($cursorProcess) {
    Write-Host "❌ ERROR: Cursor is still running!" -ForegroundColor Red
    Write-Host "`n   Please close Cursor completely and run this script again.`n" -ForegroundColor Yellow
    Write-Host "   Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host "✓ Cursor is closed" -ForegroundColor Green

# List of broken extensions to remove
$brokenExtensions = @(
    'bigdaddyg.bigdaddyg-copilot-1.0.0',
    'undefined_publisher.bigdaddyg-asm-extension-1.0.0',
    'bigdaddyg.bigdaddyg-asm-ide-1.0.0',
    'undefined_publisher.bigdaddyg-cursor-chat-1.0.0'
)

$extensionsPath = "C:\Users\HiH8e\.cursor\extensions"
$removed = @()
$notFound = @()

Write-Host "`n🗑️  Removing broken extensions...`n"

foreach ($ext in $brokenExtensions) {
    $fullPath = Join-Path $extensionsPath $ext
    
    if (Test-Path $fullPath) {
        try {
            Remove-Item $fullPath -Recurse -Force -ErrorAction Stop
            $removed += $ext
            Write-Host "  ✓ Removed: $ext" -ForegroundColor Green
        }
        catch {
            Write-Host "  ✗ Failed: $ext" -ForegroundColor Red
            Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
    }
    else {
        $notFound += $ext
    }
}

Write-Host "`n════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Cleanup Summary" -ForegroundColor Yellow
Write-Host "════════════════════════════════════════════════════════`n" -ForegroundColor Cyan

Write-Host "✅ Removed: $($removed.Count) broken extensions" -ForegroundColor Green
if ($notFound.Count -gt 0) {
    Write-Host "ℹ️  Already gone: $($notFound.Count) extensions" -ForegroundColor Gray
}

Write-Host "`n✓ Active extension remains at:" -ForegroundColor Green
Write-Host "  E:\Everything\cursor\extensions\bigdaddyg-copilot-1.0.0`n" -ForegroundColor Cyan

Write-Host "🎯 Next steps:" -ForegroundColor Yellow
Write-Host "  1. Start Cursor IDE"
Write-Host "  2. Press Ctrl+Shift+P"
Write-Host "  3. Type: 'BigDaddyG Copilot'"
Write-Host "  4. Commands should now appear without errors`n"

Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
