# Quick-Fix-EPipe.ps1
# Quick fix for EPipe errors - restarts Cursor processes

Write-Host "🔧 Quick EPipe Fix" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$cursorProcesses = Get-Process | Where-Object { $_.ProcessName -eq "Cursor" } -ErrorAction SilentlyContinue

if ($cursorProcesses) {
    Write-Host "`n📋 Found $($cursorProcesses.Count) Cursor process(es)" -ForegroundColor Yellow
    
    Write-Host "`n⚠️  This will close all Cursor windows" -ForegroundColor Yellow
    Write-Host "   Make sure you've saved your work!" -ForegroundColor Yellow
    
    $confirm = Read-Host "`nClose all Cursor processes? (y/N)"
    
    if ($confirm -eq "y" -or $confirm -eq "Y") {
        Write-Host "`n🔄 Closing Cursor processes..." -ForegroundColor Yellow
        
        foreach ($proc in $cursorProcesses) {
            try {
                Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
                Write-Host "   ✅ Closed process $($proc.Id)" -ForegroundColor Green
            }
            catch {
                Write-Host "   ⚠️  Could not close process $($proc.Id): $_" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n✅ All Cursor processes closed" -ForegroundColor Green
        Write-Host "`n💡 Now:" -ForegroundColor Cyan
        Write-Host "   1. Wait 5 seconds" -ForegroundColor Gray
        Write-Host "   2. Reopen Cursor" -ForegroundColor Gray
        Write-Host "   3. The EPipe error should be resolved" -ForegroundColor Gray
    } else {
        Write-Host "`n⚠️  Cancelled. Try restarting Cursor manually." -ForegroundColor Yellow
    }
} else {
    Write-Host "`n✅ No Cursor processes running" -ForegroundColor Green
    Write-Host "   You can safely open Cursor now" -ForegroundColor Gray
}

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan

