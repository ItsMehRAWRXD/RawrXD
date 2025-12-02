# Quick-VSCode-Search.ps1
# Quick search script to find VS Code

Write-Host "🔍 Quick VS Code Search" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

# Check the shortcut location
$shortcutPath = "E:\Everything\04-Compilers\Visual Studio Code_1.lnk"
if (Test-Path $shortcutPath) {
    Write-Host "`n📋 Found shortcut: $shortcutPath" -ForegroundColor Yellow
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        Write-Host "   Target: $($shortcut.TargetPath)" -ForegroundColor White
        Write-Host "   Working Dir: $($shortcut.WorkingDirectory)" -ForegroundColor Gray
        
        if (Test-Path $shortcut.TargetPath) {
            Write-Host "   ✅ Target exists!" -ForegroundColor Green
            $targetDir = Split-Path $shortcut.TargetPath -Parent
            Write-Host "`n   VS Code Location: $targetDir" -ForegroundColor Cyan
        } else {
            Write-Host "   ⚠️  Target path doesn't exist (may have been moved)" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "   ❌ Error reading shortcut: $_" -ForegroundColor Red
    }
}

# Check 04-Compilers directory
Write-Host "`n📂 Checking E:\Everything\04-Compilers..." -ForegroundColor Yellow
if (Test-Path "E:\Everything\04-Compilers") {
    $items = Get-ChildItem -Path "E:\Everything\04-Compilers" -ErrorAction SilentlyContinue
    Write-Host "   Found $($items.Count) items" -ForegroundColor Gray
    
    # Look for VS Code related items
    $vscodeItems = $items | Where-Object { $_.Name -match "code|visual|studio|vscode" -or $_.Name -match "^V|^v" }
    if ($vscodeItems) {
        Write-Host "   ✅ Found potential VS Code items:" -ForegroundColor Green
        foreach ($item in $vscodeItems) {
            Write-Host "      - $($item.Name) ($(if($item.PSIsContainer){'Directory'}else{'File'}))" -ForegroundColor White
        }
    }
}

# Quick search in common E drive locations
Write-Host "`n🔍 Quick search in E:\Everything..." -ForegroundColor Yellow
$quickSearch = @(
    "E:\Everything\VSCode",
    "E:\Everything\Microsoft VS Code",
    "E:\Everything\Visual Studio Code",
    "E:\Everything\~dev\VSCode",
    "E:\Everything\~dev\Microsoft VS Code",
    "E:\Everything\04-Compilers\VSCode",
    "E:\Everything\04-Compilers\Microsoft VS Code"
)

foreach ($path in $quickSearch) {
    if (Test-Path $path) {
        Write-Host "   ✅ Found: $path" -ForegroundColor Green
        $codeExe = Get-ChildItem -Path $path -Recurse -Filter "code.exe" -ErrorAction SilentlyContinue -Depth 1 | Select-Object -First 1
        if ($codeExe) {
            Write-Host "      Executable: $($codeExe.FullName)" -ForegroundColor White
        }
    }
}

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "💡 If VS Code wasn't found:" -ForegroundColor Yellow
Write-Host "   1. Check if you have a backup of the D drive" -ForegroundColor Gray
Write-Host "   2. Consider reinstalling VS Code to E drive" -ForegroundColor Gray
Write-Host "   3. Use portable version if you prefer" -ForegroundColor Gray

