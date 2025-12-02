# Find-VSCode-Installation.ps1
# Helps locate VS Code installation on E drive after moving from D drive

Write-Host "🔍 Searching for VS Code Installation on E Drive..." -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Gray

$foundInstallations = @()

# Common VS Code executable names
$executableNames = @("code.exe", "Code.exe", "VSCode.exe")

# Search paths
$searchPaths = @(
    "E:\Everything\~dev",
    "E:\Everything",
    "E:\Backup",
    "E:\"
)

foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        Write-Host "`n📂 Searching in: $searchPath" -ForegroundColor Yellow
        
        foreach ($exeName in $executableNames) {
            $results = Get-ChildItem -Path $searchPath -Recurse -Filter $exeName -ErrorAction SilentlyContinue -Depth 4
            
            foreach ($result in $results) {
                $foundInstallations += @{
                    Path = $result.FullName
                    Directory = $result.DirectoryName
                    LastModified = $result.LastWriteTime
                    Size = $result.Length
                }
            }
        }
    }
}

# Also check for VS Code directories
Write-Host "`n📂 Searching for VS Code directories..." -ForegroundColor Yellow
$vscodeDirs = @(
    (Get-ChildItem -Path E:\ -Directory -Filter "*vscode*" -ErrorAction SilentlyContinue -Depth 2),
    (Get-ChildItem -Path E:\ -Directory -Filter "*Visual Studio Code*" -ErrorAction SilentlyContinue -Depth 2),
    (Get-ChildItem -Path E:\ -Directory -Filter "*Microsoft VS Code*" -ErrorAction SilentlyContinue -Depth 2)
)

foreach ($dir in $vscodeDirs) {
    if ($dir) {
        $codeExe = Get-ChildItem -Path $dir.FullName -Recurse -Filter "code.exe" -ErrorAction SilentlyContinue -Depth 2 | Select-Object -First 1
        if ($codeExe) {
            $foundInstallations += @{
                Path = $codeExe.FullName
                Directory = $codeExe.DirectoryName
                LastModified = $codeExe.LastWriteTime
                Size = $codeExe.Length
            }
        }
    }
}

# Display results
Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "  SEARCH RESULTS" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

if ($foundInstallations.Count -eq 0) {
    Write-Host "`n❌ VS Code executable not found on E drive" -ForegroundColor Red
    Write-Host "`n💡 Suggestions:" -ForegroundColor Yellow
    Write-Host "  1. Check if VS Code is still on D drive" -ForegroundColor Gray
    Write-Host "  2. Verify the move completed successfully" -ForegroundColor Gray
    Write-Host "  3. Check if it's in a different location" -ForegroundColor Gray
    Write-Host "  4. You may need to reinstall VS Code" -ForegroundColor Gray
} else {
    Write-Host "`n✅ Found $($foundInstallations.Count) VS Code installation(s):`n" -ForegroundColor Green
    
    $index = 1
    foreach ($install in $foundInstallations) {
        Write-Host "[$index] VS Code Installation" -ForegroundColor Cyan
        Write-Host "    Path: $($install.Path)" -ForegroundColor White
        Write-Host "    Directory: $($install.Directory)" -ForegroundColor Gray
        Write-Host "    Last Modified: $($install.LastModified)" -ForegroundColor Gray
        Write-Host "    Size: $([math]::Round($install.Size / 1MB, 2)) MB" -ForegroundColor Gray
        Write-Host ""
        $index++
    }
    
    # Check if it's a valid installation
    $primaryInstall = $foundInstallations[0]
    $installDir = Split-Path $primaryInstall.Directory -Parent
    
    Write-Host "📋 Installation Details:" -ForegroundColor Cyan
    Write-Host "   Primary Location: $installDir" -ForegroundColor White
    
    # Check for common VS Code directories
    $resourcesDir = Join-Path $installDir "resources"
    $binDir = Join-Path $installDir "bin"
    
    if (Test-Path $resourcesDir) {
        Write-Host "   ✅ Resources directory found" -ForegroundColor Green
    }
    if (Test-Path $binDir) {
        Write-Host "   ✅ Bin directory found" -ForegroundColor Green
    }
    
    # Check for code.cmd in bin directory
    $codeCmd = Join-Path $binDir "code.cmd"
    if (Test-Path $codeCmd) {
        Write-Host "   ✅ code.cmd found (command-line launcher)" -ForegroundColor Green
    }
    
    Write-Host "`n💡 To use this installation:" -ForegroundColor Yellow
    Write-Host "   1. Add to PATH: $installDir\bin" -ForegroundColor Gray
    Write-Host "   2. Or create a shortcut to: $($primaryInstall.Path)" -ForegroundColor Gray
    Write-Host "   3. Or run directly: & '$($primaryInstall.Path)'" -ForegroundColor Gray
}

# Also show Cursor location
Write-Host "`n" + "=" * 60 -ForegroundColor Cyan
Write-Host "  CURSOR LOCATION" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$cursorExe = Get-ChildItem -Path E:\ -Recurse -Filter "cursor.exe" -ErrorAction SilentlyContinue -Depth 5 | Select-Object -First 1
if ($cursorExe) {
    Write-Host "`n✅ Found Cursor:" -ForegroundColor Green
    Write-Host "   Path: $($cursorExe.FullName)" -ForegroundColor White
    Write-Host "   Directory: $($cursorExe.DirectoryName)" -ForegroundColor Gray
} else {
    Write-Host "`n⚠️  Cursor not found on E drive" -ForegroundColor Yellow
}

Write-Host "`n" + "=" * 60 -ForegroundColor Cyan

