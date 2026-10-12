# Qt Elimination Verification Script
# This script verifies that Qt has been completely eliminated from the Win32IDE build

param(
    [string]$BuildDir = "F:\rawrxd\build",
    [string]$CertDir = "F:\rawrxd\evidence\RAWRXD_QT_ELIMINATION_001"
)

$ErrorActionPreference = "Stop"

Write-Host "=== Qt Elimination Verification ===" -ForegroundColor Cyan

# 1. Check build log for Qt references
Write-Host "`n[1] Checking build log for Qt references..." -ForegroundColor Yellow
$buildLog = Join-Path $BuildDir "evidence\win32ide_build.log"
if (Test-Path $buildLog) {
    $qtRefs = Select-String -Path $buildLog -Pattern 'QObject|QString|QWidget|QProcess|QNetworkAccessManager|QWebSocket|QSqlDatabase|Qt6::|Qt5::|\\Qt\\|/Qt/'
    if ($qtRefs) {
        Write-Host "FAIL: Qt references found in build log:" -ForegroundColor Red
        $qtRefs | Select-Object -First 10 | ForEach-Object { Write-Host "  $($_.Line)" }
        $qtFound = $false
    } else {
        Write-Host "PASS: No Qt references in build log" -ForegroundColor Green
        $qtFound = $true
    }
} else {
    Write-Host "SKIP: Build log not found" -ForegroundColor Yellow
    $qtFound = $false
}

# 2. Find the built executable
Write-Host "`n[2] Locating RawrXD-Win32IDE.exe..." -ForegroundColor Yellow
$exe = Get-ChildItem $BuildDir -Recurse -Filter "RawrXD-Win32IDE.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($exe) {
    Write-Host "PASS: Found executable at $($exe.FullName)" -ForegroundColor Green
    $exePath = $exe.FullName
} else {
    Write-Host "FAIL: RawrXD-Win32IDE.exe not found" -ForegroundColor Red
    $exePath = $null
}

# 3. Check executable dependencies
Write-Host "`n[3] Checking executable dependencies..." -ForegroundColor Yellow
if ($exePath) {
    $dumpbinOutput = & dumpbin /dependents $exePath 2>&1
    $qtDlls = @('Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll', 'Qt6Network.dll', 'Qt6Sql.dll', 'Qt6WebSockets.dll', 'Qt5*.dll')
    $qtFoundInExe = $false
    foreach ($dll in $qtDlls) {
        if ($dumpbinOutput -match $dll) {
            Write-Host "FAIL: Found Qt dependency: $dll" -ForegroundColor Red
            $qtFoundInExe = $true
        }
    }
    if (-not $qtFoundInExe) {
        Write-Host "PASS: No Qt DLL dependencies found" -ForegroundColor Green
    }
} else {
    Write-Host "SKIP: No executable to check" -ForegroundColor Yellow
    $qtFoundInExe = $false
}

# 4. Check build metadata for Qt references
Write-Host "`n[4] Checking build metadata for Qt references..." -ForegroundColor Yellow
$metadataFiles = Get-ChildItem $BuildDir -Recurse -Include '*.vcxproj','*.props','*.targets','*.rsp','*.txt' -ErrorAction SilentlyContinue
$qtMetaRefs = 0
foreach ($file in $metadataFiles) {
    $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
    if ($content -match 'Qt6|Qt5|QtCore|QtGui|QtWidgets|QtNetwork|QtSql|QtWebSockets') {
        $qtMetaRefs++
        Write-Host "  Qt ref in: $($file.FullName)" -ForegroundColor Yellow
    }
}
if ($qtMetaRefs -eq 0) {
    Write-Host "PASS: No Qt references in build metadata" -ForegroundColor Green
} else {
    Write-Host "WARN: Found $qtMetaRefs files with Qt references in build metadata" -ForegroundColor Yellow
}

# 5. Summary
Write-Host "`n=== Verification Summary ===" -ForegroundColor Cyan
$allPassed = $qtFound -and (-not $qtFoundInExe) -and ($qtMetaRefs -eq 0)
if ($allPassed) {
    Write-Host "VERDICT: PASS - Qt elimination verified" -ForegroundColor Green
    exit 0
} else {
    Write-Host "VERDICT: FAIL - Qt references still present" -ForegroundColor Red
    exit 1
}
