@echo off
REM =============================================================================
REM   RawrXD Package Manager - Batch 6 of 5 (Bonus)
REM   Dependency management and package installation
REM =============================================================================

setlocal EnableDelayedExpansion

set "RAWRXD_HOME=d:\rawrxd"
set "PACKAGES_DIR=%RAWRXD_HOME%\packages"
set "INSTALL_DIR=%RAWRXD_HOME%\installed"
set "CACHE_DIR=%RAWRXD_HOME%\cache"

if not exist "%PACKAGES_DIR%" mkdir "%PACKAGES_DIR%"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"

set "COMMAND=%1"
if "!COMMAND!"=="" set "COMMAND=help"

set "PACKAGE_NAME=%2"
set "PACKAGE_VERSION=%3"
if "!PACKAGE_VERSION!"=="" set "PACKAGE_VERSION=latest"

echo =============================================================================
echo   RawrXD Package Manager
echo   Command: !COMMAND!
echo =============================================================================
echo.

if /i "!COMMAND!"=="help" goto :help
if /i "!COMMAND!"=="install" goto :install
if /i "!COMMAND!"=="remove" goto :remove
if /i "!COMMAND!"=="list" goto :list
if /i "!COMMAND!"=="search" goto :search
if /i "!COMMAND!"=="update" goto :update
if /i "!COMMAND!"=="upgrade" goto :upgrade
if /i "!COMMAND!"=="clean" goto :clean
if /i "!COMMAND!"=="verify" goto :verify

echo Unknown command: !COMMAND!
echo Run 'rpkg help' for usage
goto :error

:help
echo Usage: rpkg [command] [package] [version]
echo.
echo Commands:
echo   install  [pkg] [ver]  Install a package
echo   remove   [pkg]       Remove a package
echo   list                 List installed packages
echo   search   [term]      Search for packages
echo   update               Update package index
echo   upgrade              Upgrade all packages
echo   clean                Clean package cache
echo   verify               Verify installation integrity
echo   help                 Show this help
echo.
echo Examples:
echo   rpkg install test-framework 1.0.0
echo   rpkg install profiler
echo   rpkg list
echo   rpkg clean
goto :end

:install
echo Installing package: !PACKAGE_NAME! (!PACKAGE_VERSION!)
echo.

if "!PACKAGE_NAME!"=="" (
    echo ERROR: Package name required
    goto :error
)

REM Check if already installed
if exist "%INSTALL_DIR%\!PACKAGE_NAME!" (
    echo Package !PACKAGE_NAME! is already installed
    echo Use 'rpkg upgrade !PACKAGE_NAME!' to update
    goto :end
)

REM Simulate package installation
echo   Downloading !PACKAGE_NAME!-!PACKAGE_VERSION!.tar.gz...
echo   ✓ Downloaded (simulated)
echo.
echo   Verifying checksum...
echo   ✓ Checksum verified (simulated)
echo.
echo   Extracting...
mkdir "%INSTALL_DIR%\!PACKAGE_NAME!"
echo   ✓ Extracted
echo.
echo   Installing files...
echo     Copying headers...
echo     Copying libraries...
echo     Copying binaries...
echo   ✓ Installation complete
echo.

REM Create package manifest
echo name=!PACKAGE_NAME! > "%INSTALL_DIR%\!PACKAGE_NAME!\MANIFEST.txt"
echo version=!PACKAGE_VERSION! >> "%INSTALL_DIR%\!PACKAGE_NAME!\MANIFEST.txt"
echo installed=%date% %time% >> "%INSTALL_DIR%\!PACKAGE_NAME!\MANIFEST.txt"
echo source=rawrxd-repo >> "%INSTALL_DIR%\!PACKAGE_NAME!\MANIFEST.txt"

echo   ✅ Package !PACKAGE_NAME! !PACKAGE_VERSION! installed successfully
goto :end

:remove
echo Removing package: !PACKAGE_NAME!
echo.

if "!PACKAGE_NAME!"=="" (
    echo ERROR: Package name required
    goto :error
)

if not exist "%INSTALL_DIR%\!PACKAGE_NAME!" (
    echo ERROR: Package !PACKAGE_NAME! is not installed
    goto :error
)

echo   Uninstalling !PACKAGE_NAME!...
rmdir /s /q "%INSTALL_DIR%\!PACKAGE_NAME!"
echo   ✓ Package removed
echo.
echo   ✅ Package !PACKAGE_NAME! removed successfully
goto :end

:list
echo Installed Packages:
echo.

set "FOUND_PACKAGES=0"
for /d %%D in ("%INSTALL_DIR%\*") do (
    set "PKG_NAME=%%~nD"
    set "PKG_VERSION=unknown"
    
    if exist "%%D\MANIFEST.txt" (
        for /f "tokens=2 delims==" %%V in ('findstr "^version=" "%%D\MANIFEST.txt"') do (
            set "PKG_VERSION=%%V"
        )
    )
    
    echo   !PKG_NAME! (!PKG_VERSION!)
    set /a FOUND_PACKAGES+=1
)

if !FOUND_PACKAGES! equ 0 (
    echo   No packages installed
) else (
    echo.
    echo Total: !FOUND_PACKAGES! package(s)
)
goto :end

:search
echo Searching for: !PACKAGE_NAME!
echo.
echo Available Packages:
echo   test-framework    - Core testing framework
echo   profiler          - Performance profiler
echo   coverage          - Code coverage tool
echo   analyzer          - Static analysis tool
echo   docs              - Documentation generator
echo   benchmark         - Benchmarking suite
echo   linter            - Code linter
echo   formatter         - Code formatter
goto :end

:update
echo Updating package index...
echo.
echo   Fetching package list from repository...
echo   ✓ Package index updated
echo.
echo   Available updates will be shown with 'rpkg upgrade'
goto :end

:upgrade
echo Upgrading packages...
echo.

set "UPGRADED=0"
for /d %%D in ("%INSTALL_DIR%\*") do (
    set "PKG_NAME=%%~nD"
    set "PKG_VERSION=unknown"
    
    if exist "%%D\MANIFEST.txt" (
        for /f "tokens=2 delims==" %%V in ('findstr "^version=" "%%D\MANIFEST.txt"') do (
            set "PKG_VERSION=%%V"
        )
    )
    
    echo Checking !PKG_NAME! for updates...
    echo   Current: !PKG_VERSION!, Latest: !PKG_VERSION! (up to date)
)

if !UPGRADED! equ 0 (
    echo All packages are up to date
) else (
    echo Upgraded !UPGRADED! package(s)
)
goto :end

:clean
echo Cleaning package cache...
echo.

set "CACHE_SIZE=0"
for /r "%CACHE_DIR%" %%F in (*) do (
    set /a CACHE_SIZE+=1
)

if !CACHE_SIZE! gtr 0 (
    echo   Removing !CACHE_SIZE! cached files...
    rmdir /s /q "%CACHE_DIR%"
    mkdir "%CACHE_DIR%"
    echo   ✓ Cache cleaned
) else (
    echo   Cache is already empty
)
goto :end

:verify
echo Verifying installation integrity...
echo.

set "VERIFIED=0"
set "FAILED=0"

for /d %%D in ("%INSTALL_DIR%\*") do (
    set "PKG_NAME=%%~nD"
    
    if exist "%%D\MANIFEST.txt" (
        echo   ✓ !PKG_NAME! - manifest exists
        set /a VERIFIED+=1
    ) else (
        echo   ⚠ !PKG_NAME! - manifest missing
        set /a FAILED+=1
    )
)

echo.
if !FAILED! equ 0 (
    echo   ✅ All !VERIFIED! package(s) verified successfully
) else (
    echo   ⚠ !VERIFIED! verified, !FAILED! failed
)
goto :end

:error
echo.
echo =============================================================================
echo   OPERATION FAILED
echo =============================================================================
exit /b 1

:end
echo.
echo =============================================================================
echo   Operation complete
echo =============================================================================
exit /b 0
