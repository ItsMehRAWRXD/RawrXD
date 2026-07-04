@echo off
REM build_vscode_extension.bat — Package RawrXD-Script VS Code Extension
REM Run from: d:\rawrxd\vscode-extension\

echo ===========================================
echo RawrXD-Script VS Code Extension Build
echo ===========================================

REM Check prerequisites
where npm >nul 2>&1
if errorlevel 1 (
    echo ERROR: npm not found. Install Node.js first.
    exit /b 1
)

where vsce >nul 2>&1
if errorlevel 1 (
    echo Installing vsce (VS Code Extension CLI)...
    call npm install -g @vscode/vsce
)

echo.
echo [1/4] Installing dependencies...
call npm install
if errorlevel 1 (
    echo ERROR: npm install failed
    exit /b 1
)

echo.
echo [2/4] Compiling TypeScript...
call npm run compile
if errorlevel 1 (
    echo ERROR: TypeScript compilation failed
    exit /b 1
)

echo.
echo [3/4] Validating extension structure...
if not exist "out\rawrxdScriptExtension.js" (
    echo ERROR: Extension entry point not found
    echo Expected: out\rawrxdScriptExtension.js
    exit /b 1
)
if not exist "out\debugAdapterFactory.js" (
    echo WARNING: Debug adapter factory not found
)
if not exist "out\registerViewProvider.js" (
    echo WARNING: Register view provider not found
)

echo.
echo [4/4] Packaging extension...
call vsce package --out rawrxd-script-1.0.0.vsix
if errorlevel 1 (
    echo ERROR: vsce package failed
    exit /b 1
)

echo.
echo ===========================================
echo BUILD SUCCESSFUL
echo ===========================================
echo Output: rawrxd-script-1.0.0.vsix
echo.
echo Install in VS Code:
echo   code --install-extension rawrxd-script-1.0.0.vsix
echo.
echo Or drag-and-drop into VS Code Extensions panel
echo.
echo To test in Extension Development Host:
echo   Press F5 in VS Code (with this folder open)
echo ===========================================
