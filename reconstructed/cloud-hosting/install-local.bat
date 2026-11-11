@echo off
REM RawrXD Quantum Models - Offline Local Installation for Windows
REM This script sets up llama.cpp and models for local/offline use
REM No cloud services required!

setlocal EnableDelayedExpansion

set "INSTALL_DIR=%USERPROFILE%\RawrXD"
set "MODELS_DIR=%INSTALL_DIR%\models"
set "CACHE_DIR=%INSTALL_DIR%\cache"
set "LOGS_DIR=%INSTALL_DIR%\logs"
set "BIN_DIR=%INSTALL_DIR%\bin"

echo ================================================================
echo  RawrXD Quantum Models - Offline Local Installation (Windows)
echo  The Absolute Bestest Local AI Experience!
echo ================================================================
echo.

REM Create directory structure
echo [*] Setting up directories...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%MODELS_DIR%" mkdir "%MODELS_DIR%"
if not exist "%CACHE_DIR%" mkdir "%CACHE_DIR%"
if not exist "%LOGS_DIR%" mkdir "%LOGS_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
echo [+] Directories created at %INSTALL_DIR%
echo.

REM Check for Git
where git >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Git not found. Please install Git for Windows from:
    echo     https://git-scm.com/download/win
    echo.
    pause
    exit /b 1
)

REM Check for CMake
where cmake >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] CMake not found. Please install CMake from:
    echo     https://cmake.org/download/
    echo.
    pause
    exit /b 1
)

REM Check for Visual Studio or Build Tools
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] Visual C++ compiler not found.
    echo     Please install Visual Studio 2019 or later with C++ tools
    echo     OR install Visual Studio Build Tools from:
    echo     https://visualstudio.microsoft.com/downloads/
    echo.
    pause
    exit /b 1
)

REM Build llama.cpp
echo [*] Building llama.cpp server...
cd "%INSTALL_DIR%"

if exist "llama.cpp" (
    echo [*] Updating existing llama.cpp...
    cd llama.cpp
    git pull
) else (
    echo [*] Cloning llama.cpp...
    git clone https://github.com/ggerganov/llama.cpp.git
    cd llama.cpp
)

REM Build with CMake
echo [*] Compiling (this may take a few minutes)...
if not exist "build" mkdir build
cd build

REM Check for CUDA
set CMAKE_FLAGS=-DCMAKE_BUILD_TYPE=Release
where nvcc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] CUDA detected - enabling GPU acceleration
    set CMAKE_FLAGS=%CMAKE_FLAGS% -DLLAMA_CUBLAS=ON
)

cmake .. %CMAKE_FLAGS%
cmake --build . --config Release -j 4

REM Copy binaries
echo [*] Installing binaries...
if exist "bin\Release\server.exe" (
    copy /Y "bin\Release\server.exe" "%BIN_DIR%\llama-server.exe"
) else if exist "bin\Release\llama-server.exe" (
    copy /Y "bin\Release\llama-server.exe" "%BIN_DIR%\llama-server.exe"
) else (
    echo [!] Server binary not found after build
    pause
    exit /b 1
)

REM Copy other tools
if exist "bin\Release\main.exe" copy /Y "bin\Release\main.exe" "%BIN_DIR%\" >nul 2>&1
if exist "bin\Release\quantize.exe" copy /Y "bin\Release\quantize.exe" "%BIN_DIR%\" >nul 2>&1

echo [+] llama-server installed successfully
echo.

REM Check for models
echo [*] Checking for models...
set MODEL_COUNT=0
for %%f in ("%MODELS_DIR%\*.gguf") do set /a MODEL_COUNT+=1

if %MODEL_COUNT% equ 0 (
    echo [!] No models found. Would you like to download a sample model?
    echo.
    set /p DOWNLOAD="Download Phi-2 (2.7B parameters, ~1.6GB)? [Y/n]: "
    
    if /i "!DOWNLOAD!"=="y" goto DOWNLOAD_MODEL
    if /i "!DOWNLOAD!"=="" goto DOWNLOAD_MODEL
    goto SKIP_DOWNLOAD
    
    :DOWNLOAD_MODEL
    echo [*] Downloading Phi-2 Q4_K_M model from HuggingFace...
    cd "%MODELS_DIR%"
    
    REM Check for curl
    where curl >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        curl -L -o phi-2.Q4_K_M.gguf "https://huggingface.co/TheBloke/phi-2-GGUF/resolve/main/phi-2.Q4_K_M.gguf"
        if exist "phi-2.Q4_K_M.gguf" (
            echo [+] Model downloaded successfully
        ) else (
            echo [!] Download failed. You can manually download models to: %MODELS_DIR%
        )
    ) else (
        echo [!] curl not found. Please manually download a model to: %MODELS_DIR%
        echo     Example: https://huggingface.co/TheBloke/phi-2-GGUF
    )
    
    :SKIP_DOWNLOAD
) else (
    echo [+] Found %MODEL_COUNT% model(s)
)
echo.

REM Create launcher script
echo [*] Creating launcher scripts...

REM PowerShell launcher
(
echo $ErrorActionPreference = "Stop"
echo $InstallDir = "%INSTALL_DIR%"
echo $ModelsDir = "$InstallDir\models"
echo $LogsDir = "$InstallDir\logs"
echo.
echo # Find first available model
echo $Model = Get-ChildItem -Path $ModelsDir -Filter "*.gguf" ^| Select-Object -First 1
echo.
echo if (-not $Model^) {
echo     Write-Host "Error: No models found in $ModelsDir" -ForegroundColor Red
echo     Write-Host "Please download a GGUF model and place it in the models directory"
echo     exit 1
echo }
echo.
echo Write-Host "Starting RawrXD Local Server..." -ForegroundColor Green
echo Write-Host "Model: $($Model.Name^)" -ForegroundColor Cyan
echo Write-Host "API will be available at: http://localhost:8080" -ForegroundColor Cyan
echo Write-Host ""
echo Write-Host "Press Ctrl+C to stop"
echo Write-Host ""
echo.
echo # Start server
echo $env:PATH = "$InstallDir\bin;$env:PATH"
echo $ServerExe = "$InstallDir\bin\llama-server.exe"
echo.
echo ^& $ServerExe `
echo     --model $Model.FullName `
echo     --host 0.0.0.0 `
echo     --port 8080 `
echo     --threads $env:NUMBER_OF_PROCESSORS `
echo     --ctx-size 2048 `
echo     --batch-size 512 `
echo     *^>^&1 ^| Tee-Object -FilePath "$LogsDir\server.log"
) > "%BIN_DIR%\rawrxd-serve.ps1"

REM Batch launcher
(
echo @echo off
echo setlocal
echo.
echo set "INSTALL_DIR=%INSTALL_DIR%"
echo set "MODELS_DIR=%%INSTALL_DIR%%\models"
echo set "LOGS_DIR=%%INSTALL_DIR%%\logs"
echo set "BIN_DIR=%%INSTALL_DIR%%\bin"
echo.
echo REM Find first available model
echo for %%%%f in ^("%%MODELS_DIR%%\*.gguf"^) do ^(
echo     set "MODEL=%%%%f"
echo     goto :found
echo ^)
echo.
echo echo Error: No models found in %%MODELS_DIR%%
echo echo Please download a GGUF model and place it in the models directory
echo exit /b 1
echo.
echo :found
echo echo Starting RawrXD Local Server...
echo echo Model: %%MODEL%%
echo echo API will be available at: http://localhost:8080
echo echo.
echo echo Press Ctrl+C to stop
echo echo.
echo.
echo "%%BIN_DIR%%\llama-server.exe" ^
echo     --model "%%MODEL%%" ^
echo     --host 0.0.0.0 ^
echo     --port 8080 ^
echo     --threads %%NUMBER_OF_PROCESSORS%% ^
echo     --ctx-size 2048 ^
echo     --batch-size 512 ^
echo     2^>^&1 ^| tee "%%LOGS_DIR%%\server.log"
) > "%BIN_DIR%\rawrxd-serve.bat"

echo [+] Launcher scripts created
echo.

REM Create desktop shortcut
echo [*] Would you like to create a desktop shortcut?
set /p CREATE_SHORTCUT="[Y/n]: "

if /i "%CREATE_SHORTCUT%"=="y" goto CREATE_SHORTCUT
if /i "%CREATE_SHORTCUT%"=="" goto CREATE_SHORTCUT
goto SKIP_SHORTCUT

:CREATE_SHORTCUT
echo [*] Creating desktop shortcut...
(
echo Set oWS = WScript.CreateObject^("WScript.Shell"^)
echo sLinkFile = oWS.SpecialFolders^("Desktop"^) ^& "\RawrXD Server.lnk"
echo Set oLink = oWS.CreateShortcut^(sLinkFile^)
echo oLink.TargetPath = "%BIN_DIR%\rawrxd-serve.bat"
echo oLink.WorkingDirectory = "%INSTALL_DIR%"
echo oLink.Description = "RawrXD Quantum Models Local Server"
echo oLink.Save
) > "%TEMP%\create_shortcut.vbs"
cscript //nologo "%TEMP%\create_shortcut.vbs"
del "%TEMP%\create_shortcut.vbs"
echo [+] Desktop shortcut created
:SKIP_SHORTCUT
echo.

REM Add to PATH
echo [*] Adding to system PATH...
setx PATH "%BIN_DIR%;%PATH%" >nul 2>&1
echo [+] PATH updated (restart terminal to use 'rawrxd-serve')
echo.

REM Installation complete
echo ================================================================
echo  Installation Complete! 🎉
echo ================================================================
echo.
echo Quick Start:
echo   1. Start server: %BIN_DIR%\rawrxd-serve.bat
echo      (or double-click desktop shortcut)
echo   2. Test API: curl http://localhost:8080/health
echo   3. Or open browser: http://localhost:8080
echo.
echo Directories:
echo   Installation: %INSTALL_DIR%
echo   Models:       %MODELS_DIR%
echo   Logs:         %LOGS_DIR%
echo.
echo Next Steps:
echo   - Add more models to: %MODELS_DIR%
echo   - View available models: dir %MODELS_DIR%
echo   - Server logs: %LOGS_DIR%\server.log
echo.
echo Offline Mode: Everything works without internet! Models are cached locally.
echo.
echo ================================================================
pause
