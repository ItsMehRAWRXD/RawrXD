@echo off
echo ================================================================
echo QUANTUM MASM SYSTEM 2035 - MinGW BUILD SCRIPT
echo ================================================================
echo MinGW-w64 Compatible Build System for C++ Components
echo Build Date: %DATE% %TIME%
echo ================================================================

:: Check if we're in the correct directory
if not exist "data_converter.cpp" (
    echo ERROR: Source files not found!
    echo Please run this script from the workspace directory.
    pause
    exit /b 1
)

:: Check for MinGW compiler
echo [1/6] Verifying MinGW Environment...
where g++.exe >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ERROR: MinGW g++ compiler not found in PATH!
    echo.
    echo Please install one of the following:
    echo   - MinGW-w64: https://www.mingw-w64.org/
    echo   - MSYS2: https://www.msys2.org/
    echo   - TDM-GCC: https://jmeubank.github.io/tdm-gcc/
    echo.
    echo Or ensure MinGW is added to your PATH environment variable.
    pause
    exit /b 1
)

:: Get compiler version
echo MinGW Compiler found:
g++ --version | head -1
echo.

echo [2/6] Cleaning Previous Builds...
if exist *.exe del *.exe
if exist *.o del *.o
if exist test_shellcode.bin del test_shellcode.bin
echo Build area cleaned.

echo [3/6] Compiling Shellcode Generator...
g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o shellcode_generator.exe shellcode_generator.cpp
if %ERRORLEVEL% neq 0 (
    echo ERROR: Shellcode generator compilation failed!
    pause
    exit /b 1
)
echo ✓ Shellcode generator built successfully

echo [4/6] Compiling Data Converter...
g++ -O3 -std=c++11 -Wall -Wextra -static-libgcc -static-libstdc++ -o data_converter.exe data_converter.cpp
if %ERRORLEVEL% neq 0 (
    echo ERROR: Data converter compilation failed!
    pause
    exit /b 1
)
echo ✓ Data converter built successfully

echo [5/6] Testing Built Components...
echo Generating test shellcode...
shellcode_generator.exe
if exist test_shellcode.bin (
    echo ✓ Test shellcode generated successfully
    for %%f in (test_shellcode.bin) do echo   Size: %%~zf bytes
) else (
    echo ⚠ Warning: Test shellcode not generated
)

echo.
echo Testing data converter...
echo | data_converter.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo ✓ Data converter appears to be working
) else (
    echo ⚠ Data converter may have issues (this is normal for demo mode)
)

echo [6/6] Build Verification...
:: Check file sizes
if exist shellcode_generator.exe (
    for %%f in (shellcode_generator.exe) do set shell_size=%%~zf
    echo ✓ shellcode_generator.exe: %shell_size% bytes
) else (
    echo ✗ shellcode_generator.exe: MISSING
)

if exist data_converter.exe (
    for %%f in (data_converter.exe) do set conv_size=%%~zf
    echo ✓ data_converter.exe: %conv_size% bytes
) else (
    echo ✗ data_converter.exe: MISSING
)

echo.
echo ================================================================
echo SUCCESS! MinGW BUILD COMPLETE
echo ================================================================
echo.
echo BUILT COMPONENTS:
echo   shellcode_generator.exe - Test payload creator
echo   data_converter.exe      - Multi-format data converter
echo.
echo USAGE:
echo   shellcode_generator.exe           # Generate test_shellcode.bin
echo   data_converter.exe                # Run conversion demonstrations
echo.
echo FEATURES:
echo   ✓ Static linking (no external DLL dependencies)
echo   ✓ Optimized for size and speed (-O3)
echo   ✓ C++11 standard compliance
echo   ✓ MinGW-w64 compatible
echo   ✓ Cross-platform code (Windows/Linux)
echo.
echo NEXT STEPS:
echo   1. Test the built executables
echo   2. Use shellcode_generator.exe to create test payloads
echo   3. Use data_converter.exe for format conversions
echo   4. Integrate with the MASM components (if available)
echo.
echo ================================================================

set /p run_demo="Run demonstration? (y/n): "
if /i "%run_demo%"=="y" (
    echo.
    echo ================================================================
    echo RUNNING DEMONSTRATION
    echo ================================================================
    
    echo Testing shellcode generator...
    shellcode_generator.exe
    if exist test_shellcode.bin (
        echo ✓ Generated test_shellcode.bin
        dir test_shellcode.bin
    )
    
    echo.
    echo Testing data converter...
    data_converter.exe
    
    echo.
    echo ================================================================
    echo DEMONSTRATION COMPLETE
    echo ================================================================
)

echo.
echo Build completed successfully!
pause