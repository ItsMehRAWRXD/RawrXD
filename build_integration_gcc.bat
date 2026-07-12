@echo off
:: Build script for Titan Kernel Integration using MinGW GCC
:: Compiles all components and links them together

setlocal EnableDelayedExpansion

echo ╔══════════════════════════════════════════════════════════════╗
echo ║     TITAN KERNEL INTEGRATION BUILD (GCC)                     ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

:: Configuration
set "BUILD_DIR=d:\rawrxd\build"
set "SRC_DIR=d:\rawrxd\src"
set "ASM_DIR=d:\src\asm"
set "CXX=C:\ProgramData\mingw64\mingw64\bin\g++.exe"
set "CXXFLAGS=-std=c++17 -O2 -mavx2 -mfma -DNDEBUG -D_WIN32"
set "INCLUDES=-I%SRC_DIR% -I%ASM_DIR%"
set "LDFLAGS=-static-libgcc -static-libstdc++ -lkernel32"

:: Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/5] Building UnifiedKernelInterface.cpp...
"%CXX%" %CXXFLAGS% %INCLUDES% -c "%SRC_DIR%\core\execution\UnifiedKernelInterface.cpp" -o "%BUILD_DIR%\UnifiedKernelInterface.o" 2>&1
if errorlevel 1 (
    echo FAILED: UnifiedKernelInterface.cpp
    exit /b 1
)
echo ✓ UnifiedKernelInterface.o
echo.

echo [2/5] Building MemoryBridge.cpp...
"%CXX%" %CXXFLAGS% %INCLUDES% -c "%SRC_DIR%\core\execution\MemoryBridge.cpp" -o "%BUILD_DIR%\MemoryBridge.o" 2>&1
if errorlevel 1 (
    echo FAILED: MemoryBridge.cpp
    exit /b 1
)
echo ✓ MemoryBridge.o
echo.

echo [3/5] Building Titan_KernelIntegration.cpp...
"%CXX%" %CXXFLAGS% %INCLUDES% -c "%SRC_DIR%\core\execution\Titan_KernelIntegration.cpp" -o "%BUILD_DIR%\Titan_KernelIntegration.o" 2>&1
if errorlevel 1 (
    echo FAILED: Titan_KernelIntegration.cpp
    exit /b 1
)
echo ✓ Titan_KernelIntegration.o
echo.

echo [4/5] Building Sovereign_KernelDispatch_Runtime.cpp...
"%CXX%" %CXXFLAGS% %INCLUDES% -c "%SRC_DIR%\core\execution\Sovereign_KernelDispatch_Runtime.cpp" -o "%BUILD_DIR%\Sovereign_KernelDispatch.o" 2>&1
if errorlevel 1 (
    echo FAILED: Sovereign_KernelDispatch_Runtime.cpp
    exit /b 1
)
echo ✓ Sovereign_KernelDispatch.o
echo.

echo [5/5] Building TitanCLI.exe...
"%CXX%" %CXXFLAGS% %INCLUDES% "%SRC_DIR%\cli\TitanCLI.cpp" "%BUILD_DIR%\UnifiedKernelInterface.o" "%BUILD_DIR%\MemoryBridge.o" "%BUILD_DIR%\Titan_KernelIntegration.o" "%BUILD_DIR%\Sovereign_KernelDispatch.o" -o "%BUILD_DIR%\TitanCLI.exe" %LDFLAGS% 2>&1
if errorlevel 1 (
    echo FAILED: TitanCLI.exe linking
    exit /b 1
)
echo ✓ TitanCLI.exe
echo.

echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    BUILD COMPLETE                              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo Output files:
echo   %BUILD_DIR%\TitanCLI.exe       - CLI tool
echo.
echo Run tests:
echo   %BUILD_DIR%\TitanCLI.exe --status
echo   %BUILD_DIR%\TitanCLI.exe --test
echo   %BUILD_DIR%\TitanCLI.exe --benchmark
echo.

endlocal
