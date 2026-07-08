@echo off
REM Build ABI Validator for RawrCodex Multi-Architecture Decoder
REM Compiles abi_validator.cpp and links against RawrCodex_Multi_Reference_v2.obj

set ML64_EXE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CL_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe
set LINK_EXE=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe

set SDK_ROOT=C:\Program Files (x86)\Windows Kits\10
set SDK_VER=10.0.22621.0
set MSVC_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231

set INCLUDE=%MSVC_ROOT%\include;%SDK_ROOT%\Include\%SDK_VER%\ucrt;%SDK_ROOT%\Include\%SDK_VER%\um;%SDK_ROOT%\Include\%SDK_VER%\shared
set LIB=%MSVC_ROOT%\lib\x64;%SDK_ROOT%\Lib\%SDK_VER%\ucrt\x64;%SDK_ROOT%\Lib\%SDK_VER%\um\x64

set SRC_DIR=d:\rawrxd\src\reverse_engineering
set ASM_DIR=d:\rawrxd\src\asm
set BUILD_DIR=d:\rawrxd\build_abi_validator

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/4] Compiling check_offsets.cpp ...
"%CL_EXE%" /c /EHsc /std:c++17 /W4 /Zi /Od /I"%SRC_DIR%" ^
    /Fo"%BUILD_DIR%\check_offsets.obj" ^
    "%SRC_DIR%\check_offsets.cpp"

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo [2/4] Linking check_offsets.exe ...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /DEBUG:FULL ^
    /OUT:"%BUILD_DIR%\check_offsets.exe" ^
    "%BUILD_DIR%\check_offsets.obj" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo [3/4] Running check_offsets.exe ...
"%BUILD_DIR%\check_offsets.exe"

echo [4/4] Compiling abi_validator_simple.cpp ...
"%CL_EXE%" /c /EHsc /std:c++17 /W4 /Zi /Od /I"%SRC_DIR%" ^
    /Fo"%BUILD_DIR%\abi_validator_simple.obj" ^
    "%SRC_DIR%\abi_validator_simple.cpp"

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo [5/6] Copying RawrCodex_Multi_Reference_v2.obj ...
copy /Y "%ASM_DIR%\RawrCodex_Multi_Reference_v2.obj" "%BUILD_DIR%\"

echo [6/6] Linking abi_validator.exe ...
"%LINK_EXE%" /SUBSYSTEM:CONSOLE /DEBUG:FULL /LARGEADDRESSAWARE:NO ^
    /OUT:"%BUILD_DIR%\abi_validator.exe" ^
    "%BUILD_DIR%\abi_validator_simple.obj" ^
    "%BUILD_DIR%\RawrCodex_Multi_Reference_v2.obj" ^
    kernel32.lib user32.lib

if errorlevel 1 (
    echo ERROR: Linking failed
    exit /b 1
)

echo.
echo SUCCESS: abi_validator.exe built
echo Location: %BUILD_DIR%\abi_validator.exe
echo.
echo Running ABI validator...
"%BUILD_DIR%\abi_validator.exe"