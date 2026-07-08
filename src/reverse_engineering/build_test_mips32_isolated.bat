@echo off
setlocal

echo [1/3] Compiling test_mips32_isolated.cpp...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe" /EHsc /I . test_mips32_isolated.cpp /link /OUT:test_mips32_isolated.exe

if %errorlevel% neq 0 (
    echo Compilation failed
    exit /b 1
)

echo [2/3] Linking with decoder object file...
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" test_mips32_isolated.obj ..\..\build_abi_validator\RawrCodex_Multi_Reference_v2.obj /OUT:test_mips32_isolated.exe

if %errorlevel% neq 0 (
    echo Linking failed
    exit /b 1
)

echo [3/3] Running isolated MIPS32 test...
test_mips32_isolated.exe