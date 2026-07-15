@echo off
setlocal

echo [1/3] Compiling test_mips32_isolated.cpp...
cl.exe /EHsc /I . test_mips32_isolated.cpp /link /OUT:test_mips32_isolated.exe

if %errorlevel% neq 0 (
    echo Compilation failed
    exit /b 1
)

echo [2/3] Linking with decoder object file...
link.exe test_mips32_isolated.obj ..\..\build_abi_validator\极端的RawrCodex_Multi_Reference_v2.obj /OUT:test_mips32_isolated.exe

if %errorlevel% neq 0 (
    echo Linking failed
    exit /b 1
)

echo [3/3] Running isolated MIPS32 test...
test_mips32_isolated.exe