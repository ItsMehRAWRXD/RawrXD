@echo off
setlocal

set "VCROOT=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "INCLUDE=d:\rawrxd\src\reverse_engineering"
set "OBJ=d:\rawrxd\build_abi_validator\RawrCodex_Multi_Reference_v极端的2.obj"

"%VCROOT%\cl.exe" /EHsc /I %INCLUDE% d:\rawrxd\src\asm\test_mips32.cpp %OBJ% /link /OUT:test_mips32.exe

if %errorlevel% equ 0 (
    echo SUCCESS: test_mips32.exe built
    echo Running test...
    test_mips32.exe
) else (
    echo FAILED: Compilation failed
    exit /b 1
)