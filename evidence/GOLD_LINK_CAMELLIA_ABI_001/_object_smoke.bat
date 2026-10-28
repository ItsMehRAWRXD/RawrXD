@echo off
setlocal
set EV=G:\~dev\rawrxd\evidence\GOLD_LINK_CAMELLIA_ABI_001
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

echo GOLD_LINK_CAMELLIA_ABI_001 object smoke > "%EV%\object_smoke.txt"
echo ASOF_UTC=2026-10-28 >> "%EV%\object_smoke.txt"

echo === Source ABI cite (gold_link_closure.cpp) === >> "%EV%\object_smoke.txt"
findstr /N /C:"GOLD_LINK_CAMELLIA_ABI_001" /C:"!RAWR_HAS_MASM" /C:"asm_camellia256_auth_encrypt_file" /C:"key, iv" "G:\~dev\rawrxd\src\core\gold_link_closure.cpp" >> "%EV%\object_smoke.txt"

echo === SMOKE A: RAWR_HAS_MASM=1 === >> "%EV%\object_smoke.txt"
cl /nologo /c /EHsc /std:c++20 /DRAWR_HAS_MASM=1 /Fo"%EV%\abi_masm1.obj" "%EV%\abi_smoke.cpp" >> "%EV%\object_smoke.txt" 2>&1
echo CL_MASM1_EXIT=%ERRORLEVEL% >> "%EV%\object_smoke.txt"
dumpbin /SYMBOLS "%EV%\abi_masm1.obj" > "%EV%\dumpbin_masm1.txt" 2>&1
findstr /I "camellia256_auth" "%EV%\dumpbin_masm1.txt" >> "%EV%\object_smoke.txt"
if errorlevel 1 echo CAMELLIA_AUTH_SYMBOLS_MASM1=NONE >> "%EV%\object_smoke.txt"

echo === SMOKE B: RAWR_HAS_MASM=0 === >> "%EV%\object_smoke.txt"
cl /nologo /c /EHsc /std:c++20 /DRAWR_HAS_MASM=0 /Fo"%EV%\abi_masm0.obj" "%EV%\abi_smoke.cpp" >> "%EV%\object_smoke.txt" 2>&1
echo CL_MASM0_EXIT=%ERRORLEVEL% >> "%EV%\object_smoke.txt"
dumpbin /SYMBOLS "%EV%\abi_masm0.obj" > "%EV%\dumpbin_masm0.txt" 2>&1
findstr /I "camellia256_auth" "%EV%\dumpbin_masm0.txt" >> "%EV%\object_smoke.txt"

echo === Link smoke MASM0 (two-path present) === >> "%EV%\object_smoke.txt"
link /nologo /OUT:"%EV%\abi_masm0.exe" "%EV%\abi_masm0.obj" >> "%EV%\object_smoke.txt" 2>&1
echo LINK_MASM0_EXIT=%ERRORLEVEL% >> "%EV%\object_smoke.txt"

echo === Auth.obj still product owner (cite map) === >> "%EV%\object_smoke.txt"
findstr /I "asm_camellia256_auth_encrypt_file" "G:\~dev\rawrxd\evidence\CAMELLIA_AUTH_ASM_BIND_001\map_auth_symbols.txt" >> "%EV%\object_smoke.txt"

echo DONE >> "%EV%\object_smoke.txt"
exit /b 0
