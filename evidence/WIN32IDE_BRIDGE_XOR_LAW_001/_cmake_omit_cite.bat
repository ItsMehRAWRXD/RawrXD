@echo off
setlocal
set EV=G:\~dev\rawrxd\evidence\WIN32IDE_BRIDGE_XOR_LAW_001
echo === CMakeLists.txt refs to win32ide_asm_kernel_bridge === > "%EV%\cmake_omit_cite.txt"
findstr /N /I /C:"win32ide_asm_kernel_bridge" "G:\~dev\rawrxd\CMakeLists.txt" >> "%EV%\cmake_omit_cite.txt"
if errorlevel 1 echo MATCH_COUNT=0 CMAKE_OMIT=1 >> "%EV%\cmake_omit_cite.txt"
echo === Auth map cite (product owner) === >> "%EV%\cmake_omit_cite.txt"
findstr /I "camellia256_auth" "G:\~dev\rawrxd\evidence\CAMELLIA_AUTH_ASM_BIND_001\map_auth_symbols.txt" >> "%EV%\cmake_omit_cite.txt"
echo === Source gate cite === >> "%EV%\cmake_omit_cite.txt"
findstr /N /I "GATED_OMIT RAWR_HAS_MASM WIN32IDE_BRIDGE_XOR" "G:\~dev\rawrxd\src\core\win32ide_asm_kernel_bridge.cpp" >> "%EV%\cmake_omit_cite.txt"
echo DONE >> "%EV%\cmake_omit_cite.txt"
exit /b 0
