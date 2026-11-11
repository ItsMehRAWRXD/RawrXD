@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" amd64 >nul
echo === dumpbin /dependents single ===
dumpbin /dependents "F:\rawrxd\build\bin\aggregate_decode_single_smoke.exe"
echo === dumpbin /dependents multi ===
dumpbin /dependents "F:\rawrxd\build\bin\aggregate_decode_multi_smoke.exe"
echo === dumpbin /HEADERS lib (first) ===
dumpbin /HEADERS "F:\rawrxd\build\Release\deep2_engine_lib.lib" | findstr /i "machine timedatestamp sizeofcode sizeofimage"
echo === lib member Deep2Engine ===
dumpbin /LINKERMEMBER:1 "F:\rawrxd\build\Release\deep2_engine_lib.lib" | findstr /i "Deep2Engine KVCache AttentionWithCache"
echo === strings evidence AGGREGATE_DECODE_USE_DEEP2 / Deep2Backend ===
findstr /m /c:"DEEP2" "F:\rawrxd\build\bin\aggregate_decode_single_smoke.exe" && echo SINGLE_CONTAINS_DEEP2=1
findstr /m /c:"DEEP2" "F:\rawrxd\build\bin\aggregate_decode_multi_smoke.exe" && echo MULTI_CONTAINS_DEEP2=1
