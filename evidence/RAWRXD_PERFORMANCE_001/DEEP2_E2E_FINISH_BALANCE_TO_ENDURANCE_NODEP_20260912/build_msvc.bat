@echo off
setlocal
cl /nologo /O2 /W4 /std:c11 /TC ^
selftest.c ^
deep2_decode_finish_balance.c ^
deep2_persistent_decode.c ^
deep2_residency_solver.c ^
deep2_streamer_live.c ^
deep2_endurance.c ^
/Fe:selftest.exe
if errorlevel 1 exit /b %errorlevel%
selftest.exe
