@echo off
setlocal
cl /nologo /O2 /W4 /std:c11 /TC ^
  selftest.c ^
  d2_engine_ssvk_decode_bind.c ^
  d2_persistent_decode_gate.c ^
  d2_daily_streamer_live.c ^
  d2_endurance_gate.c ^
  /Fe:selftest.exe
if errorlevel 1 exit /b %errorlevel%
selftest.exe
