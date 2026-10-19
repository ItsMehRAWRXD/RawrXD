@echo off
setlocal

ml64 /nologo /c /Foauthoritative_decode.obj authoritative_decode.asm
if errorlevel 1 exit /b %errorlevel%

ml64 /nologo /c /Fozero_harness.obj zero_harness.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  zero_harness.obj authoritative_decode.obj kernel32.lib ^
  /out:authoritative_decode_zero.exe
if errorlevel 1 exit /b %errorlevel%

ml64 /nologo /c /Fopositive_harness.obj positive_harness.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  positive_harness.obj authoritative_decode.obj kernel32.lib ^
  /out:authoritative_decode_positive.exe
if errorlevel 1 exit /b %errorlevel%

authoritative_decode_zero.exe
if errorlevel 1 exit /b 10

authoritative_decode_positive.exe
if errorlevel 1 exit /b 11

echo AUTHORITATIVE_RUNTIME_DECODE_TESTS=PASS
exit /b 0
