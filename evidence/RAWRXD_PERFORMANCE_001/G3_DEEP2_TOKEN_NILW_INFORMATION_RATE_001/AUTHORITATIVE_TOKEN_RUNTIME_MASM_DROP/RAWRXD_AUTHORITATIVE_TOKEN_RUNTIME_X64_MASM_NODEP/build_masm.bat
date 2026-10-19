@echo off
setlocal

ml64 /nologo /c /Foauthoritative_token.obj authoritative_token.asm
if errorlevel 1 exit /b %errorlevel%

ml64 /nologo /c /Fozero_harness.obj zero_harness.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  zero_harness.obj authoritative_token.obj kernel32.lib ^
  /out:authoritative_token_zero.exe
if errorlevel 1 exit /b %errorlevel%

ml64 /nologo /c /Fopositive_harness.obj positive_harness.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  positive_harness.obj authoritative_token.obj kernel32.lib ^
  /out:authoritative_token_positive.exe
if errorlevel 1 exit /b %errorlevel%

authoritative_token_zero.exe
if errorlevel 1 exit /b 10

authoritative_token_positive.exe
if errorlevel 1 exit /b 11

echo AUTHORITATIVE_TOKEN_MASM_TESTS=PASS
exit /b 0
