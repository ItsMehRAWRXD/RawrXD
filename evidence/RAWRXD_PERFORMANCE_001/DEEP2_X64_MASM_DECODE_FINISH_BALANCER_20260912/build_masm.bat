@echo off
setlocal
if not exist build mkdir build
ml64 /nologo /c /Fo build\deep2_decode_balance.obj deep2_decode_balance.asm
if errorlevel 1 exit /b 1
echo BUILD=PASS
endlocal
