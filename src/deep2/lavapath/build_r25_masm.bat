@echo off
setlocal
cd /d "%~dp0"
where ml64 >nul 2>nul || (echo ml64 not found. Use x64 Native Tools Prompt. & exit /b 1)
where lib >nul 2>nul || (echo lib.exe not found. & exit /b 1)
ml64 /nologo /c /For25_productopen_masm.obj r25_productopen_masm.asm || exit /b 1
lib /nologo /out:r25_productopen_masm.lib r25_productopen_masm.obj || exit /b 1
echo built r25_productopen_masm.lib
exit /b 0
