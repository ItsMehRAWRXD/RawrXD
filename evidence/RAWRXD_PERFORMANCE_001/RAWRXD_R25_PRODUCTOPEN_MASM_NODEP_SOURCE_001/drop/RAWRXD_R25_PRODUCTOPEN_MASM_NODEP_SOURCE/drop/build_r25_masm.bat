@echo off
setlocal
where ml64 >nul 2>nul || (echo ml64 not found. Run from x64 Native Tools Command Prompt. & exit /b 1)
ml64 /nologo /c /Fo:r25_productopen_masm.obj r25_productopen_masm.asm || exit /b 1
link /nologo /lib /out:r25_productopen_masm.lib r25_productopen_masm.obj || exit /b 1
echo built r25_productopen_masm.lib
