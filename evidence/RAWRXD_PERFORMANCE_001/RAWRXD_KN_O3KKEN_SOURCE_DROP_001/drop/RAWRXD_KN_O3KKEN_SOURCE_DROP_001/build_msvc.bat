@echo off
setlocal
where ml64 >nul 2>nul || (echo ml64 not found. Run from x64 Native Tools Command Prompt. & exit /b 1)
where link >nul 2>nul || (echo link not found. Run from x64 Native Tools Command Prompt. & exit /b 1)
ml64 /nologo /c KN_O3KKEN.asm || exit /b 1
link /nologo /subsystem:console /entry:main KN_O3KKEN.obj kernel32.lib || exit /b 1
KN_O3KKEN.exe
set EC=%ERRORLEVEL%
echo KN_O3KKEN_SMOKE_EXIT=%EC%
if not "%EC%"=="42" exit /b 2
exit /b 0
