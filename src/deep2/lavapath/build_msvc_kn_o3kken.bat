@echo off
setlocal
ml64 /nologo /c /FoKN_O3KKEN.obj KN_O3KKEN.asm
if errorlevel 1 exit /b 1
lib /nologo /out:KN_O3KKEN.lib KN_O3KKEN.obj
exit /b %ERRORLEVEL%
