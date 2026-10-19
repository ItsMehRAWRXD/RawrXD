@echo off
setlocal
ml64 /nologo /c /For671_open_diag.obj r671_open_diag.asm
if errorlevel 1 exit /b %errorlevel%

ml64 /nologo /c /Fosmoke_diag.obj smoke_diag.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  smoke_diag.obj r671_open_diag.obj kernel32.lib ^
  /out:r671_open_diag.exe
if errorlevel 1 exit /b %errorlevel%

r671_open_diag.exe
set RC=%ERRORLEVEL%
echo R671_OPEN_DIAG_EXIT=%RC%
exit /b %RC%
