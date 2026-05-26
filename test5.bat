@echo off
setlocal EnableDelayedExpansion
set VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe
if exist "%VSWHERE%" ( for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do ( set "VSINSTALLPATH=%%i" ) )
if not defined VSINSTALLPATH set "VSINSTALLPATH=C:\VS2022Enterprise"
call "%VSINSTALLPATH%\VC\Auxiliary\Build\vcvars64.bat"

set SRCDIR=%~dp0src
set BINDIR=%~dp0bin
if not exist "%BINDIR%" mkdir "%BINDIR%"

set ML64_FLAGS=/c /nologo /Zi /W3 /Cp /Cx
for %%F in ("%SRCDIR%\Sovereign_*.asm") do (
  echo Assembling %%F
  ml64.exe %ML64_FLAGS% /Fo"%BINDIR%\%%~nF.obj" "%%F"
)

set LINKCMD=link.exe /NOLOGO /OUT:"%BINDIR%\Sovereign_Kernel.exe" /SUBSYSTEM:CONSOLE /MACHINE:X64 /LARGEADDRESSAWARE /OPT:REF /OPT:ICF /NXCOMPAT /DYNAMICBASE
for %%F in ("%BINDIR%\*.obj") do (
  set LINKCMD=!LINKCMD! "%%F"
)
echo !LINKCMD!
!LINKCMD!
