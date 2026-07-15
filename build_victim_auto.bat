@echo off
setlocal

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINKER=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set MSVC_LIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64
set SDK_UM_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64
set SRC=d:\rawrxd\src\debugger\Victim.asm
set OBJ=d:\rawrxd\bin\Victim.obj
set EXE=d:\rawrxd\bin\Victim.exe
set LOG=d:\rawrxd\logs\victim_build.log

if not exist d:\rawrxd\logs mkdir d:\rawrxd\logs

if exist %OBJ% del %OBJ%
if exist %EXE% del %EXE%
if exist %LOG% del %LOG%

echo [1/2] Assembling Victim.asm...>>%LOG%
"%ML64%" /nologo /c "%SRC%" /Fo%OBJ% >>%LOG% 2>&1
if errorlevel 1 (
  echo BUILD_FAILED_ASM
  type %LOG%
  exit /b 1
)

if not exist %OBJ% (
  echo BUILD_FAILED_ASM_OUTPUT_MISSING
  echo ERROR: expected object missing: %OBJ%>>%LOG%
  type %LOG%
  exit /b 1
)

echo [2/2] Linking Victim.exe...>>%LOG%
"%LINKER%" /nologo /OUT:"%EXE%" /SUBSYSTEM:CONSOLE /ENTRY:main "%OBJ%" /LIBPATH:"%MSVC_LIB%" /LIBPATH:"%SDK_UM_LIB%" kernel32.lib user32.lib >>%LOG% 2>&1
if errorlevel 1 (
  echo BUILD_FAILED_LINK
  type %LOG%
  exit /b 1
)

if not exist %EXE% (
  echo BUILD_FAILED_LINK_OUTPUT_MISSING
  echo ERROR: expected executable missing: %EXE%>>%LOG%
  type %LOG%
  exit /b 1
)

echo BUILD_OK
exit /b 0
