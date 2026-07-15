@echo off
setlocal

set LINK="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
set OUT=d:\rawrxd\build-masm-x64\RawrXD_x64_IDE.exe
set OBJDIR=d:\rawrxd\build-masm-x64\obj
set LIBPATH="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"
set UCRTPATH="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
set UMSPATH="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

%LINK% /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
  /OUT:%OUT% ^
  /LIBPATH:%LIBPATH% ^
  /LIBPATH:%UCRTPATH% ^
  /LIBPATH:%UMSPATH% ^
  @d:\rawrxd\build-masm-x64\link_objects.txt ^
  kernel32.lib user32.lib ntdll.lib ucrt.lib legacy_stdio_definitions.lib ^
  2>d:\rawrxd\build-masm-x64\link_errors.txt

echo Link exit code: %ERRORLEVEL%

if %ERRORLEVEL%==0 (
  echo SUCCESS: %OUT%
  dir %OUT%
) else (
  echo FAILED — see link_errors.txt
  type d:\rawrxd\build-masm-x64\link_errors.txt
)
