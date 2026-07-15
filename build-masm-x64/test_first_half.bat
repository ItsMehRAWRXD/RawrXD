@echo off
setlocal

set LINK="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
set OUT=d:\rawrxd\build-masm-x64\test1.exe
set LIBPATH1="C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\lib\x64"
set LIBPATH2="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
set LIBPATH3="C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"

%LINK% /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB /LARGEADDRESSAWARE:NO /OUT:%OUT% @d:\rawrxd\build-masm-x64\link_first_half.txt kernel32.lib user32.lib ntdll.lib ucrt.lib legacy_stdio_definitions.lib /LIBPATH:%LIBPATH1% /LIBPATH:%LIBPATH2% /LIBPATH:%LIBPATH3% 2>d:\rawrxd\build-masm-x64\test1_err.txt

echo First half exit: %ERRORLEVEL%
if %ERRORLEVEL%==0 (
  echo FIRST HALF OK
) else (
  echo FIRST HALF FAILED
  type d:\rawrxd\build-masm-x64\test1_err.txt
)
