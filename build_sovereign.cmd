@echo off
set CL=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\cl.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set LIBDIRS=/LIBPATH:"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"
set INCDIRS=/I"D:\rawrxd-ci-bootstrap\src"
set SRCDIR=D:\rawrxd-ci-bootstrap\src\engine
set BINDIR=D:\rawrxd-ci-bootstrap\build\bin
set OBJDIR=D:\rawrxd-ci-bootstrap\build\obj

if not exist "%BINDIR%" mkdir "%BINDIR%"
if not exist "%OBJDIR%" mkdir "%OBJDIR%"

echo Compiling RawrXD_Sovereign.cpp...
"%CL%" /nologo /O2 /EHsc /std:c++20 /DUNICODE /DWIN32_LEAN_AND_MEAN %INCDIRS% /c /Fo"%OBJDIR%\RawrXD_Sovereign.obj" "%SRCDIR%\RawrXD_Sovereign.cpp"
if errorlevel 1 (
    echo COMPILE FAILED
    exit /b 1
)

echo Linking RawrXD_Sovereign.exe...
set RSPFILE=%TEMP%\sovereign_link.rsp
echo -nologo > "%RSPFILE%"
echo -MACHINE:X64 >> "%RSPFILE%"
echo -OUT:"%BINDIR%\RawrXD_Sovereign.exe" >> "%RSPFILE%"
echo "%OBJDIR%\RawrXD_Sovereign.obj" >> "%RSPFILE%"
echo kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib advapi32.lib ole32.lib >> "%RSPFILE%"
echo /SUBSYSTEM:WINDOWS >> "%RSPFILE%"
echo %LIBDIRS% >> "%RSPFILE%"

"%LINK%" @"%RSPFILE%"
if errorlevel 1 (
    echo LINK FAILED
    exit /b 1
)

for %%f in ("%BINDIR%\RawrXD_Sovereign.exe") do echo Built: %%~nxf  %%~zf bytes
echo Done.
exit /b 0
