@echo off
:: Build script for comprehensive smoke test suite v3
:: All tiers: Literals, Arithmetic, Strings, Compare, Variables, Functions, Arrays, Objects, Control Flow

echo Building RawrXD Smoke Test Suite v3.0 (All Tiers)...
echo.

set SRC=..\src\script\smoke_test_suite_v3.cpp
set OUT=smoke_test_v3.exe

set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231
set WINSDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
set WINSDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0

"%VS_PATH%\bin\Hostx64\x64\cl.exe" /O2 /EHsc /std:c++20 /W4 /nologo /Fe:%OUT% %SRC% /I"%VS_PATH%\include" /I"%WINSDK_INC%\ucrt" /I"%WINSDK_INC%\um" /I"%WINSDK_INC%\shared" /link /LIBPATH:"%VS_PATH%\lib\x64" /LIBPATH:"%WINSDK_LIB%\ucrt\x64" /LIBPATH:"%WINSDK_LIB%\um\x64" 2>&1

if %ERRORLEVEL% neq 0 (
    echo.
    echo BUILD FAILED
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL: %OUT%
echo.
echo Running comprehensive smoke test suite...
echo.
%OUT%

exit /b %ERRORLEVEL%
