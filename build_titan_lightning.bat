@echo off
REM TITAN Lightning x64 Build Script
REM Fully functional JIT + NF4 + AVX-512 engine

echo ==========================================
echo TITAN Lightning x64 Build System
echo ==========================================

set ML64="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
set LINK="C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
set SRC=TITAN_Lightning_x64.asm
set OBJ=TITAN_Lightning_x64.obj
set EXE=TITAN_Lightning_x64.exe

echo.
echo [1/3] Assembling %SRC%...
%ML64% /c /W3 /nologo /Zi /Fo %OBJ% %SRC%
if errorlevel 1 goto :asm_fail

echo.
echo [2/3] Linking %OBJ%...
%LINK% /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /LARGEADDRESSAWARE:NO ^
    /OUT:%EXE% %OBJ% kernel32.lib ^
    /SECTION:.text,ERW ^
    /DEBUG
if errorlevel 1 goto :link_fail

echo.
echo [3/3] Build SUCCESS!
echo.
echo Output: %EXE%
echo.
echo File info:
for %%F in (%EXE%) do (
    echo   Size: %%~zF bytes
    echo   Modified: %%~tF
)

echo.
echo ==========================================
echo Build complete. Run with: %EXE%
echo ==========================================
goto :done

:asm_fail
echo.
echo ERROR: Assembly failed!
echo Check syntax errors above.
goto :done

:link_fail
echo.
echo ERROR: Linking failed!
echo Check unresolved symbols above.
goto :done

:done
pause
