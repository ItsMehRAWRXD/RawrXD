@echo off
cd /d d:\RawrXD\src\ide

echo Testing compiler...

where cl >nul 2>nul
if errorlevel 1 (
    echo ERROR: cl.exe not found
    exit /b 1
)

echo Compiler found: 
cl 2>&1 | findstr "Microsoft"

echo.
echo Creating test file...
echo #include ^<windows.h^> > test_cl.cpp
echo int WINAPI WinMain(HINSTANCE,HINSTANCE,LPSTR,int){return 0;} >> test_cl.cpp

echo Compiling...
cl test_cl.cpp /Fetest_cl.exe /nologo

if errorlevel 1 (
    echo ERROR: Compilation failed
    exit /b 1
)

echo SUCCESS: Compiler works!
dir test_cl.exe
