@echo off
setlocal
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set CXX=g++
set SRC=d:\RawrXD\src\reverse
set OUT=d:\RawrXD\bin

if not exist "%OUT%" mkdir "%OUT%"

%CXX% -std=c++17 -O2 -mavx2 -mavx512f -mavx512bw -I%SRC% -o %OUT%\reverse_cli.exe %SRC%\ReverseModelLoader.cpp %SRC%\ReverseEngine.cpp %SRC%\reverse_cli.cpp

if %ERRORLEVEL% neq 0 (
    echo Build failed.
    exit /b 1
)

echo Built: %OUT%\reverse_cli.exe
endlocal
