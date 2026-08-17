@echo off
cd d:\src
set GCC=C:\ProgramData\mingw64\mingw64\bin\g++.exe
set BUILD_DIR=build-unified-final
set CFLAGS=-std=c++17 -O2 -Wall -Isrc -Isrc\include -Isrc\deep2 -Isrc\core -Isrc\unified -Isrc\context -Isrc\agent -Isrc\inference -Isrc\tokenizer -DUNICODE -D_UNICODE -DPHASE15_UNIFIED -DNDEBUG
set LDFLAGS=-static-libgcc -static-libstdc++ -Wl,--subsystem,console

echo Building remaining files...

%GCC% %CFLAGS% -c -o %BUILD_DIR%\AIServiceAdapter.obj src\unified\AIServiceAdapter.cpp
if errorlevel 1 (
    echo FAILED: AIServiceAdapter.cpp
    exit /b 1
)
echo OK: AIServiceAdapter.obj

%GCC% %CFLAGS% -c -o %BUILD_DIR%\RawrXDHost.obj src\unified\RawrXDHost.cpp
if errorlevel 1 (
    echo FAILED: RawrXDHost.cpp
    exit /b 1
)
echo OK: RawrXDHost.obj

%GCC% %CFLAGS% -c -o %BUILD_DIR%\main_unified.obj src\unified\main_unified.cpp
if errorlevel 1 (
    echo FAILED: main_unified.cpp
    exit /b 1
)
echo OK: main_unified.obj

echo.
echo Linking RawrXDUnified.exe...
%GCC% %LDFLAGS% -o %BUILD_DIR%\RawrXDUnified.exe ^
    %BUILD_DIR%\main_unified.obj ^
    %BUILD_DIR%\RawrXDHost.obj ^
    %BUILD_DIR%\AIServiceAdapter.obj ^
    %BUILD_DIR%\CompilerAgent.obj ^
    %BUILD_DIR%\ContextEngine.obj ^
    %BUILD_DIR%\Deep2Provider.obj ^
    %BUILD_DIR%\Deep2Engine.obj ^
    %BUILD_DIR%\Tokenizer.obj ^
    %BUILD_DIR%\advanced_sampler.obj ^
    -lws2_32 -lwinmm

if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)

echo SUCCESS: RawrXDUnified.exe created!
dir %BUILD_DIR%\RawrXDUnified.exe
