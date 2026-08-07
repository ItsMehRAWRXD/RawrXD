@echo off
REM Build Deep2 API Server
REM ======================

echo Building Deep2 API Server...

set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe

REM Compile API Server
echo Compiling Deep2APIServer.cpp...
cl.exe /c /W3 /O2 /nologo /EHsc /std:c++17 /I. /I.. /I..\..\3rdparty /FoDeep2APIServer.obj Deep2APIServer.cpp
if errorlevel 1 (
    echo Compilation failed!
    exit /b 1
)

echo.
echo Linking API Server...
%LINK% /SUBSYSTEM:CONSOLE /OUT:Deep2APIServer.exe Deep2APIServer.obj Deep2Engine.obj ^
    ThreadPool.obj KVCache.obj MoERouter.obj MoEWeightProxy.obj MoEWeightsLoader.obj ^
    ws2_32.lib

if errorlevel 1 (
    echo Linking failed!
    exit /b 1
)

echo.
echo Build complete: Deep2APIServer.exe
echo.
echo To run: Deep2APIServer.exe ^<model.gguf^>
echo.

pause
