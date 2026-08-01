@echo off
cd /d d:\RawrXD\gateway
"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /EHsc /O2 /W3 /Fed:\RawrXD\build\RawrXDGateway.exe /Fod:\RawrXD\build\RawrXDGateway.obj RawrXDGateway_simple.cpp /link ws2_32.lib
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD SUCCESS
echo Output: d:\RawrXD\build\RawrXDGateway.exe
