@echo off
set "INCLUDE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt"
set "LIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64"
set "PATH=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64;%PATH%"

cd /d d:\rawrxd
cl.exe /EHsc /Zi /W3 test_titan_load.cpp TITAN_X64_CORE.obj /Feti_load_test.exe
ti_load_test.exe
