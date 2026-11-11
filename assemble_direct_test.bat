@echo off
cd /d d:\rawrxd\src\asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /Fo test_multi_arch_direct.obj test_multi_arch_direct.asm
echo Assembly exit code: %errorlevel%
