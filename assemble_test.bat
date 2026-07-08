@echo off
cd /d d:\rawrxd\src\asm
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe" /c /Fo test_multi_arch_simple.obj test_multi_arch_simple.asm
echo Assembly exit code: %errorlevel%
