@echo off
set LIBPATH=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" /OUT:TestKVCache.exe /SUBSYSTEM:CONSOLE /ENTRY:TestKVCacheMain /MACHINE:X64 /LIBPATH:"%LIBPATH%" test_kv_cache_masm.obj kv_cache_standalone.obj kernel32.lib user32.lib
