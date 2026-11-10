@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
echo === sovereign_streaming_engine.dll ===
dumpbin /exports F:\rawrxd\compilers\native_toolchain\sovereign_streaming_engine.dll | findstr Deep2
echo === rawramxd_fabric.dll ===
dumpbin /exports F:\rawrxd\compilers\native_toolchain\rawramxd_fabric.dll | findstr Deep2
echo === sovereign_unified_model_loader.dll ===
dumpbin /exports F:\rawrxd\compilers\native_toolchain\sovereign_unified_model_loader.dll | findstr Deep2