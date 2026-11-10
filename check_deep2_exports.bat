@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
echo === Checking for Deep2_CreateEngine in DLLs ===
for %%f in (F:\rawrxd\compilers\native_toolchain\*.dll) do (
    echo Checking %%f
    dumpbin /exports %%f | findstr Deep2_CreateEngine
)
echo === Checking for RawrLaneGenerateStream ===
for %%f in (F:\rawrxd\compilers\native_toolchain\*.dll) do (
    echo Checking %%f
    dumpbin /exports %%f | findstr RawrLaneGenerateStream
)
echo === Checking for Deep2_Initialize ===
for %%f in (F:\rawrxd\compilers\native_toolchain\*.dll) do (
    echo Checking %%f
    dumpbin /exports %%f | findstr Deep2_Initialize
)