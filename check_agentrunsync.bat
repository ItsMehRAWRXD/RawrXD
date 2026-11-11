@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
echo === Checking deploy DLLs for AgentRunSync ===
for %%f in (F:\rawrxd\deploy\*.dll) do (
    echo Checking %%f
    dumpbin /exports %%f | findstr AgentRunSync
)
echo === Checking native_toolchain DLLs ===
for %%f in (F:\rawrxd\compilers\native_toolchain\*.dll) do (
    echo Checking %%f
    dumpbin /exports %%f | findstr AgentRunSync
)