@echo off
call "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
lib /OUT:bin\RawrXD_Fix5A.lib bin\RawrXD_KVCache_Layout.obj bin\RawrXD_DeterministicPerformance.obj
echo Library built
