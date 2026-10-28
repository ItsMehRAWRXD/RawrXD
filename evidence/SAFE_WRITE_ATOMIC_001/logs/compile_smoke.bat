@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "G:\~dev\rawrxd\evidence\SAFE_WRITE_ATOMIC_001\logs"
cl /nologo /c /EHsc /std:c++17 /IG:\~dev\rawrxd\src\win32app "G:\~dev\rawrxd\src\win32app\SafeWriteAtomic.cpp" "G:\~dev\rawrxd\src\win32app\SafeWriteRollback.cpp"
echo EXIT=!ERRORLEVEL!
