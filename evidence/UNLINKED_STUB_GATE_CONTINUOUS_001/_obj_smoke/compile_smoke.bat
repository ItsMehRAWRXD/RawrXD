@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d "G:\~dev\rawrxd"
set OUT=G:\~dev\rawrxd\evidence\UNLINKED_STUB_GATE_CONTINUOUS_001\_obj_smoke
cl /c /nologo /DWIN32 /D_WINDOWS /EHsc /O2 /DNDEBUG /std:c++latest /MT /W0 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /IShip /Isrc /Iinclude /Fo%OUT%\batch_022.cpp.obj src\core\unlinked_symbols_batch_022.cpp
if errorlevel 1 exit /b 2
cl /c /nologo /DWIN32 /D_WINDOWS /EHsc /O2 /DNDEBUG /std:c++latest /MT /W0 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /IShip /Isrc /Fo%OUT%\batch_021.cpp.obj src\core\unlinked_symbols_batch_021.cpp
if errorlevel 1 exit /b 3
cl /c /nologo /DWIN32 /EHsc /O2 /DNDEBUG /std:c++latest /MT /W0 /Fo%OUT%\batch_015.cpp.obj src\core\unlinked_symbols_batch_015.cpp
if errorlevel 1 exit /b 4
dir %OUT%\*.obj
echo SMOKE_OK
exit /b 0
