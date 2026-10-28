@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
cl /nologo /c /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS /DRAWR_HAS_MASM=1 /I src\core /I include /I . /FoG:\~dev\rawrxd\evidence\BLOCKER_CLEAR_015_001\_b04_smoke\win32ide_watchdog_init.obj src\core\win32ide_watchdog_init.cpp
echo WD_INIT_EXIT=!ERRORLEVEL!
cl /nologo /c /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS /DRAWR_HAS_MASM=1 /I src\core /I include /I . /I src /FoG:\~dev\rawrxd\evidence\BLOCKER_CLEAR_015_001\_b04_smoke\batch_005.obj src\core\unlinked_symbols_batch_005.cpp
echo BATCH005_EXIT=!ERRORLEVEL!
cl /nologo /c /EHsc /std:c++17 /O2 /DWIN32 /D_WINDOWS /DRAWR_HAS_MASM=1 /I src\core /I include /I . /I src /FoG:\~dev\rawrxd\evidence\BLOCKER_CLEAR_015_001\_b04_smoke\batch_001.obj src\core\unlinked_symbols_batch_001.cpp
echo BATCH001_EXIT=!ERRORLEVEL!
