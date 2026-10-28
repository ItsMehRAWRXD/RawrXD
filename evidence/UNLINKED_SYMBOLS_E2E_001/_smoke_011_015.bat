@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\UNLINKED_SYMBOLS_E2E_001"
set FAILS=0
echo === COMPILE unlinked_symbols_batch_001.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_001.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_001.cpp"
if errorlevel 1 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_011.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_011.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_011.cpp"
if errorlevel 1 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_012.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_012.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_012.cpp"
if errorlevel 1 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_013.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_013.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_013.cpp"
if errorlevel 1 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_014.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_014.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_014.cpp"
if errorlevel 1 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_015.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_015.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_015.cpp"
if errorlevel 1 set /a FAILS+=1
echo FAILS=%FAILS%
exit /b %FAILS%
