@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\UNLINKED_SYMBOLS_E2E_001"
set FAILS=0
echo === COMPILE unlinked_symbols_batch_016.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_016.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_016.cpp"
set EC_016=%ERRORLEVEL%
echo EXIT_016=%EC_016%
if not %EC_016%==0 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_017.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_017.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_017.cpp"
set EC_017=%ERRORLEVEL%
echo EXIT_017=%EC_017%
if not %EC_017%==0 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_018.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_018.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_018.cpp"
set EC_018=%ERRORLEVEL%
echo EXIT_018=%EC_018%
if not %EC_018%==0 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_019.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_019.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_019.cpp"
set EC_019=%ERRORLEVEL%
echo EXIT_019=%EC_019%
if not %EC_019%==0 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_020.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_020.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_020.cpp"
set EC_020=%ERRORLEVEL%
echo EXIT_020=%EC_020%
if not %EC_020%==0 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_021.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_021.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_021.cpp"
set EC_021=%ERRORLEVEL%
echo EXIT_021=%EC_021%
if not %EC_021%==0 set /a FAILS+=1
echo === COMPILE unlinked_symbols_batch_022.cpp ===
cl /nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE /Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd /Fo"unlinked_symbols_batch_022.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_022.cpp"
set EC_022=%ERRORLEVEL%
echo EXIT_022=%EC_022%
if not %EC_022%==0 set /a FAILS+=1
echo FAILS=%FAILS%
exit /b %FAILS%
