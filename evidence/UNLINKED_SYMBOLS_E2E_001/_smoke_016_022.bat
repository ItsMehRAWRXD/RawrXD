@echo off
REM Object smoke 016-022 only. No full Win32IDE link.
REM PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 LINK=NOT_RUN
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\UNLINKED_SYMBOLS_E2E_001"
set FAILS=0
set INC=/Ig:\~dev\rawrxd\src\core /Ig:\~dev\rawrxd\src /Ig:\~dev\rawrxd\include /Ig:\~dev\rawrxd\src\win32app /Ig:\~dev\rawrxd
set CLF=/nologo /c /EHsc /std:c++20 /DWIN32 /D_WIN32 /DUNICODE /D_UNICODE %INC%

echo === COMPILE unlinked_symbols_batch_016.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_016.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_016.cpp"
echo EXIT_016=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo === COMPILE unlinked_symbols_batch_017.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_017.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_017.cpp"
echo EXIT_017=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo === COMPILE unlinked_symbols_batch_018.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_018.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_018.cpp"
echo EXIT_018=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo === COMPILE unlinked_symbols_batch_019.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_019.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_019.cpp"
echo EXIT_019=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo === COMPILE unlinked_symbols_batch_020.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_020.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_020.cpp"
echo EXIT_020=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo === COMPILE unlinked_symbols_batch_021.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_021.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_021.cpp"
echo EXIT_021=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo === COMPILE unlinked_symbols_batch_022.cpp ===
cl %CLF% /Fo"unlinked_symbols_batch_022.obj" "g:\~dev\rawrxd\src\core\unlinked_symbols_batch_022.cpp"
echo EXIT_022=%ERRORLEVEL%
if errorlevel 1 set /a FAILS+=1

echo FAILS=%FAILS%
exit /b %FAILS%
