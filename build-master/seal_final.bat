@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

echo ==========================================
echo RawrXD Golden Master Sealing System
echo ==========================================
echo.

REM Check for required files
echo [Check] Verifying source files...
if not exist "..\src\script\seal_full_corpus.cpp" (
    echo ERROR: seal_full_corpus.cpp not found
    exit /b 1
)
if not exist "..\src\script\golden_master.cpp" (
    echo ERROR: golden_master.cpp not found
    exit /b 1
)
if not exist "interpreter_seal.obj" (
    echo ERROR: interpreter_seal.obj not found
    exit /b 1
)

echo [1/5] Compiling golden_master.cpp...
cl /c /std:c++20 /W3 /O2 /nologo /Fo:golden_master.obj ..\src\script\golden_master.cpp /I..\src\script >nul 2>&1
if errorlevel 1 (
    echo FAILED: golden_master.cpp compilation
    exit /b 1
)
echo          OK

echo [2/5] Compiling seal_full_corpus.cpp...
cl /c /std:c++20 /W3 /O2 /nologo /Fo:seal_corpus.obj ..\src\script\seal_full_corpus.cpp /I..\src\script >nul 2>&1
if errorlevel 1 (
    echo FAILED: seal_full_corpus.cpp compilation
    exit /b 1
)
echo          OK

echo [3/5] Linking seal_corpus.exe...
link /nologo seal_corpus.obj golden_master.obj interpreter_seal.obj /out:seal_corpus.exe /subsystem:console >nul 2>&1
if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)
echo          OK

echo [4/5] Running sealing process...
echo.
seal_corpus.exe
if errorlevel 1 (
    echo.
    echo FAILED: Sealing execution
    exit /b 1
)

echo.
echo [5/5] Verifying output files...
if exist "rawrxd_golden_masters.db" (
    echo          rawrxd_golden_masters.db - CREATED
) else (
    echo          rawrxd_golden_masters.db - NOT FOUND
)
if exist "rawrxd_golden_masters.json" (
    echo          rawrxd_golden_masters.json - CREATED
) else (
    echo          rawrxd_golden_masters.json - NOT FOUND
)

echo.
echo ==========================================
echo Sealing Complete!
echo ==========================================
