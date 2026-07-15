@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

echo ==========================================
echo RawrXD Golden Master Sealing System
echo ==========================================
echo.

echo [1/3] Linking seal_corpus.exe...
link /nologo seal_corpus.obj golden_master.obj interpreter_seal.obj /out:seal_corpus.exe /subsystem:console
if errorlevel 1 (
    echo FAILED: Linking
    exit /b 1
)
echo          OK

echo [2/3] Running sealing process...
echo.
seal_corpus.exe
if errorlevel 1 (
    echo.
    echo FAILED: Sealing execution
    exit /b 1
)

echo.
echo [3/3] Verifying output files...
if exist "rawrxd_golden_masters.db" (
    echo          rawrxd_golden_masters.db - CREATED
    for %%F in (rawrxd_golden_masters.db) do echo          Size: %%~zF bytes
) else (
    echo          rawrxd_golden_masters.db - NOT FOUND
)
if exist "rawrxd_golden_masters.json" (
    echo          rawrxd_golden_masters.json - CREATED
    for %%F in (rawrxd_golden_masters.json) do echo          Size: %%~zF bytes
) else (
    echo          rawrxd_golden_masters.json - NOT FOUND
)

echo.
echo ==========================================
echo Sealing Complete!
echo ==========================================
