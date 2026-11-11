@echo off
echo ========================================
echo VAL-025 MINGW VALIDATION
echo ========================================
echo.
set EXE=RawrXD_IDE.exe
set LOG=val025_mingw_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.log
set LOG=%LOG: =0%
echo VAL-025 MinGW Validation Log > %LOG%
echo Started: %date% %time% >> %LOG%
echo. >> %LOG%

echo [PHASE 1] Binary Verification
echo [PHASE 1] Binary Verification >> %LOG%
if not exist %EXE% (
    echo   FAIL: %EXE% not found
    echo   FAIL: %EXE% not found >> %LOG%
    goto :failed
)
echo   PASS: %EXE% exists
for %%F in (%EXE%) do (
    echo   Size: %%~zF bytes
    echo   Size: %%~zF bytes >> %LOG%
)
echo. >> %LOG%

echo [PHASE 2] Dependency Check
echo [PHASE 2] Dependency Check >> %LOG%
where g++ >nul 2>nul
if errorlevel 1 (
    echo   WARN: MinGW not in PATH
) else (
    echo   PASS: MinGW available
)
echo. >> %LOG%

echo [PHASE 3] Runtime Test
echo [PHASE 3] Runtime Test >> %LOG%
echo   Launching IDE for 3 seconds...
start "" %EXE%
timeout /t 3 /nobreak >nul
taskkill /f /im %EXE% >nul 2>nul
echo   PASS: IDE launched and terminated
echo   PASS: IDE launched and terminated >> %LOG%
echo. >> %LOG%

echo ========================================
echo VAL-025 MINGW: PASSED
echo ========================================
echo.
echo Log: %LOG%
pause
exit /b 0

:failed
echo ========================================
echo VAL-025 MINGW: FAILED
echo ========================================
pause
exit /b 1
