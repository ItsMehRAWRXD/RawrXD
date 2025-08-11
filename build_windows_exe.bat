@echo off
setlocal

set APP_NAME=AICodeGenerator
set ENTRY=ai_coder_windows.py
set DISTPATH=.
set VERSION_FILE=windows_version_info.txt
set ICON_FILE=app.ico

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
  echo Python not found in PATH. Please install Python 3.10+ and try again.
  exit /b 1
)

python -m pip install --upgrade pip
pip install --upgrade pyinstaller

set ICON_FLAG=
if exist "%ICON_FILE%" (
  set ICON_FLAG=--icon "%ICON_FILE%"
)

set VERSION_FLAG=
if exist "%VERSION_FILE%" (
  set VERSION_FLAG=--version-file "%VERSION_FILE%"
)

pyinstaller --clean --noupx --onedir --console --name %APP_NAME% --distpath %DISTPATH% %ICON_FLAG% %VERSION_FLAG% %ENTRY%

if exist "%APP_NAME%\%APP_NAME%.exe" (
  echo.
  echo ✅ Build complete: %APP_NAME%\%APP_NAME%.exe

  rem Optional code signing if env vars are provided
  rem Required: CERT_PFX_PATH and CERT_PFX_PASSWORD
  if defined CERT_PFX_PATH if defined CERT_PFX_PASSWORD (
    where signtool >nul 2>nul
    if %ERRORLEVEL% equ 0 (
      echo Signing executable...
      signtool sign /f "%CERT_PFX_PATH%" /p "%CERT_PFX_PASSWORD%" /tr http://timestamp.digicert.com /td SHA256 /fd SHA256 "%APP_NAME%\%APP_NAME%.exe"
      if %ERRORLEVEL% equ 0 (
        echo ✅ Code signing completed.
      ) else (
        echo ⚠️ Code signing failed. Proceeding without signature.
      )
    ) else (
      echo ℹ️ signtool not found. Skipping code signing.
    )
  ) else (
    echo ℹ️ CERT_PFX_PATH/CERT_PFX_PASSWORD not set. Skipping code signing.
  )
  exit /b 0
) else (
  echo.
  echo ❌ Build failed. Check PyInstaller output above.
  exit /b 1
)