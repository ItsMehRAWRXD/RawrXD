@echo off
setlocal

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
  echo Python not found in PATH. Please install Python 3.10+ and try again.
  exit /b 1
)

python -m pip install --upgrade pip
pip install --upgrade pyinstaller

pyinstaller --noconfirm --onefile --console --name AICodeGenerator --distpath . ai_coder_windows.py

if exist "AICodeGenerator.exe" (
  echo.
  echo ✅ Build complete: AICodeGenerator.exe
  exit /b 0
) else (
  echo.
  echo ❌ Build failed. Check PyInstaller output above.
  exit /b 1
)