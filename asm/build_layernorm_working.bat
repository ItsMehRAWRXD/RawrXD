@echo off
cd /d d:\src\asm

for /f "delims=" %%i in ('"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set VSPATH=%%i

set VCTOOLS=%VSPATH%\VC\Tools\MSVC
for /f %%i in ('dir /b /ad "%VCTOOLS%" ^| findstr /r "^[0-9]"') do set MSVCVER=%%i

set ML64="%VCTOOLS%\%MSVCVER%\bin\Hostx64\x64\ml64.exe"

echo Building working LayerNorm (copy-only version)...
%ML64% /c /W3 /Zi /Fo Sovereign_LayerNorm.obj Sovereign_LayerNorm_Working.asm

if errorlevel 1 (
    echo ERROR: Assembly failed
    exit /b 1
)

echo SUCCESS: Sovereign_LayerNorm.obj built
