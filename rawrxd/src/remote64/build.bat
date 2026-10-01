@echo off
setlocal
where ml64 >nul 2>nul || (echo ERROR: ml64.exe not found & exit /b 1)
where link >nul 2>nul || (echo ERROR: link.exe not found & exit /b 1)
if not exist build mkdir build
for %%F in (*.asm) do (
  echo [ASM] %%F
  ml64 /nologo /c /Fo"build\%%~nF.obj" "%%F" || exit /b 1
)
echo Objects assembled. Link these objects into the existing RawrXD target with:
echo kernel32.lib user32.lib gdi32.lib ws2_32.lib bcrypt.lib
echo No PASS is claimed until the Windows runtime certification gates complete.
