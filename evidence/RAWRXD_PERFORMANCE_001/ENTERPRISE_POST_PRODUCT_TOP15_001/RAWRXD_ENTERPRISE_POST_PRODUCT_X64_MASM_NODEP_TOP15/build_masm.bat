@echo off
setlocal
where ml64 >nul 2>nul || exit /b 90
where link >nul 2>nul || exit /b 91

ml64 /nologo /c /Foenterprise_gate.obj enterprise_gate.asm
if errorlevel 1 exit /b %errorlevel%

ml64 /nologo /c /Foenterprise_smoke.obj enterprise_smoke.asm
if errorlevel 1 exit /b %errorlevel%

link /nologo /subsystem:console /entry:main ^
  enterprise_smoke.obj enterprise_gate.obj kernel32.lib ^
  /out:enterprise_smoke.exe
if errorlevel 1 exit /b %errorlevel%

enterprise_smoke.exe
if errorlevel 1 exit /b %errorlevel%

echo ENTERPRISE_TOP15_SMOKE=PASS
echo PRODUCT_AUTHORITY_MINTED=0
echo DECODE_AUTHORITY_MINTED=0
echo TOKEN_AUTHORITY_MINTED=0
echo PROMOTE_AUTHORITY_MINTED=0
exit /b 0
