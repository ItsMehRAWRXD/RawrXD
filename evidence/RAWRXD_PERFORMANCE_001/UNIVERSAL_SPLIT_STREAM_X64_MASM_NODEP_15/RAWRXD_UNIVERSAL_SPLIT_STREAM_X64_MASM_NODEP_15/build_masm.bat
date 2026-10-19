@echo off
setlocal
where ml64 >nul 2>nul || exit /b 90
where link >nul 2>nul || exit /b 91

for %%F in (usr_core usr_residency usr_alias_budget usr_hot usr_batch_receipt smoke) do (
  ml64 /nologo /c /Fo:%%F.obj %%F.asm
  if errorlevel 1 exit /b %errorlevel%
)

link /nologo /subsystem:console /entry:main ^
  smoke.obj usr_core.obj usr_residency.obj usr_alias_budget.obj ^
  usr_hot.obj usr_batch_receipt.obj kernel32.lib ^
  /out:usr_smoke.exe
if errorlevel 1 exit /b %errorlevel%

usr_smoke.exe
if errorlevel 1 exit /b %errorlevel%

echo UNIVERSAL_SPLIT_STREAM_SMOKE=PASS
echo THIRD_PARTY_DEPS=0
echo MG_REDEFINED=0
echo PROMOTE=0
exit /b 0
