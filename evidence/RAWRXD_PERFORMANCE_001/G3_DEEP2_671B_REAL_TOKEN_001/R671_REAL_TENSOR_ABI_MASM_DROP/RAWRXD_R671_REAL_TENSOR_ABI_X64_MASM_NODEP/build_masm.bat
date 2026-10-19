@echo off
setlocal
where ml64 >nul 2>nul || exit /b 90
where link >nul 2>nul || exit /b 91

for %%F in (r671_core deep2_r671_primitive real_tensor_gate abi_smoke) do (
  ml64 /nologo /c /Fo%%F.obj %%F.asm
  if errorlevel 1 exit /b %errorlevel%
)

link /nologo /subsystem:console /entry:main ^
  abi_smoke.obj r671_core.obj deep2_r671_primitive.obj ^
  kernel32.lib /out:r671_abi_smoke.exe
if errorlevel 1 exit /b %errorlevel%

r671_abi_smoke.exe
if errorlevel 1 exit /b %errorlevel%

echo R671_ABI_SMOKE=PASS
echo THIRD_PARTY_DEPS=0
echo PROMOTE=0
exit /b 0
