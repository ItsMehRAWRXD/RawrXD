@echo off
setlocal

ml64 /nologo /c /Foreverse_doublelayer_bypass.obj reverse_doublelayer_bypass.asm
if errorlevel 1 exit /b %errorlevel%

for %%H in (normal bypass stale_bypass epoch_mismatch) do (
  ml64 /nologo /c /Fo%%H_harness.obj %%H_harness.asm
  if errorlevel 1 exit /b %errorlevel%

  link /nologo /subsystem:console /entry:main ^
    %%H_harness.obj reverse_doublelayer_bypass.obj kernel32.lib ^
    /out:rdl_%%H.exe
  if errorlevel 1 exit /b %errorlevel%

  rdl_%%H.exe
  if errorlevel 1 exit /b %errorlevel%
)

echo REVERSE_DOUBLELAYER_BYPASS_X64_MASM_TESTS=PASS
exit /b 0
