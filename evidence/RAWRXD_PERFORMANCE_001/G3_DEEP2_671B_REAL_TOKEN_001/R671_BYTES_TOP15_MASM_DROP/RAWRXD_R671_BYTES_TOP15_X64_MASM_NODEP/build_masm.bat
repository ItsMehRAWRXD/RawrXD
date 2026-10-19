@echo off
setlocal

ml64 /nologo /c /For671_bytes15.obj r671_bytes15.asm
if errorlevel 1 exit /b %errorlevel%

for %%H in (zero positive tamper) do (
  ml64 /nologo /c /Fo%%H_harness.obj %%H_harness.asm
  if errorlevel 1 exit /b %errorlevel%

  link /nologo /subsystem:console /entry:main ^
    %%H_harness.obj r671_bytes15.obj kernel32.lib ^
    /out:r671_bytes15_%%H.exe
  if errorlevel 1 exit /b %errorlevel%

  r671_bytes15_%%H.exe
  if errorlevel 1 exit /b %errorlevel%
)

echo R671_BYTES_TOP15_X64_MASM_TESTS=PASS
exit /b 0
