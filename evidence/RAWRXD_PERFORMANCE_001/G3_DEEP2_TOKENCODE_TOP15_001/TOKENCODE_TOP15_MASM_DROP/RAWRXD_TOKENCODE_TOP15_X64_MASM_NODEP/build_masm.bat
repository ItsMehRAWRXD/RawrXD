@echo off
setlocal

ml64 /nologo /c /Fotokencode15.obj tokencode15.asm
if errorlevel 1 exit /b %errorlevel%

for %%H in (zero positive tamper) do (
  ml64 /nologo /c /Fo%%H_harness.obj %%H_harness.asm
  if errorlevel 1 exit /b %errorlevel%

  link /nologo /subsystem:console /entry:main ^
    %%H_harness.obj tokencode15.obj kernel32.lib ^
    /out:tokencode15_%%H.exe
  if errorlevel 1 exit /b %errorlevel%

  tokencode15_%%H.exe
  if errorlevel 1 exit /b %errorlevel%
)

echo TOKENCODE_TOP15_X64_MASM_TESTS=PASS
exit /b 0
