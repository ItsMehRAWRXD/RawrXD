@echo off
setlocal

ml64 /nologo /c /Fotokencode_tokenid_domain.obj tokencode_tokenid_domain.asm
if errorlevel 1 exit /b %errorlevel%

for %%H in (bounded u64full tamper overflow) do (
  ml64 /nologo /c /Fo%%H_harness.obj %%H_harness.asm
  if errorlevel 1 exit /b %errorlevel%

  link /nologo /subsystem:console /entry:main ^
    %%H_harness.obj tokencode_tokenid_domain.obj kernel32.lib ^
    /out:tokenid_%%H.exe
  if errorlevel 1 exit /b %errorlevel%

  tokenid_%%H.exe
  if errorlevel 1 exit /b %errorlevel%
)

echo TOKENCODE_TOKENID_DOMAIN_X64_MASM_TESTS=PASS
exit /b 0
