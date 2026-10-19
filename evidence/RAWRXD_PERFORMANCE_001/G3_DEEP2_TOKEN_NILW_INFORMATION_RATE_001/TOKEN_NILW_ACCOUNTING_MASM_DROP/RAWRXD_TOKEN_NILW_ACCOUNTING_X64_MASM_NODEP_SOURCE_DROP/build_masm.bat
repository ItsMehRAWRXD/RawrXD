@echo off
setlocal EnableExtensions

where ml64.exe >nul 2>nul || (echo BUILD_ERROR=ML64_NOT_FOUND& exit /b 2)
where link.exe >nul 2>nul || (echo BUILD_ERROR=LINK_NOT_FOUND& exit /b 3)
if not exist build mkdir build

for %%S in (nilw_u128 nilw_validate nilw_derive nilw_performance nilw_authorize nilw_accounting smoke_identity smoke_overhead smoke_q4_reuse smoke_reject_identity smoke_reject_budget) do (
  ml64.exe /nologo /c /Fo"build\%%S.obj" "%%S.asm"
  if errorlevel 1 (echo ASSEMBLE_FAIL=%%S& exit /b 10)
)

for %%T in (smoke_identity smoke_overhead smoke_q4_reuse smoke_reject_identity smoke_reject_budget) do (
  link.exe /nologo /nodefaultlib /machine:x64 /subsystem:console /entry:main /out:"build\%%T.exe" "build\%%T.obj" "build\nilw_u128.obj" "build\nilw_validate.obj" "build\nilw_derive.obj" "build\nilw_performance.obj" "build\nilw_authorize.obj" "build\nilw_accounting.obj" kernel32.lib
  if errorlevel 1 (echo LINK_FAIL=%%T& exit /b 20)
  "build\%%T.exe"
  if errorlevel 1 (echo SMOKE_FAIL=%%T& exit /b 30)
  echo SMOKE_%%T=PASS
)

echo BUILD_AND_SMOKE=PASS
echo THIRD_PARTY_DEPS=0
exit /b 0
