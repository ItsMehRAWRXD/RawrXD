@echo off
setlocal
where cl >nul 2>nul || (echo MSVC_NOT_FOUND & exit /b 2)
cl /nologo /EHsc /std:c++17 /O2 KimiCostAuthority_Core.cpp ^
 KimiCostAuthority_Compare.cpp KimiCostAuthority_Emit.cpp selftest.cpp ^
 /Fe:kimi_cost_selftest.exe
if errorlevel 1 exit /b %errorlevel%
kimi_cost_selftest.exe
exit /b %errorlevel%
