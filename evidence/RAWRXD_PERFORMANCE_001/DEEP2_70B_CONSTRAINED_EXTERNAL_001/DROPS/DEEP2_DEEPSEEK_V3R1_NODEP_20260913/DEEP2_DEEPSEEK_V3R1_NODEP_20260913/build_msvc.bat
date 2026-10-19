@echo off
setlocal
where cl >nul 2>nul || (echo MSVC_NOT_FOUND & exit /b 2)
cl /nologo /EHsc /std:c++17 /O2 ^
 Deep2DeepSeekRuntime_Core.cpp Deep2DeepSeekRuntime_Router.cpp ^
 Deep2DeepSeekRuntime_Schedule.cpp Deep2DeepSeekRuntime_Residency.cpp ^
 Deep2DeepSeekRuntime_KvPrefill.cpp Deep2DeepSeekRuntime_MtpQuant.cpp ^
 Deep2DeepSeekRuntime_Prefetch.cpp Deep2DeepSeekDualStickAdapter.cpp ^
 selftest.cpp /Fe:deepseek_nodep_selftest.exe
if errorlevel 1 exit /b %errorlevel%
deepseek_nodep_selftest.exe
exit /b %errorlevel%
