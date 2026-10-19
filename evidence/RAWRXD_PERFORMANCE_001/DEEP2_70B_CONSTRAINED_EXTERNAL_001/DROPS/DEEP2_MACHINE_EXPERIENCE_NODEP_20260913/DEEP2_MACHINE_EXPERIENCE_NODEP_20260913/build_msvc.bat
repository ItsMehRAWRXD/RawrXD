@echo off
setlocal
where cl >nul 2>nul || (echo MSVC_NOT_FOUND & exit /b 2)
cl /nologo /EHsc /std:c++17 /O2 ^
 Deep2MachineExperience_Key.cpp Deep2MachineExperience_Core.cpp ^
 Deep2MachineExperience_Predict.cpp Deep2MachineExperience_Persist.cpp ^
 DualStickExperienceAdapter.cpp selftest.cpp /Fe:mx_selftest.exe
if errorlevel 1 exit /b %errorlevel%
mx_selftest.exe
exit /b %errorlevel%
