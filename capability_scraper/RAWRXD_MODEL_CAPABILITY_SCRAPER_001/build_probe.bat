@echo off
where cl.exe >nul 2>nul || (echo ERROR: cl.exe not found. Run x64 Native Tools Command Prompt.& exit /b 1)
cl.exe /nologo /std:c++17 /O2 /EHsc /W4 model_capability_probe.cpp /Fe:model_capability_probe.exe
if errorlevel 1 exit /b %errorlevel%
echo BUILT=model_capability_probe.exe
echo VERDICT=PASS
