@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d F:\rawrxd
cl /nologo /std:c++20 /EHsc /O2 /W3 /I F:\rawrxd\src /I F:\rawrxd\src\deep2 /I F:\rawrxd\src\deep2\modelgenie tools\rawrxd_modelgenie_runtime_probe.cpp /Fe:F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\modelgenie_runtime_probe.exe > F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate11_modelgenie_build.log 2>&1
echo RC=%errorlevel% >> F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate11_modelgenie_build.log
