@echo off
setlocal
set GATE=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_DIRECT_ICD_001
set VK=C:\VulkanSDK\1.4.357.0
set VS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set ICD=C:\Windows\System32\DriverStore\FileRepository\amdvlk.inf_amd64_914ba89eaaafdf60\amdvlk64.dll
mkdir "%GATE%" 2>nul
call "%VS%" >nul
cd /d G:\~dev\rawrxd\tools
rem IMPORTANT: do NOT link vulkan-1.lib — ICD only via LoadLibrary
cl /nologo /EHsc /std:c++17 /O2 /MD /I"%VK%\Include" ^
  g3_amdvlk_direct_icd.cpp g3_amdvlk_direct_icd_a0.cpp ^
  /Fe:"%GATE%\g3_amdvlk_direct_icd.exe" /link >"%GATE%\build.log" 2>&1
if errorlevel 1 (
  type "%GATE%\build.log"
  exit /b 1
)
dumpbin /DEPENDENTS "%GATE%\g3_amdvlk_direct_icd.exe" >"%GATE%\PE_DEPENDENTS.txt"
findstr /i "vulkan" "%GATE%\PE_DEPENDENTS.txt" >"%GATE%\deps_check.txt"
echo === PE vulkan imports (must be empty) ===
type "%GATE%\deps_check.txt"
"%GATE%\g3_amdvlk_direct_icd.exe" 7800 "%ICD%" >"%GATE%\SOLO_7800.txt"
echo EXIT_7800=%ERRORLEVEL%
"%GATE%\g3_amdvlk_direct_icd.exe" R9700 "%ICD%" >"%GATE%\SOLO_R9700.txt"
echo EXIT_R9700=%ERRORLEVEL%
echo === 7800 ===
type "%GATE%\SOLO_7800.txt"
echo === R9700 ===
type "%GATE%\SOLO_R9700.txt"
endlocal
