@echo off
setlocal EnableExtensions
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set "BUILD=F:\rawrxd\build_tip_debug_rel"
set "SRC=F:\rawrxd\src\win32app\Win32IDE_PowerShellPanel.cpp"
set "OBJ=F:\rawrxd\build_tip_debug_rel\CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_PowerShellPanel.cpp.obj"
set "CAND=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_ps_routing_001"
set "INTEG=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001"
set "OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts"
set "LOG=%OUT%\relink_ps_panel_only.log"
echo START %DATE% %TIME% > "%LOG%"
call "%VCVARS%" >> "%LOG%" 2>&1
cd /d "%BUILD%" || (echo CD_FAIL>>"%LOG%" & exit /b 1)
echo CL_START >> "%LOG%"
cl.exe /nologo /TP -DENABLE_VULKAN=1 -DFORTIFY_SOURCE=2 -DGGML_USE_CPU -DGGML_USE_VULKAN -DHAVE_GGML=1 -DHAVE_VULKAN=1 -DNOMINMAX -DRAWRXD_HARDENING=1 -DRAWRXD_NATIVE_IDE_EXT=1 -DRAWR_HAS_QUICKJS=1 -DRAWR_QUICKJS_STUB=0 -D_CRT_SECURE_NO_WARNINGS -D_FORTIFY_SOURCE=2 -D_MBCS -D_WIN32_WINNT=0x0A00 -IF:\rawrxd\build_tip_debug_rel\generated -IF:\rawrxd\src -IF:\rawrxd\src\deep2 -IF:\rawrxd\src\win32app -IF:\rawrxd\src\modules -IF:\rawrxd\src\utils -IF:\rawrxd\src\snap -IF:\rawrxd\src\deep2\perf_fix -IF:\rawrxd\src\deep2\watchdog -IF:\rawrxd\3rdparty\ggml\include -IF:\rawrxd\tools\agent_esp\rawrxd_agent_esp -IF:\rawrxd\tools\deep2_snap\deep2_snap -IF:\rawrxd\tools\snap_process_guard -IF:\rawrxd\3rdparty\quickjs_ng -IF:\rawrxd\src\production -IF:\rawrxd\3rdparty\ggml\src\..\include -external:IC:\VulkanSDK\1.4.357.0\include -external:IF:\rawrxd\include -external:W0 /DWIN32 /D_WINDOWS /EHsc /Zi /O2 /Ob1 /DNDEBUG -std:c++20 -MD /MD /GS /guard:cf /guard:ehcont /VOLATILE:ISO /W4 /Zc:strictStrings /Zc:throwingNew /permissive- /EHsc /Fo"%OBJ%" /FdCMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\ /FS -c "%SRC%" >> "%LOG%" 2>&1
if errorlevel 1 (echo CL_FAIL>>"%LOG%" & type "%LOG%" & exit /b 2)
echo CL_OK >> "%LOG%"
echo NINJA_LINK_START >> "%LOG%"
ninja bin\RawrXD-Win32IDE-Native-Ext.exe >> "%LOG%" 2>&1
set "NEC=%ERRORLEVEL%"
echo NINJA_LINK_EXIT=%NEC% >> "%LOG%"
if not "%NEC%"=="0" (
  echo LINK_VIA_NINJA_FAIL trying restore note >> "%LOG%"
  type "%LOG%"
  exit /b 3
)
mkdir "%CAND%" 2>nul
mkdir "%INTEG%" 2>nul
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%" 2>&1
copy /Y "%BUILD%\bin\RawrXD-Win32IDE-Native-Ext.exe" "%INTEG%\RawrXD-Win32IDE-Native-Ext.exe" >> "%LOG%" 2>&1
certutil -hashfile "%CAND%\RawrXD-Win32IDE-Native-Ext.exe" SHA256 > "%OUT%\tip_ps_routing_001_sha.txt"
type "%OUT%\tip_ps_routing_001_sha.txt"
echo DONE %DATE% %TIME% >> "%LOG%"
exit /b 0
