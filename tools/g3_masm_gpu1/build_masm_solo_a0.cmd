@echo off
setlocal
set GATE=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_MASM_SOLO_A0_001
set SRC=G:\~dev\rawrxd\tools\g3_masm_gpu1
set VS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
set ML64=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\ml64.exe
mkdir "%GATE%\obj" 2>nul
call "%VS%" >nul
cd /d "%SRC%"
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_io.obj" g3_masm_io.asm || exit /b 1
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_matchw.obj" g3_masm_matchw.asm || exit /b 1
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_dxgi.obj" g3_masm_dxgi.asm || exit /b 1
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_vk_data.obj" g3_masm_vk_data.asm || exit /b 1
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_vk_a0.obj" g3_masm_vk_a0.asm || exit /b 1
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_vk_dev.obj" g3_masm_vk_dev.asm || exit /b 1
"%ML64%" /nologo /c /Fo"%GATE%\obj\g3_masm_main.obj" g3_masm_main.asm || exit /b 1
link /nologo /SUBSYSTEM:CONSOLE /OUT:"%GATE%\g3_masm_solo_a0.exe" ^
  "%GATE%\obj\g3_masm_io.obj" "%GATE%\obj\g3_masm_matchw.obj" "%GATE%\obj\g3_masm_dxgi.obj" ^
  "%GATE%\obj\g3_masm_vk_data.obj" "%GATE%\obj\g3_masm_vk_a0.obj" "%GATE%\obj\g3_masm_vk_dev.obj" ^
  "%GATE%\obj\g3_masm_main.obj" ^
  kernel32.lib ucrt.lib vcruntime.lib libcmt.lib /LIBPATH:"C:\VulkanSDK\1.4.357.0\Lib" vulkan-1.lib >"%GATE%\build.log" 2>&1
if errorlevel 1 (
  type "%GATE%\build.log"
  exit /b 1
)
"%GATE%\g3_masm_solo_a0.exe" >"%GATE%\PROBE_OUT.txt"
type "%GATE%\PROBE_OUT.txt"
echo PROBE_EXIT=%ERRORLEVEL%
endlocal
