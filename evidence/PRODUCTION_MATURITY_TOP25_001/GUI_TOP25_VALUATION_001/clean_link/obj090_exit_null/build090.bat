@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set ROOT=G:\~dev\rawrxd
set OUT=%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj090_exit_null
set BUILD=%ROOT%\build_win32ide_link001
set LOG=%OUT%\build090.log
if not exist "%OUT%" mkdir "%OUT%"
echo BUILD090_BEGIN %DATE% %TIME%> "%LOG%"
cd /d "%BUILD%"

set CLFLAGS=/nologo /TP -DHAS_BRUTAL_GZIP_MASM=1 -DNOMINMAX -DRAWRXD_HAS_MW_KERNEL=1 -DRAWRXD_HAS_PROMPT_ENGINE=1 -DRAWR_ATOMIC_ACTIVATION_ENABLED=1 -DRAWR_CAPABILITY_TOKENS_ENABLED=1 -DRAWR_ENABLE_VULKAN=1 -DRAWR_HAS_MASM=1 -DRAWR_HAS_QUICKJS=1 -DRAWR_HAS_SOVEREIGN_ENGINES=1 -DRAWR_HAS_VULKAN=1 -DRAWR_STANDALONE_INFERENCE=1 -DRAWR_VULKAN_AVAILABLE=1 -DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -IG:\~dev\rawrxd\include -IC:\VulkanSDK\1.4.357.0\Include -IG:\~dev\rawrxd\src -IG:\~dev\rawrxd\src\deep2 -IG:\~dev\rawrxd\src\inference -IG:\~dev\rawrxd\src\engine -IG:\~dev\rawrxd\src\core -IG:\~dev\rawrxd\src\codec -IG:\~dev\rawrxd\src\masm -IG:\~dev\rawrxd\src\runtime\governance -IG:\~dev\rawrxd\3rdparty\quickjs_ng /DWIN32 /D_WINDOWS /EHsc /O2 /Ob2 /DNDEBUG -std:c++latest -MT /GS- /W0 /arch:AVX512

echo CL_GPUFWD>> "%LOG%"
cl.exe %CLFLAGS% /c "%ROOT%\src\deep2\Deep2Engine_GpuForward.cpp" /Fo"%OUT%\Deep2Engine_GpuForward.cpp.obj" /Fd"%OUT%\r75.pdb" /FS >> "%LOG%" 2>&1
echo CL_GPUFWD_RC=%ERRORLEVEL%>> "%LOG%"
if errorlevel 1 goto :done

echo CL_INFER>> "%LOG%"
cl.exe %CLFLAGS% /c "%ROOT%\src\product\gateway\product_deep2_infer.cpp" /Fo"%OUT%\product_deep2_infer.cpp.obj" /Fd"%OUT%\r75.pdb" /FS >> "%LOG%" 2>&1
echo CL_INFER_RC=%ERRORLEVEL%>> "%LOG%"
if errorlevel 1 goto :done

echo CL_SEH>> "%LOG%"
cl.exe %CLFLAGS% /c "%ROOT%\src\product\gateway\product_deep2_infer_seh.cpp" /Fo"%OUT%\product_deep2_infer_seh.cpp.obj" /Fd"%OUT%\r75.pdb" /FS >> "%LOG%" 2>&1
echo CL_SEH_RC=%ERRORLEVEL%>> "%LOG%"
if errorlevel 1 goto :done

echo MAKE_RSP>> "%LOG%"
powershell -NoProfile -Command ^
  "$src='%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj089_aa4f_bisect\link089.rsp';" ^
  "$dst='%OUT%\link090.rsp';" ^
  "$c=Get-Content $src -Raw;" ^
  "$c=$c -replace [regex]::Escape('g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj075_gemma_seal\Deep2Engine_GpuForward.cpp.obj'),'%OUT%\Deep2Engine_GpuForward.cpp.obj';" ^
  "$c=$c -replace [regex]::Escape('CMakeFiles\RawrXD-Win32IDE.dir\src\product\gateway\product_deep2_infer.cpp.obj'),'%OUT%\product_deep2_infer.cpp.obj';" ^
  "$c=$c -replace [regex]::Escape('g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj078_avfault\product_deep2_infer_seh.cpp.obj'),'%OUT%\product_deep2_infer_seh.cpp.obj';" ^
  "$c=$c -replace 'RawrXD-Win32IDE_tip_land_aa4f_r69','RawrXD-Win32IDE_tip_land_aa4f_r75';" ^
  "Set-Content -Path $dst -Value $c -NoNewline"

echo LINK>> "%LOG%"
link.exe @"%OUT%\link090.rsp" >> "%LOG%" 2>&1
echo LINK_RC=%ERRORLEVEL%>> "%LOG%"

if exist "%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_aa4f_r75.exe" (
  copy /Y "%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\RawrXD-Win32IDE_tip_land_aa4f_r75.exe" "%ROOT%\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\LOCKED\RawrXD-Win32IDE_tip_land_aa4f_r75.exe" >> "%LOG%" 2>&1
)

:done
echo BUILD090_END %DATE% %TIME%>> "%LOG%"
endlocal
