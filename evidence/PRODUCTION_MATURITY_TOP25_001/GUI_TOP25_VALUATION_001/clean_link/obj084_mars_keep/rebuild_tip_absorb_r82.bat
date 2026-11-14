@echo off
setlocal
REM TIP_ABSORB_AUTH_HOLD R82: recompile ProductRunDecode + Deep2IDEIntegration ODR only.
REM Tip bin 6754616E RO. Do NOT recompile Deep2Engine (keepGPU sealed). PROMOTE=0.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\build_win32ide_link001"
set OBJ=g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\GUI_TOP25_VALUATION_001\clean_link\obj084_mars_keep
set LOG=%OBJ%\rebuild_tip_absorb_r82.log
set TIP=g:\~dev\rawrxd\bin\RawrXD-Win32IDE.exe
set CLFLAGS=/nologo /TP -DHAS_BRUTAL_GZIP_MASM=1 -DNOMINMAX -DRAWRXD_HAS_MW_KERNEL=1 -DRAWRXD_HAS_PROMPT_ENGINE=1 -DRAWR_ENABLE_VULKAN=1 -DRAWR_HAS_VULKAN=1 -DRAWR_HAS_MASM=1 -DRAWR_STANDALONE_INFERENCE=1 -DRAWR_PRODUCT_RUNTIME_OPEN_MIN=1 -DRAWR_RUN_SESSION_DECLS_ONLY=1 -DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -IG:\~dev\rawrxd\include -IC:\VulkanSDK\1.4.357.0\Include -IG:\~dev\rawrxd\src -IG:\~dev\rawrxd\src\deep2 -IG:\~dev\rawrxd\src\inference -IG:\~dev\rawrxd\src\engine -IG:\~dev\rawrxd\src\core -IG:\~dev\rawrxd\src\codec -IG:\~dev\rawrxd\src\masm -IG:\~dev\rawrxd\src\runtime\governance -IG:\~dev\rawrxd\3rdparty\quickjs_ng\.. -IG:\~dev\rawrxd\3rdparty\quickjs_ng -IG:\~dev\rawrxd\build_win32ide_link001\_deps\nlohmann_json-src\include /DWIN32 /D_WINDOWS /EHsc /O2 /Ob2 /DNDEBUG -std:c++latest -MT /GS- /W0 /arch:AVX512
echo BEGIN %DATE% %TIME%> "%LOG%"
powershell -NoProfile -Command "(Get-FileHash '%TIP%' -Algorithm SHA256).Hash" > "%OBJ%\_tip_pre_r82.txt"
cl.exe %CLFLAGS% /I"g:\~dev\rawrxd\src\deep2" /Fo"%OBJ%\ProductRunDecode.cpp.obj" /Fd"%OBJ%\decode_r82.pdb" /FS -c "g:\~dev\rawrxd\src\deep2\lavapath\ProductRunDecode.cpp" >> "%LOG%" 2>&1
echo CL_DECODE=%ERRORLEVEL%>> "%LOG%"
if errorlevel 1 goto :eof
cl.exe %CLFLAGS% /Fo"%OBJ%\Deep2IDEIntegration_r80.cpp.obj" /Fd"%OBJ%\ide_r82.pdb" /FS -c "g:\~dev\rawrxd\src\deep2\Deep2IDEIntegration.cpp" >> "%LOG%" 2>&1
echo CL_IDE=%ERRORLEVEL%>> "%LOG%"
if errorlevel 1 goto :eof
link.exe @"%OBJ%\link084_qdim_tip_absorb_r82.rsp" >> "%LOG%" 2>&1
echo LINK=%ERRORLEVEL%>> "%LOG%"
powershell -NoProfile -Command "(Get-FileHash '%TIP%' -Algorithm SHA256).Hash" > "%OBJ%\_tip_post_r82.txt"
echo END %DATE% %TIME%>> "%LOG%"
endlocal
