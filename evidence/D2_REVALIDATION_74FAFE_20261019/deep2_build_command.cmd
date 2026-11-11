@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if errorlevel 1 exit /b 1
set "GGML_BUILD=F:\rawrxd\.build_d2_revalidate_74fafe\ggml"
set "SRC=F:\rawrxd\.worktrees\codex-d2-revalidate-74fafe\src"
set "T=F:\rawrxd\.worktrees\codex-d2-revalidate-74fafe\tools"
cl /nologo /std:c++20 /EHsc /O2 /W3 /permissive- /bigobj /openmp /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I C:\VulkanSDK\1.4.357.0\Include /I %SRC%\..\3rdparty\ggml\include /I %SRC% /I %SRC%\deep2 /I %SRC%\deep2\modelgenie /I F:\rawrxd\.worktrees\codex-d2-revalidate-74fafe\include /I F:\rawrxd\.worktrees\codex-d2-revalidate-74fafe %T%\deep2_bench_tps.cpp %SRC%\deep2\runtime_graph_executor.cpp %SRC%\deep2\modelgenie\universal_gguf.cpp %SRC%\deep2\quant_dot_dispatch.cpp %SRC%\vulkan_compute.cpp /FeF:\rawrxd\.build_d2_revalidate_74fafe\deep2_bench_tps.exe /link /LIBPATH:C:\VulkanSDK\1.4.357.0\Lib vulkan-1.lib psapi.lib /LIBPATH:%GGML_BUILD%\src\Release ggml.lib ggml-cpu.lib ggml-base.lib /LIBPATH:%GGML_BUILD%\bin\Release
exit /b %errorlevel%
