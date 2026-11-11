@echo off
set SRCFILES=%*
set OBJDIR=%~2
if "%OBJDIR%"=="" set OBJDIR=gatebuild\obj
mkdir F:\rawrxd\~dev\%OBJDIR% >nul 2>&1
cd /d F:\rawrxd\~dev
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo < nul
set VK=C:\VulkanSDK\1.4.357.0
set INC=/I. /IF:\rawrxd\~dev\rawrxd\src /IF:\rawrxd\~dev\rawrxd\src\deep2 /IF:\rawrxd\~dev\rawrxd\include /IF:\rawrxd\~dev\rawrxd\src\masm /I%VK%\Include /IF:\rawrxd\~dev\src /IF:\rawrxd\~dev\src\deep2
set DEFS=/DRAWRXD_DEEP2_CERT=1 /DRAWR_STANDALONE_INFERENCE=1 /DRAWR_HAS_SOVEREIGN_ENGINES=1 /DRAWR_HAS_VULKAN=1 /DRAWR_VULKAN_AVAILABLE=1 /DRAWRXD_STRICT_PRODUCTION_PROFILE=0 /DRAWRXD_PRODUCTION_STRIP_STUB_SOURCES=0 /DNOMINMAX /DWIN32_LEAN_AND_MEAN
cl /nologo /std:c++17 /O2 /arch:AVX512 /EHsc /c %INC% %DEFS% /FoF:\rawrxd\~dev\%OBJDIR%\ %1
