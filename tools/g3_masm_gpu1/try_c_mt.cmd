@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools\g3_masm_gpu1
set VK=C:\VulkanSDK\1.4.357.0
set GATE=G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_MASM_SOLO_A0_001
(
echo #include ^<stdio.h^>
echo #include ^<vulkan/vulkan.h^>
echo int main^(void^){
echo   VkApplicationInfo app={};
echo   app.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO;
echo   app.apiVersion=VK_API_VERSION_1_2;
echo   VkInstanceCreateInfo ci={};
echo   ci.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
echo   ci.pApplicationInfo=^&app;
echo   VkInstance inst=0;
echo   VkResult r=vkCreateInstance^(^&ci,0,^&inst^);
echo   printf^("C_MT_CREATE_INSTANCE=%%d\n", ^(int^)r^);
echo   if^(inst^) vkDestroyInstance^(inst,0^);
echo   return 0;
echo }
) > c_mt_ci.cpp
cl /nologo /MT /I"%VK%\Include" c_mt_ci.cpp /Fe:%GATE%\c_mt_ci.exe /link /LIBPATH:"%VK%\Lib" vulkan-1.lib
%GATE%\c_mt_ci.exe
echo C_EXIT=%ERRORLEVEL%
