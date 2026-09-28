@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >NUL 2>NUL
cd /d "F:\~dev\rawrxd"
cl /std:c++20 /EHsc /O2 /I src /I "F:\~dev\_deps\nlohmann_json-src\include" /I src\deep2 /I src\deep2\lavapath /I src\core /I "C:\VulkanSDK\1.4.357.0\Include" /DUNICODE /D_UNICODE /c src\deep2\deep2_openai_server.cpp /Fobuild\server_obj\deep2_openai_server.obj
if errorlevel 1 goto fail
link /OUT:build\bin\deep2_openai_server.exe build\server_obj\deep2_openai_server.obj build\server_obj\deep2_openai_server_main.obj build\server_obj\VramStreamingController.obj build\server_obj\ExpertCache.obj build\server_obj\VulkanExpertTransport.obj build\server_obj\HostStagingRing.obj build\Release\InferenceEngine.lib advapi32.lib shell32.lib ws2_32.lib crypt32.lib winhttp.lib "C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto fail
echo LINK_OK
goto end
:fail
echo LINK_FAIL
:end
