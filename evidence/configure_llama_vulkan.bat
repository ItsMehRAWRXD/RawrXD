@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
set VULKAN_SDK=C:\VulkanSDK\1.4.357.0
set PATH=%VULKAN_SDK%\Bin;%PATH%
cmake -S F:\llama.cpp-ref -B F:\llama.cpp-ref\build-vulkan -G Ninja -DCMAKE_BUILD_TYPE=Release -DGGML_VULKAN=ON -DGGML_CUDA=OFF -DGGML_HIP=OFF -DLLAMA_BUILD_SERVER=OFF
exit /b %ERRORLEVEL%
