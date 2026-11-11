@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /c /nologo /EHsc /std:c++20 /I F:\rawrxd\src /I F:\rawrxd\src\deep2 /I F:\rawrxd\3rdparty\ggml\include /I F:\rawrxd\3rdparty\ggml\src /I F:\rawrxd\include /I "C:\VulkanSDK\1.4.357.0\Include" F:\rawrxd\src\gguf_loader.cpp /FoF:\rawrxd\gguf_loader.obj