@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cd /d F:\~dev\rawrxd
cl /std:c++20 /EHsc /O2 /I src /I "F:\~dev\_deps\nlohmann_json-src\include" /I src\deep2 /I src\deep2\lavapath /I src\core /I "C:\VulkanSDK\1.4.357.0\Include" /DUNICODE /D_UNICODE F:\~dev\kilo_tmp\probe_tensors.cpp /Fe:F:\~dev\kilo_tmp\probe_tensors.exe src\deep2\GGUFLoader.cpp