@echo off
setlocal
if not exist build mkdir build
cl /nologo /std:c++17 /EHsc /W4 /I src src\ExpertCache.cpp src\ExpertTensorCatalog.cpp src\PackedExpertSlicer.cpp src\Deep2ExpertCacheBridge.cpp src\HostStagingRing.cpp src\VulkanExpertTransport.cpp tests\test_expert_cache_async.cpp /Fe:build\test_expert_cache_async.exe || exit /b 1
build\test_expert_cache_async.exe > cert_RAWRXD_EXPERT_CACHE_004.txt
set RC=%ERRORLEVEL%
type cert_RAWRXD_EXPERT_CACHE_004.txt
exit /b %RC%
