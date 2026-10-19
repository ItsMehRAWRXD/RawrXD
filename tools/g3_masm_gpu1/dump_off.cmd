@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd\tools\g3_masm_gpu1
set VK=C:\VulkanSDK\1.4.357.0
(
echo #include ^<stddef.h^>
echo #include ^<stdio.h^>
echo #include ^<vulkan/vulkan.h^>
echo int main^(void^){
echo printf^("APP=%%llu INST=%%llu QCI=%%llu DCI=%%llu\n", ^(unsigned long long^)sizeof^(VkApplicationInfo^), ^(unsigned long long^)sizeof^(VkInstanceCreateInfo^), ^(unsigned long long^)sizeof^(VkDeviceQueueCreateInfo^), ^(unsigned long long^)sizeof^(VkDeviceCreateInfo^)^);
echo printf^("APP_api=%%llu\n", ^(unsigned long long^)offsetof^(VkApplicationInfo, apiVersion^)^);
echo printf^("QCI_fam=%%llu QCI_cnt=%%llu QCI_prio=%%llu\n", ^(unsigned long long^)offsetof^(VkDeviceQueueCreateInfo, queueFamilyIndex^), ^(unsigned long long^)offsetof^(VkDeviceQueueCreateInfo, queueCount^), ^(unsigned long long^)offsetof^(VkDeviceQueueCreateInfo, pQueuePriorities^)^);
echo printf^("DCI_qcnt=%%llu DCI_pqi=%%llu DCI_feat=%%llu\n", ^(unsigned long long^)offsetof^(VkDeviceCreateInfo, queueCreateInfoCount^), ^(unsigned long long^)offsetof^(VkDeviceCreateInfo, pQueueCreateInfos^), ^(unsigned long long^)offsetof^(VkDeviceCreateInfo, pEnabledFeatures^)^);
echo printf^("MEM_heapN=%%llu MEM_heaps=%%llu\n", ^(unsigned long long^)offsetof^(VkPhysicalDeviceMemoryProperties, memoryHeapCount^), ^(unsigned long long^)offsetof^(VkPhysicalDeviceMemoryProperties, memoryHeaps^)^);
echo printf^("PROPS_name=%%llu\n", ^(unsigned long long^)offsetof^(VkPhysicalDeviceProperties, deviceName^)^);
echo return 0;
echo }
) > off.cpp
cl /nologo /I"%VK%\Include" off.cpp /Fe:off.exe /link /LIBPATH:"%VK%\Lib" vulkan-1.lib
off.exe
