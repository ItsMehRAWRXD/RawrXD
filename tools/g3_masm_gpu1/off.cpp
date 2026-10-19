#include <stddef.h>
#include <stdio.h>
#include <vulkan/vulkan.h>
int main(void){
printf("APP=%llu INST=%llu QCI=%llu DCI=%llu\n", (unsigned long long)sizeof(VkApplicationInfo), (unsigned long long)sizeof(VkInstanceCreateInfo), (unsigned long long)sizeof(VkDeviceQueueCreateInfo), (unsigned long long)sizeof(VkDeviceCreateInfo));
printf("APP_api=%llu\n", (unsigned long long)offsetof(VkApplicationInfo, apiVersion));
printf("QCI_fam=%llu QCI_cnt=%llu QCI_prio=%llu\n", (unsigned long long)offsetof(VkDeviceQueueCreateInfo, queueFamilyIndex), (unsigned long long)offsetof(VkDeviceQueueCreateInfo, queueCount), (unsigned long long)offsetof(VkDeviceQueueCreateInfo, pQueuePriorities));
printf("DCI_qcnt=%llu DCI_pqi=%llu DCI_feat=%llu\n", (unsigned long long)offsetof(VkDeviceCreateInfo, queueCreateInfoCount), (unsigned long long)offsetof(VkDeviceCreateInfo, pQueueCreateInfos), (unsigned long long)offsetof(VkDeviceCreateInfo, pEnabledFeatures));
printf("MEM_heapN=%llu MEM_heaps=%llu\n", (unsigned long long)offsetof(VkPhysicalDeviceMemoryProperties, memoryHeapCount), (unsigned long long)offsetof(VkPhysicalDeviceMemoryProperties, memoryHeaps));
printf("PROPS_name=%llu\n", (unsigned long long)offsetof(VkPhysicalDeviceProperties, deviceName));
return 0;
}
