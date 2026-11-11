// ============================================================================
// RawrXD GPU Execution Verifier
// Proves end-to-end GPU compute: device creation, VRAM allocation,
// shader dispatch, timestamp capture, and correctness verification.
// Uses Vulkan SDK headers (C:\VulkanSDK\1.4.328.1)
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <vulkan/vulkan.h>

uint32_t* LoadSPIRV(const char* path, size_t* outWordCount) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { printf("  FAIL: Cannot open %s\n", path); return NULL; }
    DWORD fileSize = GetFileSize(hFile, NULL);
    DWORD numWords = fileSize / 4;
    uint32_t* code = (uint32_t*)malloc(fileSize);
    if (!code) { CloseHandle(hFile); return NULL; }
    DWORD bytesRead;
    if (!ReadFile(hFile, code, fileSize, &bytesRead, NULL)) { free(code); CloseHandle(hFile); return NULL; }
    CloseHandle(hFile);
    *outWordCount = numWords;
    return code;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("========================================\n  RawrXD GPU Execution Verifier\n========================================\n\n");

    // [1] Create instance
    printf("[1] Creating Vulkan instance...\n");
    VkApplicationInfo appInfo = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    appInfo.pApplicationName = "RawrXD GPU Verifier";
    appInfo.applicationVersion = VK_MAKE_VERSION(1,0,0);
    appInfo.pEngineName = "RawrXD";
    appInfo.engineVersion = VK_MAKE_VERSION(1,0,0);
    appInfo.apiVersion = VK_API_VERSION_1_3;
    VkInstanceCreateInfo instInfo = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    instInfo.pApplicationInfo = &appInfo;
    VkInstance instance = VK_NULL_HANDLE;
    VkResult res = vkCreateInstance(&instInfo, NULL, &instance);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateInstance=%d\n",res); return 1; }
    printf("  OK\n");

    // [2] Enumerate devices
    printf("\n[2] Enumerating devices...\n");
    uint32_t devCount = 0;
    vkEnumeratePhysicalDevices(instance, &devCount, NULL);
    printf("  Found %u device(s)\n", devCount);
    if (!devCount) { vkDestroyInstance(instance,NULL); return 1; }
    VkPhysicalDevice* devices = (VkPhysicalDevice*)malloc(sizeof(VkPhysicalDevice)*devCount);
    vkEnumeratePhysicalDevices(instance, &devCount, devices);
    VkPhysicalDevice selDev = VK_NULL_HANDLE;
    int selIdx = -1;
    for (uint32_t i=0; i<devCount; i++) {
        VkPhysicalDeviceProperties p;
        vkGetPhysicalDeviceProperties(devices[i], &p);
        const char* t = "Other";
        if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU) t = "Discrete GPU";
        else if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU) t = "Integrated GPU";
        printf("\n  Device %u: %s (%s)\n    Vendor=0x%04X ID=0x%04X\n", i, p.deviceName, t, p.vendorID, p.deviceID);
        if (p.deviceType == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU && selIdx<0) { selDev=devices[i]; selIdx=i; }
    }
    if (selDev==VK_NULL_HANDLE && devCount>0) { selDev=devices[0]; selIdx=0; }
    VkPhysicalDeviceProperties selP;
    vkGetPhysicalDeviceProperties(selDev, &selP);
    printf("\n  Selected: Device %d - %s\n", selIdx, selP.deviceName);

    // [3] Memory
    printf("\n[3] Memory properties...\n");
    VkPhysicalDeviceMemoryProperties memP;
    vkGetPhysicalDeviceMemoryProperties(selDev, &memP);
    for (uint32_t i=0; i<memP.memoryHeapCount; i++) {
        printf("  Heap %u: %llu MB %s\n", i, (unsigned long long)(memP.memoryHeaps[i].size/(1024*1024)),
            (memP.memoryHeaps[i].flags & VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) ? "DEVICE_LOCAL" : "HOST");
    }
    int devLocalType=-1, hostVisType=-1;
    for (uint32_t i=0; i<memP.memoryTypeCount; i++) {
        VkMemoryPropertyFlags f = memP.memoryTypes[i].propertyFlags;
        if (f & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT && devLocalType<0) devLocalType=i;
        if ((f & VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) && (f & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) && hostVisType<0) hostVisType=i;
    }
    printf("  Device-local type: %d\n  Host-visible+coherent type: %d\n", devLocalType, hostVisType);

    // [4] Create device
    printf("\n[4] Creating logical device...\n");
    uint32_t qfCount = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(selDev, &qfCount, NULL);
    VkQueueFamilyProperties* qf = (VkQueueFamilyProperties*)malloc(sizeof(VkQueueFamilyProperties)*qfCount);
    vkGetPhysicalDeviceQueueFamilyProperties(selDev, &qfCount, qf);
    int compFam = -1;
    for (uint32_t i=0; i<qfCount; i++) { if (qf[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { compFam=i; printf("  Queue family %u: compute\n",i); break; } }
    if (compFam<0) { printf("  FAIL: no compute queue\n"); return 1; }
    float queuePriority = 1.0f;
    VkDeviceQueueCreateInfo qi = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    qi.queueFamilyIndex = compFam; qi.queueCount = 1; qi.pQueuePriorities = &queuePriority;
    VkDeviceCreateInfo di = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    di.queueCreateInfoCount = 1; di.pQueueCreateInfos = &qi;
    VkDevice device = VK_NULL_HANDLE;
    res = vkCreateDevice(selDev, &di, NULL, &device);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateDevice=%d\n",res); return 1; }
    VkQueue queue = VK_NULL_HANDLE;
    vkGetDeviceQueue(device, compFam, 0, &queue);
    printf("  OK\n");

    // [5] Command pool
    printf("\n[5] Creating command pool...\n");
    VkCommandPoolCreateInfo pci = { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    pci.queueFamilyIndex = compFam; pci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    VkCommandPool cmdPool = VK_NULL_HANDLE;
    res = vkCreateCommandPool(device, &pci, NULL, &cmdPool);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateCommandPool=%d\n",res); return 1; }
    printf("  OK\n");

    // [6] Allocate buffers
    printf("\n[6] Allocating GPU buffers...\n");
    const uint32_t NE = 1024;
    const VkDeviceSize BS = NE * sizeof(float);
    VkBufferCreateInfo bi = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    bi.size = BS; bi.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT | VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    bi.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    VkBuffer bufA, bufB, bufC;
    VkDeviceMemory memA, memB, memC;
    auto createBuf = [&](VkBuffer& b, VkDeviceMemory& m) {
        if (vkCreateBuffer(device, &bi, NULL, &b) != VK_SUCCESS) return false;
        VkMemoryRequirements mr; vkGetBufferMemoryRequirements(device, b, &mr);
        VkMemoryAllocateInfo ai = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
        ai.allocationSize = mr.size; ai.memoryTypeIndex = hostVisType;
        if (vkAllocateMemory(device, &ai, NULL, &m) != VK_SUCCESS) return false;
        vkBindBufferMemory(device, b, m, 0);
        return true;
    };
    if (!createBuf(bufA, memA) || !createBuf(bufB, memB) || !createBuf(bufC, memC)) {
        printf("  FAIL: buffer allocation\n"); return 1;
    }
    printf("  OK: 3 x %llu byte buffers\n", (unsigned long long)BS);
    float* dA; float* dB;
    vkMapMemory(device, memA, 0, BS, 0, (void**)&dA);
    vkMapMemory(device, memB, 0, BS, 0, (void**)&dB);
    for (uint32_t i=0; i<NE; i++) { dA[i]=1.0f; dB[i]=2.0f; }
    vkUnmapMemory(device, memA); vkUnmapMemory(device, memB);
    printf("  OK: Data uploaded (A=1.0, B=2.0)\n");

    // [7] Load SPIR-V
    printf("\n[7] Loading compute shader...\n");
    size_t spvWC = 0;
    uint32_t* spvCode = LoadSPIRV("gpu_verifier_add.spv", &spvWC);
    if (!spvCode) return 1;
    printf("  OK: %zu words loaded\n", spvWC);

    // [8] Shader module
    printf("\n[8] Creating shader module...\n");
    VkShaderModuleCreateInfo smi = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    smi.pCode = spvCode; smi.codeSize = spvWC * 4;
    VkShaderModule sm = VK_NULL_HANDLE;
    res = vkCreateShaderModule(device, &smi, NULL, &sm);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateShaderModule=%d\n",res); free(spvCode); return 1; }
    printf("  OK\n");

    // [9] Descriptor set layout
    printf("\n[9] Creating descriptor set layout...\n");
    VkDescriptorSetLayoutBinding bnd[3] = {};
    for (int i=0; i<3; i++) { bnd[i].binding=i; bnd[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; bnd[i].descriptorCount=1; bnd[i].stageFlags=VK_SHADER_STAGE_COMPUTE_BIT; }
    VkDescriptorSetLayoutCreateInfo dsli = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO };
    dsli.bindingCount = 3; dsli.pBindings = bnd;
    VkDescriptorSetLayout dsl = VK_NULL_HANDLE;
    res = vkCreateDescriptorSetLayout(device, &dsli, NULL, &dsl);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateDescriptorSetLayout=%d\n",res); free(spvCode); return 1; }
    printf("  OK\n");

    // [10] Pipeline layout
    printf("\n[10] Creating pipeline layout...\n");
    VkPipelineLayoutCreateInfo plli = { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    plli.setLayoutCount = 1; plli.pSetLayouts = &dsl;
    VkPipelineLayout pll = VK_NULL_HANDLE;
    res = vkCreatePipelineLayout(device, &plli, NULL, &pll);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreatePipelineLayout=%d\n",res); free(spvCode); return 1; }
    printf("  OK\n");

    // [11] Compute pipeline
    printf("\n[11] Creating compute pipeline...\n");
    VkPipelineShaderStageCreateInfo ssi = { VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO };
    ssi.stage = VK_SHADER_STAGE_COMPUTE_BIT; ssi.module = sm; ssi.pName = "main";
    VkComputePipelineCreateInfo cpi = { VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO };
    cpi.stage = ssi; cpi.layout = pll;
    VkPipeline pipeline = VK_NULL_HANDLE;
    res = vkCreateComputePipelines(device, VK_NULL_HANDLE, 1, &cpi, NULL, &pipeline);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateComputePipelines=%d\n",res); free(spvCode); return 1; }
    printf("  OK\n");

    // [12] Descriptor pool + set
    printf("\n[12] Creating descriptor pool...\n");
    VkDescriptorPoolSize ps = { VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, 3 };
    VkDescriptorPoolCreateInfo dpci = { VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO };
    dpci.maxSets = 1; dpci.poolSizeCount = 1; dpci.pPoolSizes = &ps;
    VkDescriptorPool dp = VK_NULL_HANDLE;
    res = vkCreateDescriptorPool(device, &dpci, NULL, &dp);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateDescriptorPool=%d\n",res); free(spvCode); return 1; }
    VkDescriptorSetAllocateInfo dsai = { VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO };
    dsai.descriptorPool = dp; dsai.descriptorSetCount = 1; dsai.pSetLayouts = &dsl;
    VkDescriptorSet ds = VK_NULL_HANDLE;
    vkAllocateDescriptorSets(device, &dsai, &ds);
    VkDescriptorBufferInfo bdA = {bufA,0,BS}, bdB = {bufB,0,BS}, bdC = {bufC,0,BS};
    VkWriteDescriptorSet w[3] = {};
    for (int i=0; i<3; i++) { w[i].sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET; w[i].dstSet=ds; w[i].dstBinding=i; w[i].descriptorCount=1; w[i].descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER; }
    w[0].pBufferInfo=&bdA; w[1].pBufferInfo=&bdB; w[2].pBufferInfo=&bdC;
    vkUpdateDescriptorSets(device, 3, w, 0, NULL);
    printf("  OK\n");

    // [13] Query pool
    printf("\n[13] Creating timestamp query pool...\n");
    VkQueryPoolCreateInfo qpi = { VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO };
    qpi.queryType = VK_QUERY_TYPE_TIMESTAMP; qpi.queryCount = 2;
    VkQueryPool queryPool = VK_NULL_HANDLE;
    res = vkCreateQueryPool(device, &qpi, NULL, &queryPool);
    if (res != VK_SUCCESS) { printf("  FAIL: vkCreateQueryPool=%d\n",res); free(spvCode); return 1; }
    printf("  OK\n");

    // [14] Fence
    printf("\n[14] Creating fence...\n");
    VkFenceCreateInfo fci = { VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
    VkFence fence = VK_NULL_HANDLE;
    vkCreateFence(device, &fci, NULL, &fence);
    printf("  OK\n");

    // [15] Dispatch
    printf("\n[15] Dispatching compute shader...\n");
    VkCommandBufferAllocateInfo cai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    cai.commandPool = cmdPool; cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY; cai.commandBufferCount = 1;
    VkCommandBuffer cb = VK_NULL_HANDLE;
    vkAllocateCommandBuffers(device, &cai, &cb);
    VkCommandBufferBeginInfo cbi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    cbi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(cb, &cbi);
    vkCmdResetQueryPool(cb, queryPool, 0, 2);
    vkCmdWriteTimestamp(cb, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, queryPool, 0);
    vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline);
    vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pll, 0, 1, &ds, 0, NULL);
    vkCmdDispatch(cb, (NE+255)/256, 1, 1);
    vkCmdWriteTimestamp(cb, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, queryPool, 1);
    vkEndCommandBuffer(cb);
    VkSubmitInfo si = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    si.commandBufferCount = 1; si.pCommandBuffers = &cb;
    vkResetFences(device, 1, &fence);
    res = vkQueueSubmit(queue, 1, &si, fence);
    if (res != VK_SUCCESS) { printf("  FAIL: vkQueueSubmit=%d\n",res); free(spvCode); return 1; }
    vkWaitForFences(device, 1, &fence, VK_TRUE, 1000000000ULL);
    printf("  OK: Compute dispatch completed\n");

    // [16] Timestamps
    printf("\n[16] Reading GPU timestamps...\n");
    uint64_t ts[2] = {0,0};
    res = vkGetQueryPoolResults(device, queryPool, 0, 2, sizeof(ts), ts, sizeof(uint64_t), VK_QUERY_RESULT_64_BIT|VK_QUERY_RESULT_WAIT_BIT);
    if (res == VK_SUCCESS) {
        float period = selP.limits.timestampPeriod;
        float gpuMs = (float)(ts[1]-ts[0]) * period / 1000000.0f;
        printf("  Start: %llu  End: %llu  Time: %.3f ms\n", (unsigned long long)ts[0], (unsigned long long)ts[1], gpuMs);
        printf("  => %s\n", ts[1]>ts[0] ? "GPU EXECUTION CONFIRMED" : "WARNING: timestamps identical");
    } else {
        printf("  FAIL: vkGetQueryPoolResults=%d\n", res);
    }

    // [17] Readback
    printf("\n[17] Reading back GPU results...\n");
    float* rd = NULL;
    vkMapMemory(device, memC, 0, BS, 0, (void**)&rd);
    int ok=0, bad=0; float me=0;
    for (uint32_t i=0; i<NE; i++) {
        float e = 1.0f+2.0f;
        float err = fabsf(rd[i]-e);
        if (err<0.001f) ok++; else { bad++; if(err>me) me=err; }
    }
    vkUnmapMemory(device, memC);
    printf("  %d/%u correct", ok, NE);
    if (bad) printf(", %d wrong (max err: %.6f)", bad, me);
    printf("\n  => %s\n", ok==NE ? "CORRECTNESS: PASS" : "CORRECTNESS: FAIL");

    // Summary
    printf("\n========================================\n  GPU EXECUTION VERIFIER SUMMARY\n========================================\n");
    printf("  Device: %s\n  VRAM: %llu MB\n  Compute: %s\n  Correctness: %s\n  GPU Execution: %s\n========================================\n",
        selP.deviceName, (unsigned long long)(memP.memoryHeaps[0].size/(1024*1024)),
        (ts[1]>ts[0])?"CONFIRMED":"UNVERIFIED", ok==NE?"PASS":"FAIL",
        (ts[1]>ts[0]&&ok==NE)?"VERIFIED":"NOT PROVEN");

    free(spvCode);
    if (fence) vkDestroyFence(device,fence,NULL);
    if (queryPool) vkDestroyQueryPool(device,queryPool,NULL);
    if (dp) vkDestroyDescriptorPool(device,dp,NULL);
    if (dsl) vkDestroyDescriptorSetLayout(device,dsl,NULL);
    if (pll) vkDestroyPipelineLayout(device,pll,NULL);
    if (pipeline) vkDestroyPipeline(device,pipeline,NULL);
    if (sm) vkDestroyShaderModule(device,sm,NULL);
    if (cb) vkFreeCommandBuffers(device,cmdPool,1,&cb);
    if (cmdPool) vkDestroyCommandPool(device,cmdPool,NULL);
    if (bufC) vkDestroyBuffer(device,bufC,NULL);
    if (memC) vkFreeMemory(device,memC,NULL);
    if (bufB) vkDestroyBuffer(device,bufB,NULL);
    if (memB) vkFreeMemory(device,memB,NULL);
    if (bufA) vkDestroyBuffer(device,bufA,NULL);
    if (memA) vkFreeMemory(device,memA,NULL);
    if (device) vkDestroyDevice(device,NULL);
    if (instance) vkDestroyInstance(instance,NULL);
    free(devices); free(qf);
    return (ok==NE && ts[1]>ts[0]) ? 0 : 1;
}
