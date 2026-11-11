// GpuPreflight.cpp — Windows PnP GPU health admission gate
#include "GpuPreflight.hpp"

#include <vector>
#include <string>
#include <cstdio>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

// {4D36E968-E325-11CE-BFC1-08002BE10318} — GUID_CLASS_DISPLAY
static const GUID kDisplayClassGuid = {0x4d36e968, 0xe325, 0x11ce,
                                       {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}};

// CM_DRP_DEVICE_INSTANCE_ID may be excluded under WIN32_LEAN_AND_MEAN.
#ifndef CM_DRP_DEVICE_INSTANCE_ID
#define CM_DRP_DEVICE_INSTANCE_ID 0x00000000
#endif

#ifndef CM_PROB_NONE
#define CM_PROB_NONE 0
#endif

#ifndef DN_STARTED
#define DN_STARTED 0x00000008
#endif

static std::wstring GetDeviceProperty(HDEVINFO hDevInfo, PSP_DEVINFO_DATA devData,
                                      DWORD prop) {
    WCHAR buf[MAX_PATH] = {};
    DWORD bufSize = sizeof(buf);
    if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, devData, prop, nullptr,
                                          (PBYTE)buf, bufSize, nullptr)) {
        return buf;
    }
    return L"";
}

std::vector<GpuHealth> EnumerateGpuHealth() {
    std::vector<GpuHealth> result;

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(&kDisplayClassGuid, nullptr, nullptr,
                                             DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) return result;

    DWORD index = 0;
    SP_DEVINFO_DATA devData{};
    devData.cbSize = sizeof(devData);

    while (SetupDiEnumDeviceInfo(hDevInfo, index++, &devData)) {
        GpuHealth gpu;

        // Try friendly name first, fall back to device description.
        gpu.friendlyName = GetDeviceProperty(hDevInfo, &devData, SPDRP_FRIENDLYNAME);
        if (gpu.friendlyName.empty()) {
            gpu.friendlyName = GetDeviceProperty(hDevInfo, &devData, SPDRP_DEVICEDESC);
        }

        // Instance ID (PCI device instance ID)
        WCHAR instanceId[MAX_PATH] = {};
        DWORD instanceIdSize = sizeof(instanceId);
        if (CM_Get_DevNode_Registry_PropertyW(devData.DevInst, CM_DRP_DEVICE_INSTANCE_ID,
                                              nullptr, (PBYTE)instanceId, &instanceIdSize, 0) ==
            CR_SUCCESS) {
            gpu.instanceId = instanceId;
        }

        // Device status (started + problem code). Code 31 = CM_PROB_FAILED_ADD.
        gpu.devInst = devData.DevInst;
        DWORD status = 0, problem = 0;
        if (CM_Get_DevNode_Status(&status, &problem, devData.DevInst, 0) == CR_SUCCESS) {
            gpu.status = status;
            gpu.problem = problem;
        }

        gpu.started = (status & DN_STARTED) != 0;
        gpu.problemFree = (problem == CM_PROB_NONE);
        gpu.healthy = gpu.started && gpu.problemFree;

        result.push_back(gpu);
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return result;
}

// Vulkan ICD readiness: check that vulkan-1.dll exports the entry point.
// Use FARPROC to avoid pulling in vulkan.h type definitions.
bool VulkanIcdReady() {
    HMODULE hVulkan = LoadLibraryW(L"vulkan-1.dll");
    if (!hVulkan) return false;

    FARPROC pfn = GetProcAddress(hVulkan, "vkEnumerateInstanceExtensionProperties");
    FreeLibrary(hVulkan);
    return pfn != nullptr;
}

static const std::wstring kGpu0Token = L"R9700";
static const std::wstring kGpu1Token = L"7800 XT";

bool GpuPreflightCheck(bool allowCpuOnly) {
    auto gpus = EnumerateGpuHealth();

    // Find the two configured GPUs by token in friendly name or description.
    const GpuHealth* gpu0 = nullptr;
    const GpuHealth* gpu1 = nullptr;
    for (const auto& g : gpus) {
        if (!gpu0 && (g.friendlyName.find(kGpu0Token) != std::wstring::npos)) gpu0 = &g;
        if (!gpu1 && (g.friendlyName.find(kGpu1Token) != std::wstring::npos)) gpu1 = &g;
    }

    bool attemptedReset = false;
    auto maybeReset = [&](const GpuHealth* g, const char* tag) {
        if (!g || g->healthy || !g->devInst) return;
        if (!GpuProblemCodeRecoverable(g->problem)) {
            std::fprintf(stderr,
                         "GPU_RESET_CANDIDATE=%s problem=%lu CODE31=%d SKIP=UNRECOVERABLE\n",
                         tag, g->problem, GpuIsCode31(g->problem) ? 1 : 0);
            std::fflush(stderr);
            return;
        }
        std::fprintf(stderr,
                     "GPU_RESET_CANDIDATE=%s problem=%lu CODE31=%d\n",
                     tag, g->problem, GpuIsCode31(g->problem) ? 1 : 0);
        std::fflush(stderr);
        (void)AttemptGpuDevNodeReset(g->devInst, g->problem);
        attemptedReset = true;
    };
    maybeReset(gpu0, "R9700");
    maybeReset(gpu1, "RX_7800_XT");
    if (attemptedReset) {
        gpus = EnumerateGpuHealth();
        gpu0 = gpu1 = nullptr;
        for (const auto& g : gpus) {
            if (!gpu0 && (g.friendlyName.find(kGpu0Token) != std::wstring::npos)) gpu0 = &g;
            if (!gpu1 && (g.friendlyName.find(kGpu1Token) != std::wstring::npos)) gpu1 = &g;
        }
    }
    bool gpu0Healthy = gpu0 && gpu0->healthy;
    bool gpu1Healthy = gpu1 && gpu1->healthy;

    std::fprintf(stderr, "RAWRXD_GPU_PREFLIGHT_BEGIN\n");
    if (gpu0) {
        std::fprintf(stderr,
                     "GPU_0=R9700\nGPU_0_WINDOWS_HEALTH=%s\n"
                     "GPU_0_PROBLEM_CODE=%lu\nGPU_0_CODE31=%d\n",
                     gpu0Healthy ? "PASS" : "FAIL", gpu0->problem,
                     GpuIsCode31(gpu0->problem) ? 1 : 0);
    } else {
        std::fprintf(stderr,
                     "GPU_0=R9700\nGPU_0_WINDOWS_HEALTH=FAIL\n"
                     "GPU_0_PROBLEM_CODE=0\nGPU_0_CODE31=0\n");
    }
    if (gpu1) {
        std::fprintf(stderr,
                     "GPU_1=RX_7800_XT\nGPU_1_WINDOWS_HEALTH=%s\n"
                     "GPU_1_PROBLEM_CODE=%lu\nGPU_1_CODE31=%d\n",
                     gpu1Healthy ? "PASS" : "FAIL", gpu1->problem,
                     GpuIsCode31(gpu1->problem) ? 1 : 0);
    } else {
        std::fprintf(stderr,
                     "GPU_1=RX_7800_XT\nGPU_1_WINDOWS_HEALTH=FAIL\n"
                     "GPU_1_PROBLEM_CODE=0\nGPU_1_CODE31=0\n");
    }

    bool allHealthy = gpu0Healthy && gpu1Healthy;
    std::fprintf(stderr, "GPU_PREFLIGHT=%s\n", allHealthy ? "PASS" : "FAIL");
    std::fflush(stderr);

    if (allowCpuOnly) {
        // CPU-only mode: report health but do not block.
        return true;
    }

    // GPU mode: require both GPUs healthy and Vulkan ready.
    bool vulkanReady = VulkanIcdReady();
    if (!allHealthy) {
        std::fprintf(stderr, "MODEL_LOAD=BLOCKED reason=GPU_HEALTH\n");
        std::fflush(stderr);
        return false;
    }
    if (!vulkanReady) {
        std::fprintf(stderr, "MODEL_LOAD=BLOCKED reason=VULKAN_ICD\n");
        std::fflush(stderr);
        return false;
    }
    std::fprintf(stderr, "MODEL_LOAD=ADMITTED\n");
    std::fflush(stderr);
    return true;
}
