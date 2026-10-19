/* g3_amdvlk_direct_icd.cpp — LoadLibrary amdvlk; no vulkan-1 (≤99). */
#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include <vulkan/vk_icd.h>
#include <windows.h>
#include <cstdio>
#include <cstring>

PFN_vk_icdGetInstanceProcAddr g_icdGipa = nullptr;
int RunDirectIcdA0(HMODULE dll, const char* needle, const char* tag);

int main(int argc, char** argv) {
    const char* needle = (argc >= 2 && argv[1][0]) ? argv[1] : "7800";
    const char* path =
        "C:\\Windows\\System32\\DriverStore\\FileRepository\\"
        "amdvlk.inf_amd64_914ba89eaaafdf60\\amdvlk64.dll";
    if (argc >= 3 && argv[2] && argv[2][0]) path = argv[2];

    const char* tag = "RX7800XT";
    if (std::strstr(needle, "9700") || std::strstr(needle, "R9700") ||
        std::strstr(needle, "r9700"))
        tag = "R9700";

    std::printf("GATE=G3_GPU1_AMDVLK_DIRECT_ICD_001\nONLY=%s\n"
                "VULKAN_LOADER_USED=0\nBEHAVIOR_PATCH=0\nPROMOTE=0\n",
                needle);
    std::printf("AMDVLK_DLL_PATH=%s\n", path);

    HMODULE dll = LoadLibraryA(path);
    std::printf("AMDVLK_LoadLibrary=%s\n", dll ? "PASS" : "FAIL");
    if (!dll) {
        std::printf("GetLastError=%lu\n", GetLastError());
        return 10;
    }

    auto neg = (PFN_vk_icdNegotiateLoaderICDInterfaceVersion)GetProcAddress(
        dll, "vk_icdNegotiateLoaderICDInterfaceVersion");
    auto gipa = (PFN_vk_icdGetInstanceProcAddr)GetProcAddress(
        dll, "vk_icdGetInstanceProcAddr");
    if (!neg && gipa)
        neg = (PFN_vk_icdNegotiateLoaderICDInterfaceVersion)gipa(
            VK_NULL_HANDLE, "vk_icdNegotiateLoaderICDInterfaceVersion");
    std::printf("ICD_NEGOTIATE_PRESENT=%d\nICD_GET_PROC_PRESENT=%d\n",
                neg ? 1 : 0, gipa ? 1 : 0);
    if (!gipa) {
        FreeLibrary(dll);
        return 11;
    }
    g_icdGipa = gipa;

    uint32_t ver = CURRENT_LOADER_ICD_INTERFACE_VERSION;
    if (neg) {
        VkResult nr = neg(&ver);
        std::printf("ICD_INTERFACE_NEGOTIATE_RESULT=%d\n"
                    "ICD_INTERFACE_VERSION=%u\n",
                    (int)nr, ver);
        if (nr != VK_SUCCESS) {
            FreeLibrary(dll);
            return 12;
        }
    }

    const int rc = RunDirectIcdA0(dll, needle, tag);
    FreeLibrary(dll);
    return rc;
}
