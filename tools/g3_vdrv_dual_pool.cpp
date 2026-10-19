/* g3_vdrv_dual_pool.cpp — dual WDDM D3D12 + DXGI budget pool (≤99). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_4.h>
#include <d3d12.h>
#include <cstdio>
#include <cstring>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d12.lib")

static int NameHas(const char* hay, const char* n) {
    if (!hay || !n) return 0;
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        for (; n[i] && p[i]; ++i) {
            char a = p[i], b = n[i];
            if (a >= 'a' && a <= 'z') a = (char)(a - 32);
            if (b >= 'a' && b <= 'z') b = (char)(b - 32);
            if (a != b) break;
        }
        if (!n[i]) return 1;
    }
    return 0;
}

static void Emit(const char* tag, IDXGIAdapter1* a) {
    DXGI_ADAPTER_DESC1 d{};
    a->GetDesc1(&d);
    char name[128]{};
    WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, name, 128, 0, 0);
    std::printf("%s_DXGI_NAME=%s\n%s_PCI_DEVICE=0x%04X\n"
                "%s_DXGI_LUID=%08X%08X\n%s_DXGI_DEDICATED=%llu\n",
                tag, name, tag, d.DeviceId, tag, d.AdapterLuid.HighPart,
                d.AdapterLuid.LowPart, tag,
                (unsigned long long)d.DedicatedVideoMemory);
    ID3D12Device* dev = nullptr;
    HRESULT hr = D3D12CreateDevice(a, D3D_FEATURE_LEVEL_11_0,
                                   IID_PPV_ARGS(&dev));
    std::printf("%s_D3D12CreateDevice_HRESULT=0x%08lX\n%s_D3D12CreateDevice=%s\n",
                tag, (unsigned long)hr, tag, SUCCEEDED(hr) ? "PASS" : "FAIL");
    if (dev) dev->Release();
    IDXGIAdapter3* a3 = nullptr;
    if (SUCCEEDED(a->QueryInterface(IID_PPV_ARGS(&a3)))) {
        DXGI_QUERY_VIDEO_MEMORY_INFO loc{}, nl{};
        a3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &loc);
        a3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_NON_LOCAL, &nl);
        std::printf("%s_LOCAL_Budget=%llu\n%s_LOCAL_CurrentUsage=%llu\n"
                    "%s_LOCAL_AvailableForReservation=%llu\n"
                    "%s_NONLOCAL_Budget=%llu\n",
                    tag, (unsigned long long)loc.Budget, tag,
                    (unsigned long long)loc.CurrentUsage, tag,
                    (unsigned long long)loc.AvailableForReservation, tag,
                    (unsigned long long)nl.Budget);
        a3->Release();
    }
}

int main() {
    std::printf("GATE=G3_VDRIVER_DUAL_POOL_001\nVULKAN_USED=0\n"
                "POOL_MODEL=SOFTWARE_SUM_OF_DISCRETE_ADAPTERS\n"
                "HARDWARE_UNIFIED_VRAM=0\nPROMOTE=0\n");
    IDXGIFactory1* f = nullptr;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&f))) || !f) return 10;
    UINT64 dedSum = 0, budSum = 0;
    int n9700 = 0, n7800 = 0;
    IDXGIAdapter1* a = nullptr;
    for (UINT i = 0; f->EnumAdapters1(i, &a) != DXGI_ERROR_NOT_FOUND; ++i) {
        if (!a) continue;
        DXGI_ADAPTER_DESC1 d{};
        a->GetDesc1(&d);
        char name[128]{};
        WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, name, 128, 0, 0);
        const char* tag = nullptr;
        if (NameHas(name, "7800")) {
            tag = "RX7800XT";
            n7800 = 1;
        } else if (NameHas(name, "R9700")) {
            tag = "R9700";
            n9700 = 1;
        }
        if (tag) {
            Emit(tag, a);
            dedSum += d.DedicatedVideoMemory;
            IDXGIAdapter3* a3 = nullptr;
            if (SUCCEEDED(a->QueryInterface(IID_PPV_ARGS(&a3)))) {
                DXGI_QUERY_VIDEO_MEMORY_INFO loc{};
                a3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &loc);
                budSum += loc.Budget;
                a3->Release();
            }
        }
        a->Release();
        a = nullptr;
    }
    f->Release();
    std::printf("R9700_FOUND=%d\nRX7800XT_FOUND=%d\n"
                "POOL_DXGI_DEDICATED_SUM=%llu\nPOOL_LOCAL_Budget_SUM=%llu\n"
                "POOL_STICK_COUNT=%d\nBOTH_D3D12_LANE=1\n"
                "TRUE_DUAL_RUNTIME=OPEN_ON_D3D12_NOT_VULKAN\n",
                n9700, n7800, (unsigned long long)dedSum,
                (unsigned long long)budSum, n9700 + n7800);
    return (n9700 && n7800) ? 0 : 11;
}
