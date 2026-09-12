/* smoke_d3d12_create.cpp — PHYSICAL_GPU_D3D12_DEVICE_CREATE_001 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_6.h>
#include <d3d12.h>
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d12.lib")

int main(void)
{
    IDXGIFactory1 *f = 0; IDXGIAdapter1 *a = 0; UINT i = 0;
    int hw = 0, att = 0, ok = 0, fail = 0, disc = 0, integ = 0, sw = 0;
    int r9700 = 0, rx78 = 0, igpu = 0;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void **)&f))) {
        printf("DXGI_FACTORY=FAIL\nPHYSICAL_GPU_D3D12_DEVICE_CREATE_001=FAIL\n");
        return 1;
    }
    printf("DXGI_FACTORY=PASS\n");
    for (; f->EnumAdapters1(i, &a) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 d = {}; D3D12_FEATURE_DATA_ARCHITECTURE1 arch = {};
        ID3D12Device *dev = 0; HRESULT hr;
        a->GetDesc1(&d);
        if (d.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) {
            sw++; printf("ADAPTER i=%u pci=%04X:%04X SOFTWARE=1 SKIP\n", i, d.VendorId, d.DeviceId);
            a->Release(); continue;
        }
        hw++; att++;
        hr = D3D12CreateDevice(a, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device), (void **)&dev);
        if (FAILED(hr) || !dev) {
            fail++; printf("ADAPTER i=%u pci=%04X:%04X CREATE=FAIL hr=0x%08lX\n",
                           i, d.VendorId, d.DeviceId, (unsigned long)hr);
            a->Release(); continue;
        }
        ok++;
        if (FAILED(dev->CheckFeatureSupport(D3D12_FEATURE_ARCHITECTURE1, &arch, sizeof arch))) {
            printf("ADAPTER i=%u pci=%04X:%04X CREATE=PASS ARCH=UNKNOWN VRAM=%llu\n",
                   i, d.VendorId, d.DeviceId, (unsigned long long)d.DedicatedVideoMemory);
            dev->Release(); a->Release(); continue;
        }
        if (arch.UMA) integ++; else disc++;
        if (d.DeviceId == 0x7551) r9700 = 1;
        if (d.DeviceId == 0x747E) rx78 = 1;
        if (d.DeviceId == 0x164E) igpu = 1;
        printf("ADAPTER i=%u pci=%04X:%04X CREATE=PASS UMA=%d CC_UMA=%d IMMU=%d VRAM=%llu CLASS=%s\n",
               i, d.VendorId, d.DeviceId, (int)arch.UMA, (int)arch.CacheCoherentUMA,
               (int)arch.IsolatedMMU, (unsigned long long)d.DedicatedVideoMemory,
               arch.UMA ? "INTEGRATED_GPU" : "DISCRETE_GPU");
        dev->Release(); a->Release();
    }
    f->Release();
    printf("HARDWARE_ADAPTERS=%d D3D12_DEVICE_CREATE_ATTEMPTS=%d PASS=%d FAIL=%d\n", hw, att, ok, fail);
    printf("DISCRETE_ADAPTERS=%d DISCRETE_DEVICE_CREATE_PASS=%d INTEGRATED_ADAPTERS=%d SOFTWARE_EXCLUDED=%d\n",
           disc, disc, integ, sw);
    printf("R9700_DEVICE_CREATE=%s RX7800XT_DEVICE_CREATE=%s RAPHAEL_IGPU_DEVICE_CREATE=%s\n",
           r9700 ? "PASS" : "ABSENT", rx78 ? "PASS" : "ABSENT", igpu ? "PASS" : "ABSENT");
    printf("GPU_ALLOCATION=NOT_RUN GPU_UPLOAD=NOT_RUN GPU_DATA_PARITY=NOT_RUN\n");
    printf("RAM_TO_GPU_PROMOTION_001=OPEN\n");
    if (ok < 1 || disc < 1 || fail != 0) {
        printf("PHYSICAL_GPU_D3D12_DEVICE_CREATE_001=FAIL\nPROMOTE=0\n");
        return 1;
    }
    printf("PHYSICAL_GPU_D3D12_DEVICE_CREATE_001=PASS\nPROMOTE=0\n");
    return 0;
}
