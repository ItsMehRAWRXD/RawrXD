#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_6.h>
#include <cstdio>
#pragma comment(lib, "dxgi.lib")
int wmain() {
  IDXGIFactory1* f = nullptr;
  if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&f)) || !f)
    return 1;
  IDXGIAdapter1* a = nullptr;
  for (UINT i = 0; f->EnumAdapters1(i, &a) != DXGI_ERROR_NOT_FOUND; ++i, a=nullptr) {
    if (!a) continue;
    DXGI_ADAPTER_DESC1 d{};
    a->GetDesc1(&d);
    char name[128]{};
    WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, name, 128, 0, 0);
    if (strstr(name, "R9700") || strstr(name, "7800")) {
      const char* tag = strstr(name, "7800") ? "RX7800XT" : "R9700";
      printf("%s_DXGI_NAME=%s\n%s_DXGI_VENDOR=0x%04X\n%s_DXGI_DEVICE=0x%04X\n"
                  "%s_DXGI_LUID=%08X%08X\n"
                  "%s_DXGI_DedicatedVideoMemory=%llu\n"
                  "%s_DXGI_DedicatedSystemMemory=%llu\n"
                  "%s_DXGI_SharedSystemMemory=%llu\n"
                  "%s_DXGI_FLAGS=0x%X\n",
                  tag, name, tag, d.VendorId, tag, d.DeviceId, tag,
                  d.AdapterLuid.HighPart, d.AdapterLuid.LowPart, tag,
                  (unsigned long long)d.DedicatedVideoMemory, tag,
                  (unsigned long long)d.DedicatedSystemMemory, tag,
                  (unsigned long long)d.SharedSystemMemory, tag, d.Flags);
    }
    a->Release();
  }
  f->Release();
  return 0;
}

