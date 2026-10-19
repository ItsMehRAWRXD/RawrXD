/* g3_wake_lease_d3d.cpp — DXGI/D3D12 wake 7800 (≤99). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_6.h>
#include <d3d12.h>
#include <cstdio>
#include <cstring>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d12.lib")

int NameHas(const char* hay, const char* n);

HRESULT Wake7800(ID3D12Device** outDev, ID3D12Resource** outBuf) {
    *outDev = nullptr;
    *outBuf = nullptr;
    IDXGIFactory1* fac = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&fac)))
        return E_FAIL;
    IDXGIAdapter1* ad = nullptr;
    IDXGIAdapter1* hit = nullptr;
    for (UINT i = 0; fac->EnumAdapters1(i, &ad) != DXGI_ERROR_NOT_FOUND; ++i) {
        DXGI_ADAPTER_DESC1 d{};
        ad->GetDesc1(&d);
        char name[128]{};
        WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, name, 128, 0, 0);
        if (NameHas(name, "7800")) {
            hit = ad;
            break;
        }
        ad->Release();
        ad = nullptr;
    }
    fac->Release();
    if (!hit) return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    ID3D12Device* dev = nullptr;
    HRESULT hr =
        D3D12CreateDevice(hit, D3D_FEATURE_LEVEL_11_0, __uuidof(ID3D12Device),
                          (void**)&dev);
    hit->Release();
    if (FAILED(hr)) return hr;
    D3D12_HEAP_PROPERTIES hp{};
    hp.Type = D3D12_HEAP_TYPE_DEFAULT;
    D3D12_RESOURCE_DESC rd{};
    rd.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
    rd.Width = 256ull * 1024ull * 1024ull;
    rd.Height = 1;
    rd.DepthOrArraySize = 1;
    rd.MipLevels = 1;
    rd.Format = DXGI_FORMAT_UNKNOWN;
    rd.SampleDesc.Count = 1;
    rd.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ID3D12Resource* buf = nullptr;
    hr = dev->CreateCommittedResource(&hp, D3D12_HEAP_FLAG_NONE, &rd,
                                      D3D12_RESOURCE_STATE_COMMON, nullptr,
                                      __uuidof(ID3D12Resource), (void**)&buf);
    if (FAILED(hr)) {
        dev->Release();
        return hr;
    }
    *outDev = dev;
    *outBuf = buf;
    return S_OK;
}
