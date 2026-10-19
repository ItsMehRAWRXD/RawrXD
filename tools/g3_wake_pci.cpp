/* g3_wake_pci.cpp — D3D12 wake by PCI device id (≤99). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi1_6.h>
#include <d3d12.h>
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "d3d12.lib")

HRESULT WakePci(UINT pciDev, ID3D12Device** outDev, ID3D12Resource** outBuf) {
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
        if (d.VendorId == 0x1002 && d.DeviceId == pciDev) {
            hit = ad;
            break;
        }
        ad->Release();
        ad = nullptr;
    }
    fac->Release();
    if (!hit) return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    ID3D12Device* dev = nullptr;
    HRESULT hr = D3D12CreateDevice(hit, D3D_FEATURE_LEVEL_11_0,
                                   __uuidof(ID3D12Device), (void**)&dev);
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
    rd.SampleDesc.Count = 1;
    rd.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;
    ID3D12Resource* res = nullptr;
    hr = dev->CreateCommittedResource(&hp, D3D12_HEAP_FLAG_NONE, &rd,
                                      D3D12_RESOURCE_STATE_COMMON, nullptr,
                                      __uuidof(ID3D12Resource), (void**)&res);
    if (FAILED(hr)) {
        dev->Release();
        return hr;
    }
    *outDev = dev;
    *outBuf = res;
    return S_OK;
}
