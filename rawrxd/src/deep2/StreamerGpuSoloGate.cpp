// StreamerGpuSoloGate.cpp
// STREAMER-CERT-001 support: single-GPU admission gate for the streamer cert.
//
// Deliberately NOT a size gate. This file decides only whether a device is
// usable at all, and it reports that as a measurement of the device, not a
// prediction about a model. There is no branch here that rejects a model for
// being large; a model that does not fit is attempted and Deep2 decides.

#include "StreamerGpuSoloGate.h"

#include <cstdio>
#include <vector>

#include <windows.h>
#include <dxgi.h>

namespace rawrxd::streamer {

GpuSoloReport probeGpuSolo()
{
    GpuSoloReport r{};
    r.queried = true;

    IDXGIFactory1* factory = nullptr;
    const HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr) || !factory) {
        r.detail = "CreateDXGIFactory1 failed";
        r.usable = false;
        return r;
    }

    // Enumerate adapters. Report the count; DO NOT pick a "primary" here.
    // Picking one is the GPU_SOLO selection policy, which is a different gate
    // and is intentionally not folded into streamer admission.
    for (UINT i = 0;; ++i) {
        IDXGIAdapter1* ad = nullptr;
        if (factory->EnumAdapters1(i, &ad) == DXGI_ERROR_NOT_FOUND) break;
        if (!ad) continue;
        ++r.adapterCount;

        DXGI_ADAPTER_DESC1 d{};
        if (SUCCEEDED(ad->GetDesc1(&d))) {
            if (r.firstAdapter.empty()) {
                // DXGI_ADAPTER_DESC1::Description is WCHAR[128]; convert, do not
                // reinterpret_cast -- the adapter names are UTF-16.
                char utf8[256] = {0};
                const int n = WideCharToMultiByte(CP_UTF8, 0, d.Description, -1,
                                                   utf8, (int)sizeof utf8 - 1,
                                                   nullptr, nullptr);
                if (n > 0) r.firstAdapter = utf8;
                r.dedicatedMiB = static_cast<double>(d.DedicatedVideoMemory) /
                                 (1024.0 * 1024.0);
            }
        }
        ad->Release();
    }
    factory->Release();

    // The streamer runs on CPU, so no adapter is required. usable stays true
    // even with zero adapters; that is the honest reading of the device.
    r.usable = true;
    if (r.adapterCount == 0) r.detail = "no DXGI adapters; CPU route only";
    else                     r.detail = "adapters enumerated; CPU route unaffected";
    return r;
}

} // namespace rawrxd::streamer
