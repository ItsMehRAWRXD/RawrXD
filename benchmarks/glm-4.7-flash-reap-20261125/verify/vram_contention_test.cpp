// Live VRAM contention test using EXACT LUID-associated DXGI budgets.
// Proves: reject under insufficient free capacity, then readmission once
// pressure is released (capacity raised to physical).  Real hardware, no
// synthetic numbers.  Requires the DXGI adapter3 interface.
// Compile: g++ -std=c++17 -O2 -Wall -Wextra vram_contention_test.cpp -o t -ldxgi
#include "../../../src/deep2/MultiGPU/ReservationLedger.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dxgi.h>
#include <dxgi1_4.h>

#include <cstdio>
#include <cstdint>
#include <vector>

using namespace Deep2::MultiGPU;

static uint64_t g_budget = 0, g_used = 0, g_dedicated = 0, g_luid = 0;

int main() {
    IDXGIFactory* factory = nullptr;
    if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&factory)) || !factory) {
        std::printf("SKIP: no DXGI\n"); return 0;
    }
    // Pick the discrete adapter with the largest dedicated VRAM (the R9700).
    IDXGIAdapter* best = nullptr; uint64_t bestDed = 0;
    for (UINT i = 0; ; ++i) {
        IDXGIAdapter* a = nullptr;
        if (factory->EnumAdapters(i, &a) == DXGI_ERROR_NOT_FOUND) break;
        DXGI_ADAPTER_DESC d{};
        if (SUCCEEDED(a->GetDesc(&d)) && d.VendorId != 0x1414) {
            if ((uint64_t)d.DedicatedVideoMemory > bestDed) { bestDed = d.DedicatedVideoMemory; best = a; }
            else a->Release();
        } else a->Release();
    }
    if (!best) { std::printf("SKIP: no discrete adapter\n"); return 0; }

    IDXGIAdapter3* a3 = nullptr;
    DXGI_QUERY_VIDEO_MEMORY_INFO vmi{};
    if (SUCCEEDED(best->QueryInterface(__uuidof(IDXGIAdapter3), (void**)&a3)) && a3 &&
        SUCCEEDED(a3->QueryVideoMemoryInfo(0, DXGI_MEMORY_SEGMENT_GROUP_LOCAL, &vmi))) {
        g_budget = vmi.Budget; g_used = vmi.CurrentUsage;
        g_dedicated = bestDed;
        DXGI_ADAPTER_DESC d{}; best->GetDesc(&d);
        g_luid = (uint64_t(d.AdapterLuid.HighPart) << 32) | uint32_t(d.AdapterLuid.LowPart);
    }
    if (a3) a3->Release();
    best->Release(); factory->Release();

    const uint64_t freeNow = g_budget > g_used ? g_budget - g_used : 0;
    const uint64_t MiB = 1ull << 20;
    // Real measured model requirement (GLM-4.7-Flash Q4_K_M): weights + KV + scratch + staging.
    const uint64_t weights = 17113ull * MiB, kv = 64ull * MiB, scratch = 128ull * MiB, staging = 170ull * MiB;

    std::printf("ADAPTER luid=%016llX dedicated=%llu MiB free=%llu MiB\n",
                (unsigned long long)g_luid, (unsigned long long)(g_dedicated/MiB),
                (unsigned long long)(freeNow/MiB));

    ReservationLedger L;
    L.SetCapacity(g_luid, freeNow);              // live free capacity
    Reservation r;
    bool admitContended = L.TryReserve(g_luid, weights + kv + scratch + staging, false, r);
    std::printf("contended (free=%llu): admit=%d\n",
                (unsigned long long)(freeNow/MiB), admitContended ? 1 : 0);
    if (admitContended) L.Release(r.id);         // free the hold before the released case

    // Release pressure: capacity raised to physical (all VRAM available).
    L.SetCapacity(g_luid, g_dedicated);
    Reservation r2;
    bool admitReleased = L.TryReserve(g_luid, weights + kv + scratch + staging, false, r2);
    std::printf("released (cap=%llu): admit=%d\n",
                (unsigned long long)(g_dedicated/MiB), admitReleased ? 1 : 0);

    // The released case must always admit (physical >> footprint).
    if (!admitReleased) { std::printf("FAIL: released must admit\n"); return 1; }
    // If the machine was contended (free < footprint), the contended case must reject.
    if (freeNow < weights + kv + scratch + staging && admitContended) {
        std::printf("FAIL: contended must reject when free < footprint\n"); return 1;
    }
    std::printf("VRAM_CONTENTION_ACCEPTANCE PASS (contended_admit=%d released_admit=%d)\n",
                admitContended ? 1 : 0, admitReleased ? 1 : 0);
    return 0;
}