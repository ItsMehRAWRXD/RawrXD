// StreamerGpuSoloGate.cpp — DXGI classify + MASM pick (no Vulkan init)
#include "StreamerGpuSoloGate.hpp"
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dxgi.h>
#pragma comment(lib, "dxgi.lib")
#endif

namespace Deep2 {
namespace {

bool HasI(const char* s, const char* n) noexcept {
    if (!s || !n || !*n) return false;
    for (; *s; ++s) {
        const char* a = s;
        const char* b = n;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
            if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
            if (ca != cb) break;
            ++a; ++b;
        }
        if (!*b) return true;
    }
    return false;
}

unsigned NameFlags(const char* n, uint64_t dedicated) noexcept {
    unsigned f = 0;
    if (HasI(n, "R9700") || HasI(n, "AI PRO")) f |= 1u;
    if (HasI(n, "7800")) f |= 2u;
    if (f == 0 && dedicated < (1ull << 30) &&
        (HasI(n, "Graphics") || HasI(n, "iGPU")))
        f |= 4u;
    return f;
}

} // namespace

bool RunStreamerGpuSoloSelect(GpuSoloReport& out) noexcept {
    std::memset(&out, 0, sizeof(out));
    out.openIndex = -1;
    out.vkCreateSelected = -1;
    out.cpuFallbackUsed = 1;
    out.backend = "CPU_NATIVE";
    out.gateStatus = "SEALED_BLOCKED";
    out.blocker = "GGUF_DECODE_NOT_ON_GPU";
    out.selectedName = "";
#ifdef _WIN32
    IDXGIFactory* factory = nullptr;
    if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory),
                                 reinterpret_cast<void**>(&factory))) || !factory)
        return false;
    IDXGIAdapter* adapter = nullptr;
    unsigned roles[8]{};
    unsigned long long vram[8]{};
    for (UINT i = 0; factory->EnumAdapters(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        if (!adapter) continue;
        DXGI_ADAPTER_DESC d{};
        if (SUCCEEDED(adapter->GetDesc(&d)) && d.VendorId != 0x1414 &&
            out.adapterCount < 8) {
            GpuSoloAdapter& a = out.adapters[out.adapterCount];
            WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, a.name,
                                (int)sizeof(a.name), nullptr, nullptr);
            a.dedicatedVramBytes = (uint64_t)d.DedicatedVideoMemory;
            a.sharedVramBytes = (uint64_t)d.SharedSystemMemory;
            a.vendorId = d.VendorId;
            a.role = GpuSolo_ScoreAdapter(a.dedicatedVramBytes, a.sharedVramBytes,
                                          NameFlags(a.name, a.dedicatedVramBytes));
            a.duty = "DETECTED/UNUSED";
            roles[out.adapterCount] = a.role;
            vram[out.adapterCount] = a.dedicatedVramBytes;
            ++out.adapterCount;
        }
        adapter->Release();
        adapter = nullptr;
    }
    factory->Release();
    out.openIndex = GpuSolo_PickOpenIndex(roles, vram, out.adapterCount, 1u);
    if (out.openIndex >= 0) {
        out.adapters[out.openIndex].duty = "SELECTED/IDLE";
        out.selectedName = out.adapters[out.openIndex].name;
    } else {
        out.blocker = "R9700_NOT_FOUND";
    }
    return out.adapterCount > 0;
#else
    return false;
#endif
}

void EmitStreamerGpuSoloWitnesses(FILE* f, const GpuSoloReport& r) noexcept {
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "STREAMER_GPU_SOLO_001=%s\n", r.gateStatus);
        fprintf(o, "STREAMER_GPU_SOLO_BLOCKER=%s\n", r.blocker);
        fprintf(o, "DEEP2_COMPUTE_BACKEND=%s\n", r.backend);
        fprintf(o, "DEEP2_GPU_SELECTED=%s\n",
                r.openIndex >= 0 ? "R9700" : "NONE");
        fprintf(o, "DEEP2_GPU_COMPUTE_ACTIVE=%u\n", r.gpuComputeActive);
        fprintf(o, "DEEP2_CPU_FALLBACK_USED=%u\n", r.cpuFallbackUsed);
        fprintf(o, "DEEP2_REAL_WEIGHT_LAYERS=%u\n", r.realWeightLayers);
        fprintf(o, "DEEP2_REAL_GPU_FORWARD=%u\n", r.realGpuForward);
        fprintf(o, "DEEP2_GPU_COUNT=%u\n", r.adapterCount);
        fprintf(o, "DEEP2_VK_PHYS_COUNT=%u\n", r.vkPhysCount);
        fprintf(o, "DEEP2_VK_CREATE_SELECTED=%d\n", r.vkCreateSelected);
        fprintf(o, "SYSTEM_RAM=64GB\n");
        for (unsigned i = 0; i < r.adapterCount; ++i) {
            fprintf(o, "DEEP2_GPU_%u_NAME=%s\n", i, r.adapters[i].name);
            fprintf(o, "DEEP2_GPU_%u_ROLE=%u\n", i, r.adapters[i].role);
            fprintf(o, "DEEP2_GPU_%u_DUTY=%s\n", i, r.adapters[i].duty);
            fprintf(o, "DEEP2_GPU_%u_VRAM_BYTES=%llu\n", i,
                    (unsigned long long)r.adapters[i].dedicatedVramBytes);
        }
    };
    emit(stdout);
    emit(f);
}

} // namespace Deep2
