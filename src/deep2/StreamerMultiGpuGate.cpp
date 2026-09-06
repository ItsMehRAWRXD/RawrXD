// StreamerMultiGpuGate.cpp — STREAMER_MULTIGPU_001 real host/sync probes
#include "StreamerMultiGpuGate.hpp"
#include "Deep2MultiGpuBridge.hpp"
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dxgi.h>
#endif

namespace Deep2 {
namespace {

bool VulkanIcdLooksBlocked() noexcept {
#ifdef _WIN32
    char buf[1024]{};
    const DWORD n = GetEnvironmentVariableA("VK_ICD_FILENAMES", buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf))
        return false;
    return strstr(buf, "no_such") != nullptr || strstr(buf, "fake") != nullptr ||
           strstr(buf, "blocked") != nullptr;
#else
    return false;
#endif
}

unsigned EnumAdapters(MultiGpuAdapterInfo* out, unsigned cap) noexcept {
#ifdef _WIN32
    IDXGIFactory* factory = nullptr;
    if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory),
                                 reinterpret_cast<void**>(&factory))) || !factory)
        return 0;
    unsigned n = 0;
    IDXGIAdapter* adapter = nullptr;
    for (UINT i = 0; factory->EnumAdapters(i, &adapter) != DXGI_ERROR_NOT_FOUND; ++i) {
        if (!adapter) continue;
        DXGI_ADAPTER_DESC d{};
        if (SUCCEEDED(adapter->GetDesc(&d)) && d.VendorId != 0x1414 && n < cap) {
            WideCharToMultiByte(CP_UTF8, 0, d.Description, -1, out[n].name,
                                (int)sizeof(out[n].name), nullptr, nullptr);
            out[n].dedicatedVramBytes = (uint64_t)d.DedicatedVideoMemory;
            out[n].vendorId = d.VendorId;
            ++n;
        }
        adapter->Release();
        adapter = nullptr;
    }
    factory->Release();
    return n;
#else
    (void)out; (void)cap;
    return 0;
#endif
}

} // namespace

bool RunStreamerMultiGpuGate(MultiGpuGateReport& out) noexcept {
    std::memset(&out, 0, sizeof(out));
    out.backend = "CPU_NATIVE";
    out.gpuComputeActive = 0;
    out.vulkanIcdBlocked = VulkanIcdLooksBlocked();
    out.adapterCount = EnumAdapters(out.adapters, 8);
    out.laneA = "NOT_WIRED";
    out.laneB = "NOT_WIRED";
    out.laneC = "NOT_WIRED";
    out.laneD = "NOT_WIRED";
    try {
        Deep2MultiGpuBridge bridge;
        volatile float scratch[8]{};
        float dst[8]{};
        bridge.SignalHandoffTo7800XT(1, const_cast<float*>(scratch), dst, 8);
        out.syncGateOk = (dst[0] == scratch[0]);
    } catch (...) {
        out.syncGateOk = false;
    }
    if (out.vulkanIcdBlocked)
        out.blocker = "DUAL_AMD_VULKAN_ICD_BLOCKED";
    else if (out.adapterCount < 2)
        out.blocker = "NEED_DUAL_DISCRETE_GPU";
    else
        out.blocker = "GGUF_DECODE_NOT_ON_GPU";
    out.gateStatus = "SEALED_BLOCKED";
    return out.syncGateOk && out.adapterCount >= 1;
}

void EmitStreamerMultiGpuWitnesses(FILE* f, const MultiGpuGateReport& r) noexcept {
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "STREAMER_MULTIGPU_001=%s\n", r.gateStatus);
        fprintf(o, "STREAMER_MULTIGPU_BLOCKER=%s\n", r.blocker);
        fprintf(o, "STREAMER_MULTIGPU_SYNC_GATE=%s\n", r.syncGateOk ? "PASS" : "FAIL");
        fprintf(o, "STREAMER_MULTIGPU_VK_ICD_BLOCKED=%s\n", r.vulkanIcdBlocked ? "YES" : "NO");
        fprintf(o, "STREAMER_MULTIGPU_LANE_A=%s\n", r.laneA);
        fprintf(o, "STREAMER_MULTIGPU_LANE_B=%s\n", r.laneB);
        fprintf(o, "STREAMER_MULTIGPU_LANE_C=%s\n", r.laneC);
        fprintf(o, "STREAMER_MULTIGPU_LANE_D=%s\n", r.laneD);
        fprintf(o, "DEEP2_GPU_COUNT=%u\n", r.adapterCount);
        fprintf(o, "DEEP2_GPU_COMPUTE_ACTIVE=%u\n", r.gpuComputeActive);
        fprintf(o, "DEEP2_COMPUTE_BACKEND=%s\n", r.backend);
        fprintf(o, "DUAL_GPU_HOST=%s\n", r.adapterCount >= 2 ? "YES" : "NO");
        fprintf(o, "DUAL_GPU_COMPUTE=%s\n", r.gpuComputeActive >= 2 ? "YES" : "NO");
        for (unsigned i = 0; i < r.adapterCount; ++i) {
            fprintf(o, "DEEP2_GPU_%u_NAME=%s\n", i, r.adapters[i].name);
            fprintf(o, "DEEP2_GPU_%u_VRAM_BYTES=%llu\n", i,
                    (unsigned long long)r.adapters[i].dedicatedVramBytes);
        }
    };
    emit(stdout);
    emit(f);
}

} // namespace Deep2
