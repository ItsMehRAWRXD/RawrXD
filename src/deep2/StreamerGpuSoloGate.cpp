// StreamerGpuSoloGate.cpp — SOLO_001 uses generic DeviceManager (single open)
#include "StreamerGpuSoloGate.hpp"
#include "Deep2DeviceManager.hpp"
#include <cstring>

namespace Deep2 {

bool RunStreamerGpuSoloSelect(GpuSoloReport& out) noexcept {
    std::memset(&out, 0, sizeof(out));
    out.openIndex = -1;
    out.vkCreateSelected = -1;
    out.cpuFallbackUsed = 1;
    out.backend = "CPU_NATIVE";
    out.gateStatus = "SEALED_BLOCKED";
    out.blocker = "GGUF_DECODE_NOT_ON_GPU";
    out.selectedName = "";

    DeviceManagerSnapshot snap{};
    if (!Deep2Device_Enumerate(snap))
        return false;
    Deep2Device_ApplyPolicy(snap);

    out.adapterCount = snap.deviceCount;
    if (out.adapterCount > 8) out.adapterCount = 8;
    for (unsigned i = 0; i < out.adapterCount; ++i) {
        const DeviceIdentity& d = snap.devices[i];
        GpuSoloAdapter& a = out.adapters[i];
        std::snprintf(a.name, sizeof(a.name), "%s", d.name);
        a.dedicatedVramBytes = d.dedicatedVram;
        a.sharedVramBytes = d.sharedVram;
        a.vendorId = d.vendorId;
        a.role = d.integrated ? 0u : (d.score >= 100 ? 1u : 2u);
        a.duty = "DETECTED/UNUSED";
    }

    if (snap.plan.opened >= 1 && snap.plan.primaryIndex >= 0 &&
        snap.plan.primaryIndex < (int)out.adapterCount) {
        out.openIndex = snap.plan.primaryIndex;
        out.adapters[out.openIndex].duty = "COMPUTE_PRIMARY";
        out.selectedName = out.adapters[out.openIndex].name;
    } else {
        out.blocker = "NO_COMPUTE_PRIMARY";
    }
    return out.adapterCount > 0;
}

void EmitStreamerGpuSoloWitnesses(FILE* f, const GpuSoloReport& r) noexcept {
    DeviceManagerSnapshot snap{};
    Deep2Device_Enumerate(snap);
    Deep2Device_ApplyPolicy(snap);
    // Device inventory witnesses come from the plan — do not overwrite with
    // streamer gate backend (CPU_NATIVE while GGUF forward still blocked).
    if (r.openIndex >= 0 && snap.plan.primaryIndex < 0) {
        snap.plan.primaryIndex = r.openIndex;
        snap.plan.opened = 1;
        snap.plan.openCount = 1;
        snap.plan.openIndexes[0] = r.openIndex;
        std::snprintf(snap.plan.primaryName, sizeof(snap.plan.primaryName), "%s",
                      r.adapters[r.openIndex].name);
        snap.plan.mode = ExecMode::SingleGpu;
        snap.plan.backend = "GPU";
        snap.plan.reason = "solo_gate_primary";
        if (r.openIndex < (int)snap.deviceCount)
            snap.devices[r.openIndex].duty = DeviceDuty::ComputePrimary;
    }
    auto emit = [&](FILE* o) {
        if (!o) return;
        fprintf(o, "STREAMER_GPU_SOLO_001=%s\n", r.gateStatus);
        fprintf(o, "STREAMER_GPU_SOLO_BLOCKER=%s\n", r.blocker);
        fprintf(o, "DEEP2_GPU_COMPUTE_ACTIVE=%u\n", r.gpuComputeActive);
        fprintf(o, "DEEP2_CPU_FALLBACK_USED=%u\n", r.cpuFallbackUsed);
        fprintf(o, "DEEP2_REAL_WEIGHT_LAYERS=%u\n", r.realWeightLayers);
        fprintf(o, "DEEP2_REAL_GPU_FORWARD=%u\n", r.realGpuForward);
        fprintf(o, "DEEP2_VK_PHYS_COUNT=%u\n", r.vkPhysCount);
        fprintf(o, "DEEP2_VK_CREATE_SELECTED=%d\n", r.vkCreateSelected);
        if (r.selectedName && *r.selectedName)
            fprintf(o, "DEEP2_GPU_SELECTED=%s\n", r.selectedName);
    };
    emit(stdout);
    emit(f);
    Deep2Device_EmitWitnesses(f, snap);
}

} // namespace Deep2
