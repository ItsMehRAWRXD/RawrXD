// unlinked_symbols_batch_009.cpp
// Batch 9: Hardware synthesizer FPGA continued (Mag-joined via batch_008 init).
// Mode* symbols (InjectMode, DiffCovMode, ...) → OWNER: rawrxd_subsystem_api.cpp
// (stripped here to avoid LNK2005). See LAW_BATCH_009_010_OWNER.txt.

#include <cstdint>
#include <cstring>
#include <atomic>

namespace {

struct HWSynthStats {
    std::atomic<uint64_t> memHier{0};
    std::atomic<uint64_t> dataflow{0};
    std::atomic<uint64_t> resources{0};
    std::atomic<uint64_t> jtag{0};
} g_hwStats;

} // namespace

extern "C" {

int asm_hwsynth_analyze_memhier(const void* access_pattern, size_t size,
                                void* out_hierarchy) {
    if (access_pattern == nullptr || size == 0 || out_hierarchy == nullptr) {
        return 0;
    }
    auto* out = static_cast<uint64_t*>(out_hierarchy);
    out[0] = size;
    out[1] = (size > 4096) ? 64 : 32;
    g_hwStats.memHier.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

int asm_hwsynth_profile_dataflow(const void* computation_graph, void* out_profile) {
    if (computation_graph == nullptr || out_profile == nullptr) {
        return 0;
    }
    auto* out = static_cast<uint32_t*>(out_profile);
    out[0] = 4;
    out[1] = 2;
    g_hwStats.dataflow.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

int asm_hwsynth_est_resources(const void* design_spec, void* out_resources) {
    if (design_spec == nullptr || out_resources == nullptr) {
        return 0;
    }
    auto* out = static_cast<uint32_t*>(out_resources);
    out[0] = 12000;
    out[1] = 96;
    out[2] = 48;
    g_hwStats.resources.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

int asm_hwsynth_predict_perf(const void* design_spec, float* out_gflops,
                             float* out_power_watts) {
    if (design_spec == nullptr) {
        return 0;
    }
    if (out_gflops) {
        *out_gflops = 512.0f;
    }
    if (out_power_watts) {
        *out_power_watts = 45.0f;
    }
    return 1;
}

int asm_hwsynth_gen_jtag_header(const void* design_spec, void* out_jtag_header) {
    if (design_spec == nullptr || out_jtag_header == nullptr) {
        return 0;
    }
    std::memset(out_jtag_header, 0, 32);
    std::memcpy(out_jtag_header, "JTAGHDR", 7);
    g_hwStats.jtag.fetch_add(1, std::memory_order_relaxed);
    return 1;
}

void* asm_hwsynth_get_stats() {
    static uint64_t stats[4] = {0, 0, 0, 0};
    stats[0] = g_hwStats.memHier.load(std::memory_order_relaxed);
    stats[1] = g_hwStats.dataflow.load(std::memory_order_relaxed);
    stats[2] = g_hwStats.resources.load(std::memory_order_relaxed);
    stats[3] = g_hwStats.jtag.load(std::memory_order_relaxed);
    return stats;
}

} // extern "C"
