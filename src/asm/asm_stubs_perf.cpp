// asm_stubs_perf.cpp - Stub implementations for perf_telemetry.asm exports
// Provides C++ fallbacks when MASM kernels are not available

#include <cstdint>
#include <cstring>
#include <chrono>

extern "C" {

static thread_local uint64_t g_perfSlots[16] = {0};

int asm_perf_init() {
    return 0;
}

uint64_t asm_perf_begin(uint32_t slot) {
    if (slot < 16) {
        g_perfSlots[slot] = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
        );
        return g_perfSlots[slot];
    }
    return 0;
}

uint64_t asm_perf_end(uint32_t slot, uint64_t startTsc) {
    (void)startTsc;
    if (slot < 16) {
        uint64_t end = static_cast<uint64_t>(
            std::chrono::high_resolution_clock::now().time_since_epoch().count()
        );
        return end - g_perfSlots[slot];
    }
    return 0;
}

uint64_t asm_perf_read_slot(uint32_t slot) {
    if (slot < 16) {
        return g_perfSlots[slot];
    }
    return 0;
}

void asm_perf_reset_slot(uint32_t slot) {
    if (slot < 16) {
        g_perfSlots[slot] = 0;
    }
}

} // extern "C"
