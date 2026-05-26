#pragma once
#include <cstdint>
#include <intrin.h>

inline uint64_t PulseGetCycles() { 
    return __rdtsc(); 
}

struct PulseRing { 
    static PulseRing& instance() {
        static PulseRing ring;
        return ring;
    }

    void Log(uint32_t stage, uint32_t delta) {
        // Implementation for logging cycle deltas
    }

    bool isActive() const { return true; }
};

extern PulseRing g_pulseRing;
