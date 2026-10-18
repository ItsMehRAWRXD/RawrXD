#pragma once
#include <cstdint>

namespace Deep2 {

struct B52MemoryShape {
    uint32_t rows = 0;
    uint32_t cols = 0;
    uint32_t quantBits = 4;
    uint32_t blockSize = 32;
    uint32_t waveWidth = 64;
};

struct B52MemoryPlan {
    uint32_t vectorBytes = 16;
    uint32_t burstBytes = 128;
    uint32_t rowsPerGroup = 4;
    uint32_t xBroadcastTile = 512;
    uint32_t prefetchDistance = 8;
    bool coalescedPackedLoads = true;
    bool xBroadcastLds = true;
    bool scaleCacheRegisters = true;
    bool noRedundantXReads = true;
};

class B52MemoryTail {
public:
    static B52MemoryPlan make(const B52MemoryShape&) noexcept;
    static double payloadEfficiency(const B52MemoryShape&,
                                    uint64_t actualBytesRead) noexcept;
};

}
