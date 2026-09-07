// NULiveConsumer.hpp — live-path NU byte consume (parity-gated)
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace CPUInference { class VulkanCompute; }

namespace Deep2 {

struct NULiveStats {
    uint64_t ops = 0;
    uint64_t bytes = 0;
    uint64_t rejectOff = 0;
    uint64_t rejectNoAuth = 0;
    uint64_t fail = 0;
};

bool NU_LiveWanted();
bool NU_LiveAuthorized();
bool NU_LiveActive(); // wanted && authorized
// Fail-closed unless active. Consumes NU stream via GPU GEMV path.
bool NU_LiveConsumeGemv(CPUInference::VulkanCompute& vc,
                        const uint8_t* nu, size_t nuBytes,
                        const float* x, float* y,
                        uint32_t rows, uint32_t cols,
                        uint64_t cacheKey = 0);

const NULiveStats& NU_LiveStatsGet();
void NU_LiveStatsReset();
void NU_LiveEmit(FILE* f);

} // namespace Deep2
