// NUGemv.hpp — NU stream → GPU GEMV (decode then DispatchGEMV)
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace CPUInference { class VulkanCompute; }

namespace Deep2 {

struct NUGemvStats {
    uint64_t ops = 0;
    uint64_t fail = 0;
    uint64_t skip = 0;
    uint64_t nuBytes = 0;
    uint64_t unpackedElems = 0;
    uint32_t lastFormat = 0;
    uint32_t lastMagic = 0;
};

bool NU_ValidateStream(const uint8_t* nu, size_t n,
                       uint32_t* elemsOut, uint32_t* fmtOut);
// Consumes NU bytes: magic check → unpack → GPU FP32 GEMV.
bool NU_GemvGpu(CPUInference::VulkanCompute& vc,
                const uint8_t* nu, size_t nuBytes,
                const float* x, float* y,
                uint32_t rows, uint32_t cols,
                uint64_t cacheKey = 0);
// Host reference: same NU unpack + CPU dot (parity prep).
bool NU_GemvCpu(const uint8_t* nu, size_t nuBytes,
                const float* x, float* y,
                uint32_t rows, uint32_t cols);
// Dense F32 reference GEMV (ground truth for parity).
void NU_GemvF32Cpu(const float* W, const float* x, float* y,
                   uint32_t rows, uint32_t cols);

const NUGemvStats& NU_GemvStatsGet();
void NU_GemvStatsReset();
void NU_GemvStatsEmit(FILE* f);

} // namespace Deep2
