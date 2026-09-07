// NUGemv.cpp — NU packed weights → GEMV (GPU via Vulkan FP32 path)
#include "NUGemv.hpp"
#include "NUFusedPacker.hpp"
#include "vulkan_compute.h"
#include <vector>

namespace Deep2 {
namespace {
NUGemvStats g_st;
}

void NU_GemvStatsReset() { g_st = {}; }
const NUGemvStats& NU_GemvStatsGet() { return g_st; }

void NU_GemvStatsEmit(FILE* f) {
    if (!f) return;
    fprintf(f,
            "NU_GEMV_OPS=%llu FAIL=%llu SKIP=%llu NU_BYTES=%llu UNPACKED=%llu "
            "FMT=%u MAGIC=0x%08X\n",
            (unsigned long long)g_st.ops, (unsigned long long)g_st.fail,
            (unsigned long long)g_st.skip, (unsigned long long)g_st.nuBytes,
            (unsigned long long)g_st.unpackedElems, g_st.lastFormat,
            g_st.lastMagic);
}

bool NU_ValidateStream(const uint8_t* nu, size_t n,
                       uint32_t* elemsOut, uint32_t* fmtOut) {
    if (!nu || n < sizeof(NUStreamHeader)) return false;
    const auto* h = reinterpret_cast<const NUStreamHeader*>(nu);
    if (h->magic != 0x46554E00u) return false;
    if (elemsOut) *elemsOut = h->totalElements;
    if (fmtOut) *fmtOut = h->formatTable[0];
    return true;
}

static bool UnpackNu(const uint8_t* nu, size_t nuBytes,
                     std::vector<float>& W, uint32_t rows, uint32_t cols) {
    uint32_t elems = 0, fmt = 0;
    if (!NU_ValidateStream(nu, nuBytes, &elems, &fmt)) return false;
    const size_t need = (size_t)rows * (size_t)cols;
    if (elems < need || need == 0) return false;
    W.assign(need, 0.f);
    NUFusedPacker p;
    NUPackerConfig cfg;
    if (!p.initialize(cfg)) return false;
    const size_t got = p.unpackTensor(nu, nuBytes, W.data(), need);
    g_st.lastMagic = 0x46554E00u;
    g_st.lastFormat = fmt;
    g_st.nuBytes = nuBytes;
    g_st.unpackedElems = got;
    return got == need;
}

bool NU_GemvCpu(const uint8_t* nu, size_t nuBytes,
                const float* x, float* y,
                uint32_t rows, uint32_t cols) {
    if (!nu || !x || !y || !rows || !cols) { ++g_st.skip; return false; }
    std::vector<float> W;
    if (!UnpackNu(nu, nuBytes, W, rows, cols)) { ++g_st.fail; return false; }
    NU_GemvF32Cpu(W.data(), x, y, rows, cols);
    ++g_st.ops;
    return true;
}

void NU_GemvF32Cpu(const float* W, const float* x, float* y,
                   uint32_t rows, uint32_t cols) {
    for (uint32_t r = 0; r < rows; ++r) {
        double s = 0;
        const float* row = W + (size_t)r * cols;
        for (uint32_t c = 0; c < cols; ++c)
            s += (double)row[c] * (double)x[c];
        y[r] = (float)s;
    }
}

bool NU_GemvGpu(CPUInference::VulkanCompute& vc,
                const uint8_t* nu, size_t nuBytes,
                const float* x, float* y,
                uint32_t rows, uint32_t cols,
                uint64_t cacheKey) {
    if (!nu || !x || !y || !rows || !cols) { ++g_st.skip; return false; }
    std::vector<float> W;
    if (!UnpackNu(nu, nuBytes, W, rows, cols)) { ++g_st.fail; return false; }
    if (!vc.DispatchGEMV(W.data(), x, y, rows, cols, cacheKey)) {
        ++g_st.fail;
        return false;
    }
    ++g_st.ops;
    return true;
}

} // namespace Deep2
