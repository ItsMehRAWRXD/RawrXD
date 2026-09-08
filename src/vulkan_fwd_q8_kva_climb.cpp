// vulkan_fwd_q8_kva_climb.cpp — first KVA Q8 shared-x rows climb (16 vs 64)
#ifdef _WIN32
#include <windows.h>
#include <profileapi.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "K2MlaQkvTiming.hpp"
#include "lavapath/LiveInGenTune.hpp"
#include <climits>
#include <cstdio>
#include <cstring>
#include <vector>

namespace CPUInference {
namespace {
uint64_t KvaNowUs() {
#ifdef _WIN32
    static LARGE_INTEGER f{};
    if (!f.QuadPart) QueryPerformanceFrequency(&f);
    LARGE_INTEGER c;
    QueryPerformanceCounter(&c);
    return (uint64_t)((c.QuadPart * 1000000ull) / (uint64_t)f.QuadPart);
#else
    return 0;
#endif
}
void ReduceParts(const float* part, float* out, uint32_t rows,
                 uint32_t nCol) {
    for (uint32_t r = 0; r < rows; ++r) {
        float s = 0.f;
        for (uint32_t t = 0; t < nCol; ++t) s += part[r * nCol + t];
        out[r] = s;
    }
}
} // namespace

bool VulkanCompute::ClimbQ8KvaOnce(VkBuffer wbuf, size_t bytes, size_t inB,
                                   size_t outB, uint32_t rows, uint32_t cols,
                                   uint32_t nColTiles, uint32_t colTileBlocks,
                                   uint8_t tag, float* output,
                                   uint64_t uploadUs, uint32_t& rowTileOut,
                                   uint64_t& kernelUsOut) {
    if (rawr::live::KvaWinnerRows().load() >= 0) return false;
    static const uint32_t cands[] = {16u, 64u};
    std::vector<float> ref(rows), trial(rows), bestOut(rows);
    uint64_t bestUs = UINT64_MAX;
    uint32_t bestRows = 0;
    bool haveRef = false;
    uint32_t pc[4] = {rows, cols, nColTiles, colTileBlocks};
    for (uint32_t rpw : cands) {
        VkPipeline p = nullptr;
        if (!EnsureQ8KvaSxPipeline(rpw, p)) continue;
        const uint32_t g = ((rows + rpw - 1u) / rpw) * nColTiles;
        const uint64_t t0 = KvaNowUs();
        if (!BindGemvStoragePc(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_,
                               outB, p, pc, 4u, g))
            continue;
        const uint64_t ku = KvaNowUs() - t0;
        void* m = nullptr;
        vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &m);
        ReduceParts(static_cast<const float*>(m), trial.data(), rows, nColTiles);
        vkUnmapMemory(device_, gemv_out_mem_);
        bool parity = true;
        if (!haveRef) {
            ref = trial;
            haveRef = true;
        } else {
            for (uint32_t i = 0; i < rows; ++i) {
                const float d = trial[i] - ref[i];
                if (d > 1e-2f || d < -1e-2f) {
                    parity = false;
                    break;
                }
            }
        }
        std::printf("KVA_CLIMB_CAND ROWS=%u LEGAL=1 PARITY=%u "
                    "GPU_TIME_US=%llu KEEP_GOING=1\n",
                    rpw, parity ? 1u : 0u, (unsigned long long)ku);
        if (parity && ku < bestUs) {
            bestUs = ku;
            bestRows = rpw;
            bestOut = trial;
        }
    }
    if (!bestRows) return false;
    rawr::live::NoteKvaLiveTune(bestRows, true, bestUs);
    std::memcpy(output, bestOut.data(), (size_t)rows * 4u);
    rowTileOut = bestRows;
    kernelUsOut = bestUs;
    Deep2::Qkv_NoteDispatch(tag, uploadUs, 0, bestUs, (size_t)rows * 4u);
    Deep2::Qkv_NoteSharedX(tag, rows, cols,
                           ((rows + bestRows - 1u) / bestRows) * nColTiles,
                           bestUs);
    Deep2::Qkv_NoteKvaColSplit(nColTiles,
                               ((rows + bestRows - 1u) / bestRows) * nColTiles,
                               bestUs);
    ++q4k_fused_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
