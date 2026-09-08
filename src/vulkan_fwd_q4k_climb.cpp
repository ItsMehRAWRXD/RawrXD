// vulkan_fwd_q4k_climb.cpp — first QKV shared-x rows climb inside generation
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
uint64_t ClimbNowUs() {
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
} // namespace

bool VulkanCompute::ClimbQkvSharedXOnce(VkBuffer wbuf, size_t bytes,
                                        size_t inB, size_t outB, uint32_t rows,
                                        uint32_t cols, uint8_t tag,
                                        float* output, uint64_t uploadUs,
                                        VkPipeline& pipeOut,
                                        uint32_t& sxRowsOut,
                                        uint64_t& kernelUsOut) {
    if (rawr::live::QkvWinnerRows().load() >= 0) return false;
    static const uint32_t cands[] = {64u, 32u, 128u, 256u}; /* 64 first = parity ref */
    std::vector<float> ref64(rows), trial(rows), bestOut(rows);
    uint64_t bestUs = UINT64_MAX;
    uint32_t bestRows = 0;
    bool haveRef64 = false;
    VkPipeline bestPipe = nullptr;
    for (uint32_t rpw : cands) {
        VkPipeline p = nullptr;
        if (!EnsureQ4kQkvSxPipeline(rpw, p)) continue;
        const uint32_t g = (rows + rpw - 1u) / rpw;
        const uint64_t t0 = ClimbNowUs();
        if (!BindGemvStorage(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_,
                             outB, p, rows, cols, g))
            continue;
        const uint64_t ku = ClimbNowUs() - t0;
        void* m = nullptr;
        vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &m);
        std::memcpy(trial.data(), m, (size_t)rows * 4u);
        vkUnmapMemory(device_, gemv_out_mem_);
        bool parity = true;
        if (rpw == 64u) {
            ref64 = trial;
            haveRef64 = true;
            parity = true;
        } else if (haveRef64) {
            for (uint32_t i = 0; i < rows; ++i) {
                const float d = trial[i] - ref64[i];
                if (d > 1e-2f || d < -1e-2f) {
                    parity = false;
                    break;
                }
            }
        } else {
            parity = false; /* wait for 64 ref */
        }
        std::printf("QKV_CLIMB_CAND ROWS=%u LEGAL=1 PARITY=%u "
                    "GPU_TIME_US=%llu KEEP_GOING=1\n",
                    rpw, parity ? 1u : 0u, (unsigned long long)ku);
        if (parity && ku < bestUs) {
            bestUs = ku;
            bestRows = rpw;
            bestOut = trial;
            bestPipe = p;
        }
    }
    if (!bestRows) return false;
    rawr::live::NoteQkvLiveTune(bestRows, true, bestUs);
    std::memcpy(output, bestOut.data(), (size_t)rows * 4u);
    pipeOut = bestPipe;
    sxRowsOut = bestRows;
    kernelUsOut = bestUs;
    Deep2::Qkv_NoteDispatch(tag, uploadUs, 0, bestUs, (size_t)rows * 4u);
    Deep2::Qkv_NoteSharedX(tag, rows, cols, (rows + bestRows - 1u) / bestRows,
                           bestUs);
    ++q4k_fused_ops_;
    ++q4k_oproj_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
