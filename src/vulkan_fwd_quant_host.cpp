// vulkan_fwd_quant_host.cpp — host-IO packed quant GEMV (cert / logits)
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "QuantKernelRegistry.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>

namespace CPUInference {

bool VulkanCompute::DispatchGEMVQuant(int ggmlType, const void* packed, size_t bytes,
                                      const float* input, float* output,
                                      uint32_t rows, uint32_t cols,
                                      uint64_t pinKey) {
    /* FIRST_DIVERGE_001 / BATCH2_Q4K_GEMV_001:
     * Q4 attn (12): FORCE_VULKAN still wins (ATTN_PRE_O_0 SPV close).
     * Q4 FFN gate/up (rows>cols): host wins even under FORCE (FFN_ACT ULP).
     * Q6 (14): FORCE wins — host-Q6 override moves V_1[59] farther from FP16
     *   RNE boundary (ATTN_NORM_1 cascade owns the bucket; see ATTN_PRE_O_1). */
    const char* hostPar = std::getenv("RAWRXD_QUANT_HOST_Q8K_PARITY");
    const char* forceVk = std::getenv("RAWRXD_FORCE_VULKAN_QUANT_GEMV");
    const bool hostQ6 = hostPar && hostPar[0] == '1' && ggmlType == 14 &&
                        !(forceVk && forceVk[0] == '1');
    const bool hostQ4Attn = hostPar && hostPar[0] == '1' && ggmlType == 12 &&
                            !(forceVk && forceVk[0] == '1');
    const bool hostQ4Ffn = hostPar && hostPar[0] == '1' && ggmlType == 12 &&
                           rows > cols; /* gate/up; not down (rows<=cols) */
    const bool wantHost = hostQ6 || hostQ4Attn || hostQ4Ffn;
    if (wantHost && (ggmlType == 12 || ggmlType == 14) && packed && input &&
        output && bytes && rows && cols && (cols % 256u) == 0u) {
        auto gemv = Deep2::QuantKernelRegistry::Instance().GetGEMV(ggmlType);
        if (gemv) {
            ++gemv_attempts_;
            gemv(static_cast<const uint8_t*>(packed), input, output, rows, cols);
            std::fprintf(stderr,
                         "QUANT_GEMV_HOST_Q8K_PARITY type=%d rows=%u cols=%u "
                         "(FFN-Q4 rows>cols overrides FORCE; Q6 respects FORCE) "
                         "PROMOTE=0\n",
                         ggmlType, rows, cols);
            std::fflush(stderr);
            if (ggmlType == 12) ++q4k_packed_ops_;
            if (ggmlType == 14) ++q6k_packed_ops_;
            ++gemv_success_;
            return true;
        }
    }
    VkPipeline pipe = nullptr; uint64_t* ops = nullptr;
    if (!SelectPackedPipe(ggmlType, pipe, ops) || !input || !output || !bytes)
        return false;
    /* Pin-hit may omit host packed (HOST_BYTES_FOR_HIT=0). */
    if (!packed &&
        !(pinKey && WantWeightPin() &&
          HasPinnedGemvWeight(pinKey, bytes, rows, cols)))
        return false;
    ++gemv_attempts_;
    const size_t inB = (size_t)cols * 4, outB = (size_t)rows * 4;
    if (!EnsureHostIo(inB, outB)) return false;
    const bool reuseIn =
        gemv_reuse_in_next_ && gemv_in_live_cols_ == cols && gemv_in_buf_;
    gemv_reuse_in_next_ = false;
    if (reuseIn) {
        ++gemv_in_reuse_hits_;
    } else {
        void* mapped = nullptr;
        vkMapMemory(device_, gemv_in_mem_, 0, inB, 0, &mapped);
        std::memcpy(mapped, input, inB);
        vkUnmapMemory(device_, gemv_in_mem_);
        gemv_in_live_cols_ = cols;
    }
    VkBuffer wbuf = nullptr;
    if (WantWeightPin()) {
        if (!EnsurePinnedPackedWeight(packed, bytes, rows, cols, wbuf, pinKey))
            return false;
    } else {
        if (!packed) return false;
        if (!ww_active_ || bytes > ww_slot_bytes_) {
            size_t budget = ww_budget_bytes_ ? ww_budget_bytes_
                                            : ((size_t)512 << 20);
            const char* b = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
            if (b && *b) budget = (size_t)std::atoi(b) << 20;
            uint32_t nSlots = ww_slot_count_ ? ww_slot_count_ : 8;
            const char* ns = std::getenv("DEEP2_WEIGHT_SLOTS");
            if (ns && *ns && !ww_active_) nSlots = (uint32_t)std::atoi(ns);
            if (nSlots < 2) nSlots = 2;
            if (nSlots > 128) nSlots = 128;
            size_t slotB = bytes;
            if (ww_slot_bytes_ && ww_slot_bytes_ > slotB) slotB = ww_slot_bytes_;
            if (!EnsureWeightWindow(slotB, nSlots, budget)) return false;
        }
        if (!StreamWeightToSlot(packed, bytes, wbuf)) return false;
    }
    size_t range = (bytes + 3u) & ~size_t(3);
    if (!WantWeightPin() && ww_slot_bytes_ && range > ww_slot_bytes_)
        range = ww_slot_bytes_;
    if (!BindGemvStorage(wbuf, range, gemv_in_buf_, inB, gemv_out_buf_, outB,
                         pipe, rows, cols, (rows + 63u) / 64u))
        return false;
    void* mappedOut = nullptr;
    vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &mappedOut);
    std::memcpy(output, mappedOut, outB);
    vkUnmapMemory(device_, gemv_out_mem_);
    if (ops) ++(*ops);
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
