// vulkan_fwd_q4k_fused.cpp — EnsureQ4kFusedPipeline + DispatchGEMVFusedQ4KT
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include <cstring>
#include <cstdlib>

namespace CPUInference {

void VulkanCompute::GemvReuseInputNext() {
    gemv_reuse_in_next_ = true;
}

uint64_t VulkanCompute::GemvInputReuseHits() const { return gemv_in_reuse_hits_; }

bool VulkanCompute::EnsureQ4kFusedPipeline() {
    return CreateGemvPipe("gemv_q4k_fused.spv", q4k_fused_pipe_);
}

bool VulkanCompute::DispatchGEMVFusedQ4KT(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols,
                                          uint64_t pinKey) {
    if (!EnsureQ4kFusedPipeline() || !packed || !input || !output || !bytes)
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
    if (!BindGemvStorage(wbuf, bytes, gemv_in_buf_, inB, gemv_out_buf_, outB,
                         q4k_fused_pipe_, rows, cols, (rows + 63u) / 64u))
        return false;
    void* mapped = nullptr;
    vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &mapped);
    std::memcpy(output, mapped, outB);
    vkUnmapMemory(device_, gemv_out_mem_);
    ++q4k_fused_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
