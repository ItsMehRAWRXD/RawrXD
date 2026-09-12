// vulkan_fwd_q6k_host.cpp — host-IO packed Q6_K GEMV (logits range; no ww thrash)
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "deep2/Deep2Locality64.hpp"
#include <cstring>
#include <cstdlib>

namespace CPUInference {

bool VulkanCompute::DispatchGEMVQ6kPacked(const void* packed, size_t bytes,
                                          const float* input, float* output,
                                          uint32_t rows, uint32_t cols) {
    if (!EnsureQ6kPipeline() || !packed || !input || !output || bytes == 0)
        return false;
    ++gemv_attempts_;
    const size_t inB = (size_t)cols * 4, outB = (size_t)rows * 4;
    if (!EnsureHostIo(inB, outB)) return false;
    void* mapped = nullptr;
    vkMapMemory(device_, gemv_in_mem_, 0, inB, 0, &mapped);
    std::memcpy(mapped, input, inB);
    vkUnmapMemory(device_, gemv_in_mem_);

    // Dedicated grow-only weight buffer — never StreamWeightToSlot / pin cache.
    const uintptr_t key = WeightContentFingerprint(packed, bytes);
    const bool hit = q6k_logits_w_buf_ && bytes <= q6k_logits_w_cap_ &&
                     q6k_logits_w_key_ == key;
    // Observe-only: do not change hit predicate / upload / hit counters.
    Deep2::Locality64_NoteDemand(Deep2::LocalityKind::Weight, bytes, hit);
    if (!hit) {
        if (bytes > q6k_logits_w_cap_) {
            if (q6k_logits_w_buf_) {
                vkDestroyBuffer(device_, q6k_logits_w_buf_, nullptr);
                q6k_logits_w_buf_ = nullptr;
            }
            if (q6k_logits_w_mem_) {
                vkFreeMemory(device_, q6k_logits_w_mem_, nullptr);
                q6k_logits_w_mem_ = nullptr;
            }
            q6k_logits_w_cap_ = 0;
            q6k_logits_w_key_ = 0;
            if (!CreateDeviceLocalBuffer(bytes, q6k_logits_w_buf_,
                                         q6k_logits_w_mem_))
                return false;
            q6k_logits_w_cap_ = bytes;
        }
        if (!UploadToDeviceLocal(packed, bytes, q6k_logits_w_buf_))
            return false;
        q6k_logits_w_key_ = key;
        ++gemv_weight_uploads_;
    } else {
        ++gemv_weight_hits_;
    }

    if (!BindGemvStorage(q6k_logits_w_buf_, bytes, gemv_in_buf_, inB,
                         gemv_out_buf_, outB, q6k_pipe_, rows, cols,
                         (rows + 63u) / 64u))
        return false;
    vkMapMemory(device_, gemv_out_mem_, 0, outB, 0, &mapped);
    std::memcpy(output, mapped, outB);
    vkUnmapMemory(device_, gemv_out_mem_);
    ++q6k_packed_ops_;
    ++gemv_success_;
    return true;
}

} // namespace CPUInference
#endif
