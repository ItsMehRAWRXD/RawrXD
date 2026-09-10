// vulkan_fwd_attn_mla.cpp — PATH_B DispatchAttnDecodeMLA + caches
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "deep2/ExchangeMirror.hpp"

namespace CPUInference {

bool VulkanCompute::EnsureMlaAttn(uint32_t nHeads, uint32_t qkDim, uint32_t vDim,
                                  uint32_t nope, uint32_t rope, uint32_t maxSeq,
                                  uint32_t nLayers) {
    if (!device_ || !nHeads || !qkDim || !vDim || !nope || !rope || !maxSeq || !nLayers)
        return false;
    if (!mla_attn_pipe_) {
        if (!LoadComputePipeline("attn_decode_mla.spv", 7, 48, mla_attn_pipe_,
                                 mla_attn_layout_, mla_attn_dsl_, mla_attn_pool_,
                                 mla_attn_ds_))
            return false;
    }
    auto grow = [&](DeviceBuf& b, size_t need) -> bool {
        if (b.buffer && b.bytes >= need) return true;
        if (b.buffer) { vkDestroyBuffer(device_, b.buffer, nullptr); b.buffer = nullptr; }
        if (b.memory) { vkFreeMemory(device_, b.memory, nullptr); b.memory = nullptr; }
        b.bytes = 0;
        if (!CreateDeviceLocalBuffer(need, b.buffer, b.memory)) return false;
        b.bytes = need;
        return true;
    };
    const size_t qB = (size_t)nHeads * qkDim * 4ull;
    const size_t kbB = (size_t)nHeads * nope * 4ull;
    const size_t vbB = (size_t)nHeads * vDim * 4ull;
    const size_t kpeB = (size_t)rope * 4ull;
    const size_t outB = vbB;
    const size_t kcB = (size_t)nLayers * maxSeq * nHeads * qkDim * 4ull;
    const size_t vcB = (size_t)nLayers * maxSeq * nHeads * vDim * 4ull;
    /* PATH_B: mla_q_ holds live Q. Never destroy/realloc here — that nulls
       VkBuffer (descriptor offset @ 0x0) and drops staged Q. Require
       EnsureMlaQBytes / PathB_NoteQDev first. */
    if (!mla_q_.buffer || mla_q_.bytes < qB)
        return false;
    if (!grow(mla_kb_, kbB) || !grow(mla_vb_, vbB) || !grow(mla_kpe_, kpeB) ||
        !grow(mla_out_, outB) || !grow(mla_k_cache_, kcB) ||
        !grow(mla_v_cache_, vcB))
        return false;
    mla_n_heads_ = nHeads; mla_qk_ = qkDim; mla_v_ = vDim;
    mla_max_seq_ = maxSeq; mla_n_layers_ = nLayers;
    return true;
}

bool VulkanCompute::EnsureMlaQBytes(size_t need) {
    if (!device_ || !need) return false;
    if (mla_q_.buffer && mla_q_.bytes >= need) return true;
    if (mla_q_.buffer) {
        vkDestroyBuffer(device_, mla_q_.buffer, nullptr);
        mla_q_.buffer = nullptr;
    }
    if (mla_q_.memory) {
        vkFreeMemory(device_, mla_q_.memory, nullptr);
        mla_q_.memory = nullptr;
    }
    mla_q_.bytes = 0;
    if (!CreateDeviceLocalBuffer(need, mla_q_.buffer, mla_q_.memory)) return false;
    mla_q_.bytes = need;
    return true;
}

bool VulkanCompute::DispatchAttnDecodeMLA(
    DeviceBuf& q, DeviceBuf& kb, DeviceBuf& vb, DeviceBuf& kpe, DeviceBuf& out,
    uint32_t qkDim, uint32_t vDim, uint32_t nope, uint32_t rope, uint32_t nHeads,
    uint32_t pos, float theta, float scale, float ropeScale, uint32_t layer) {
    if (!mla_attn_pipe_ || !q.buffer || !kb.buffer || !vb.buffer || !kpe.buffer ||
        !out.buffer || !mla_k_cache_.buffer || !mla_v_cache_.buffer)
        return false;
    if (pos >= mla_max_seq_ || layer >= mla_n_layers_) return false;
    const VkDeviceSize kLayerB =
        (VkDeviceSize)mla_max_seq_ * nHeads * qkDim * 4ull;
    const VkDeviceSize vLayerB =
        (VkDeviceSize)mla_max_seq_ * nHeads * vDim * 4ull;
    VkDescriptorBufferInfo infos[7] = {
        {q.buffer, 0, q.bytes},
        {kb.buffer, 0, kb.bytes},
        {vb.buffer, 0, vb.bytes},
        {kpe.buffer, 0, kpe.bytes},
        {mla_k_cache_.buffer, (VkDeviceSize)layer * kLayerB, kLayerB},
        {mla_v_cache_.buffer, (VkDeviceSize)layer * vLayerB, vLayerB},
        {out.buffer, 0, out.bytes}};
    VkWriteDescriptorSet w[7]{};
    for (int i = 0; i < 7; ++i) {
        w[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        w[i].dstSet = mla_attn_ds_;
        w[i].dstBinding = (uint32_t)i;
        w[i].descriptorCount = 1;
        w[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        w[i].pBufferInfo = &infos[i];
    }
    vkUpdateDescriptorSets(device_, 7, w, 0, nullptr);
    struct PC {
        uint32_t qk_dim, v_dim, nope, rope, n_heads, n_kv, pos, max_seq;
        float theta, scale, rope_scale;
        uint32_t _pad;
    } pc{qkDim, vDim, nope, rope, nHeads, nHeads, pos, mla_max_seq_, theta, scale,
         ropeScale, 0};
    static_assert(sizeof(PC) == 48, "attn_decode_mla PC");
    Deep2::ExchangeMirror::NoteAgg(Deep2::ExchangeMirror::Dir::D2D,
        Deep2::ExchangeMirror::Kind::Activation, (uint64_t)out.bytes,
        "attn_decode_mla_device");
    return RecordCompute(mla_attn_pipe_, mla_attn_layout_, mla_attn_ds_, &pc,
                         48, (nHeads + 63u) / 64u);
}

} // namespace CPUInference
#endif
