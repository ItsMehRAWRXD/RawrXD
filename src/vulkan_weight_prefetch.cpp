// vulkan_weight_prefetch.cpp — STREAMER_GPU_WEIGHT_PREFETCH_001 overlap
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "GpuTransferCounters.hpp"
#include <chrono>
#include <cstdlib>
#include <cstring>

namespace CPUInference {

bool VulkanCompute::WantWeightPrefetch() {
    const char* m = std::getenv("DEEP2_WEIGHT_PREFETCH");
    if (m && *m) return m[0] != '0';
    // Default ON for bounded stream windows — copy N+1 || compute N.
    return WantWeightStream();
}

bool VulkanCompute::SubmitFence(VkCommandBuffer cmd, VkFence fence) {
    return SubmitFenceOn(cmd, fence, /*transfer=*/false);
}

bool VulkanCompute::SubmitFenceOn(VkCommandBuffer cmd, VkFence fence, bool transfer) {
    VkQueue q = (transfer && dual_queue_ && transfer_queue_) ? transfer_queue_ : compute_queue_;
    VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
    si.commandBufferCount = 1;
    si.pCommandBuffers = &cmd;
    return vkQueueSubmit(q, 1, &si, fence) == VK_SUCCESS;
}

static uintptr_t WeightContentKey(const void* p, size_t bytes) {
    return VulkanCompute::WeightContentFingerprint(p, bytes);
}

bool VulkanCompute::PrefetchWeight(const void* weights, size_t bytes, uint32_t& slotOut) {
    if (!ww_active_ || !weights || bytes == 0 || bytes > ww_slot_bytes_) return false;
    ww_prefetch_ = true;
    const uintptr_t key = WeightContentKey(weights, bytes);

    // Reuse resident slot with same content — suppress duplicate upload.
    for (uint32_t j = 0; j < ww_slot_count_; ++j) {
        WeightSlot& h = ww_slots_[j];
        if (h.hasContent && h.contentKey == key && h.contentBytes == bytes &&
            !h.uploadPending) {
            Deep2::GpuTransfer_NoteWeightHit(bytes);
            slotOut = j;
            return true;
        }
    }

    if (ww_layer_used_ >= ww_slot_count_) {
        ww_slot_reuses_ += ww_layer_used_;
        Deep2::GpuTransfer_NoteSlotReuse();
        ww_layer_used_ = 0;
        ww_prefetch_distance_ = ww_slot_count_ > 1 ? (ww_slot_count_ - 1) : 0;
    }
    const uint32_t i = ww_cursor_;
    WeightSlot& s = ww_slots_[i];
    if (s.computePending && s.computeFence) {
        if (vkWaitForFences(device_, 1, &s.computeFence, VK_TRUE,
                            30ull * 1000000000ull) != VK_SUCCESS)
            return false;
        s.computePending = false;
    }
    if (s.uploadPending && s.uploadFence) {
        if (vkWaitForFences(device_, 1, &s.uploadFence, VK_TRUE,
                            30ull * 1000000000ull) != VK_SUCCESS)
            return false;
        s.uploadPending = false;
    }

    bool concurrentCompute = false;
    for (uint32_t j = 0; j < ww_slot_count_; ++j) {
        if (ww_slots_[j].computePending) { concurrentCompute = true; ++ww_overlap_events_; break; }
    }

    const bool first = Deep2::GpuTransfer_MarkSeenKey(key);
    Deep2::GpuTransfer_NoteWeightMiss(bytes, first);
    if (!first) Deep2::GpuTransfer_NoteRedundantUpload();
    std::memcpy(s.stagingMap, weights, bytes);
    if (!s.uploadCmd) {
        VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        cai.commandPool = command_pool_;
        cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cai.commandBufferCount = 1;
        if (vkAllocateCommandBuffers(device_, &cai, &s.uploadCmd) != VK_SUCCESS) return false;
    } else {
        vkResetCommandBuffer(s.uploadCmd, 0);
    }
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(s.uploadCmd, &bi);
    VkBufferCopy c{}; c.size = bytes;
    vkCmdCopyBuffer(s.uploadCmd, s.staging, s.device.buffer, 1, &c);
    Deep2::GpuTransfer_NoteCopy((uint64_t)bytes, Deep2::GpuCopyKind::Weight);
    vkEndCommandBuffer(s.uploadCmd);
    vkResetFences(device_, 1, &s.uploadFence);
    auto t0 = std::chrono::steady_clock::now();
    if (!SubmitFenceOn(s.uploadCmd, s.uploadFence, /*transfer=*/true)) return false;
    Deep2::GpuTransfer_AddSubmitUs((uint64_t)std::chrono::duration_cast<
        std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count());
    s.uploadPending = true;
    s.hasContent = true;
    s.contentKey = key;
    s.contentBytes = bytes;
    const char* ov = std::getenv("DEEP2_WEIGHT_OVERLAP");
    const bool allowOv = !(ov && ov[0] == '0');
    if (allowOv && concurrentCompute) {
        s.overlapArmed = true;
        s.overlapT0Us = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        Deep2::GpuTransfer_NoteOverlapEvent(bytes);
    } else {
        s.overlapArmed = false;
        // Serialized baseline: wait now so later SubmitGemv sees ready fence.
        if (!WaitWeightUpload(i)) return false;
    }
    ++xfer_records_;
    ++xfer_submits_;
    slotOut = i;
    ww_cursor_ = (ww_cursor_ + 1u) % ww_slot_count_;
    ++ww_layer_used_;
    ww_stream_bytes_total_ += bytes;
    ++gemv_weight_uploads_;
    return true;
}

bool VulkanCompute::WaitWeightUpload(uint32_t slot) {
    if (slot >= ww_slot_count_) return false;
    WeightSlot& s = ww_slots_[slot];
    if (!s.uploadPending) return true;
    if (s.overlapArmed) {
        const uint64_t now = (uint64_t)std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (now > s.overlapT0Us)
            Deep2::GpuTransfer_AddOverlapUs(now - s.overlapT0Us);
        s.overlapArmed = false;
    }
    // Fast path: already signaled (fully hidden behind compute).
    if (vkGetFenceStatus(device_, s.uploadFence) == VK_SUCCESS) {
        s.uploadPending = false;
        return true;
    }
    auto t0 = std::chrono::steady_clock::now();
    if (vkWaitForFences(device_, 1, &s.uploadFence, VK_TRUE,
                        30ull * 1000000000ull) != VK_SUCCESS)
        return false;
    Deep2::GpuTransfer_AddWaitUs((uint64_t)std::chrono::duration_cast<
        std::chrono::microseconds>(std::chrono::steady_clock::now() - t0).count());
    s.uploadPending = false;
    return true;
}

bool VulkanCompute::SubmitGemvPrefetch(uint32_t slot, DeviceBuf& in, DeviceBuf& out,
                                       uint32_t rows, uint32_t cols, size_t packedBytes,
                                       int packedKind) {
    if (!EnsureGemvPipeline() || slot >= ww_slot_count_ || !in.buffer || !out.buffer)
        return false;
    VkPipeline pipe = gemv_pipeline_;
    uint32_t groups = (rows + 255u) / 256u;
    size_t weightBytes = (size_t)rows * cols * sizeof(float);
    if (packedBytes) {
        VkPipeline pp = nullptr; uint64_t* ops = nullptr;
        if (!SelectPackedPipe(packedKind, pp, ops)) return false;
        pipe = pp;
        groups = (rows + 63u) / 64u;
        weightBytes = packedBytes;
        if (ops) ++(*ops);
    }
    if (!WaitWeightUpload(slot)) return false;
    ++gemv_attempts_;
    WeightSlot& s = ww_slots_[slot];
    VkDescriptorSet ds = gemv_ds_;
    if (gemv_ds_n_ > 0) ds = NextGemvDs();
    VkDescriptorBufferInfo dbiW{s.device.buffer, 0, weightBytes};
    VkDescriptorBufferInfo dbiI{in.buffer, 0, (VkDeviceSize)cols * 4};
    VkDescriptorBufferInfo dbiO{out.buffer, 0, (VkDeviceSize)rows * 4};
    VkWriteDescriptorSet writes[3]{};
    for (int i = 0; i < 3; ++i) {
        writes[i].sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET;
        writes[i].dstSet = ds;
        writes[i].descriptorCount = 1;
        writes[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
    }
    writes[0].dstBinding = 0; writes[0].pBufferInfo = &dbiW;
    writes[1].dstBinding = 1; writes[1].pBufferInfo = &dbiI;
    writes[2].dstBinding = 2; writes[2].pBufferInfo = &dbiO;
    vkUpdateDescriptorSets(device_, 3, writes, 0, nullptr);
    if (!s.computeCmd) {
        VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        cai.commandPool = command_pool_;
        cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cai.commandBufferCount = 1;
        if (vkAllocateCommandBuffers(device_, &cai, &s.computeCmd) != VK_SUCCESS) return false;
    } else {
        vkResetCommandBuffer(s.computeCmd, 0);
    }
    VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    vkBeginCommandBuffer(s.computeCmd, &bi);
    vkCmdBindPipeline(s.computeCmd, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
    vkCmdBindDescriptorSets(s.computeCmd, VK_PIPELINE_BIND_POINT_COMPUTE,
                            gemv_pipeline_layout_, 0, 1, &ds, 0, nullptr);
    uint32_t pc[2] = {rows, cols};
    vkCmdPushConstants(s.computeCmd, gemv_pipeline_layout_, VK_SHADER_STAGE_COMPUTE_BIT,
                       0, sizeof(pc), pc);
    vkCmdDispatch(s.computeCmd, groups, 1, 1);
    vkEndCommandBuffer(s.computeCmd);
    vkResetFences(device_, 1, &s.computeFence);
    if (!SubmitFence(s.computeCmd, s.computeFence)) return false;
    s.computePending = true;
    ++gemv_success_;
    ++op_submits_;
    return true;
}

bool VulkanCompute::WaitWeightCompute(uint32_t slot) {
    if (slot >= ww_slot_count_) return false;
    WeightSlot& s = ww_slots_[slot];
    if (!s.computePending) return true;
    if (vkWaitForFences(device_, 1, &s.computeFence, VK_TRUE,
                        30ull * 1000000000ull) != VK_SUCCESS)
        return false;
    s.computePending = false;
    return true;
}

bool VulkanCompute::FlushWeightComputes() {
    for (uint32_t i = 0; i < ww_slot_count_; ++i)
        if (!WaitWeightCompute(i)) return false;
    return true;
}

} // namespace CPUInference
#endif
