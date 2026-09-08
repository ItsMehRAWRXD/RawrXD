// vulkan_weight_window.cpp — STREAMER_GPU_WEIGHT_WINDOW_001 bounded slots
#ifdef _WIN32
#include <windows.h>
#endif
#include "vulkan_compute.h"
#if RAWR_VULKAN_AVAILABLE
#include "GpuTransferCounters.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>

namespace CPUInference {

bool VulkanCompute::WantWeightStream() {
    const char* m = std::getenv("DEEP2_WEIGHT_MODE");
    if (m && (std::strcmp(m, "RESIDENT_CACHE") == 0 || std::strcmp(m, "0") == 0))
        return false;
    return true;
}

void VulkanCompute::ClearPinnedGemvWeights() {
    if (!device_) {
        gemv_weight_cache_.clear();
        gemv_resident_bytes_ = 0;
        gemv_weight_uploads_ = 0;
        gemv_weight_hits_ = 0;
        gemv_pin_evicts_ = 0;
        gemv_pin_clock_ = 0;
        ww_content_hits_ = 0;
        ww_pin_rejects_ = 0;
        return;
    }
    for (auto& kv : gemv_weight_cache_) {
        if (kv.second.buffer) vkDestroyBuffer(device_, kv.second.buffer, nullptr);
        if (kv.second.memory) vkFreeMemory(device_, kv.second.memory, nullptr);
    }
    gemv_weight_cache_.clear();
    gemv_resident_bytes_ = 0;
    gemv_weight_uploads_ = 0;
    gemv_weight_hits_ = 0;
    gemv_pin_evicts_ = 0;
    gemv_pin_clock_ = 0;
    ww_content_hits_ = 0;
    ww_pin_rejects_ = 0;
}

void VulkanCompute::ReleaseWeightWindow() {
    if (!device_) { ww_slot_count_ = 0; ww_active_ = false; return; }
    for (uint32_t i = 0; i < ww_slot_count_; ++i) {
        WeightSlot& s = ww_slots_[i];
        if (s.fence) { vkDestroyFence(device_, s.fence, nullptr); s.fence = nullptr; }
        if (s.uploadFence) { vkDestroyFence(device_, s.uploadFence, nullptr); s.uploadFence = nullptr; }
        if (s.computeFence) { vkDestroyFence(device_, s.computeFence, nullptr); s.computeFence = nullptr; }
        if (s.uploadCmd) { vkFreeCommandBuffers(device_, command_pool_, 1, &s.uploadCmd); s.uploadCmd = nullptr; }
        if (s.computeCmd) { vkFreeCommandBuffers(device_, command_pool_, 1, &s.computeCmd); s.computeCmd = nullptr; }
        if (s.stagingMap) { vkUnmapMemory(device_, s.stagingMem); s.stagingMap = nullptr; }
        if (s.staging) { vkDestroyBuffer(device_, s.staging, nullptr); s.staging = nullptr; }
        if (s.stagingMem) { vkFreeMemory(device_, s.stagingMem, nullptr); s.stagingMem = nullptr; }
        if (s.device.buffer) { vkDestroyBuffer(device_, s.device.buffer, nullptr); }
        if (s.device.memory) { vkFreeMemory(device_, s.device.memory, nullptr); }
        s.device = {};
        s.busy = false;
        s.uploadPending = false;
        s.computePending = false;
        s.hasContent = false;
        s.contentKey = 0;
        s.contentBytes = 0;
    }
    ww_slot_count_ = 0;
    ww_slot_bytes_ = 0;
    ww_cursor_ = 0;
    ww_layer_used_ = 0;
    ww_active_ = false;
    ww_peak_bytes_ = 0;
    // Keep gemv_weight_cache_ / pin counters — stream rebuild ≠ pin eviction.
}

void VulkanCompute::ResetWeightWindowLayerCursor() {
    ww_cursor_ = 0;
    if (ww_layer_used_ > 0) {
        ww_slot_reuses_ += ww_layer_used_;
        ww_prefetch_distance_ = ww_slot_count_ > 1 ? (ww_slot_count_ - 1) : 0;
    }
    ww_layer_used_ = 0;
}

bool VulkanCompute::EnsureWeightWindow(size_t slotBytes, uint32_t slotCount,
                                       size_t budgetBytes) {
    if (!device_ || !WantWeightStream()) { ww_active_ = false; return true; }
    if (slotCount < 2 || slotCount > kWwMaxSlots) return false;
    if (slotBytes == 0) return false;
    if (budgetBytes && (uint64_t)slotCount * (uint64_t)slotBytes > budgetBytes) {
        // Shrink slot count to fit budget (pin path needs many small slots).
        uint32_t fit = (uint32_t)(budgetBytes / slotBytes);
        if (fit < 2) return false;
        if (fit > kWwMaxSlots) fit = kWwMaxSlots;
        slotCount = fit;
    }
    if (ww_active_ && ww_slot_bytes_ >= slotBytes && ww_slot_count_ >= slotCount)
        return true;
    if (ww_init_done_ && (slotBytes > ww_slot_bytes_ || slotCount > ww_slot_count_)) {
        if (fused_cmd_) {
            ++ww_growth_after_init_;
            return false;
        }
        ReleaseWeightWindow();
        ww_init_done_ = false;
        ww_slot_allocs_ = 0;
        ww_stream_bytes_total_ = 0;
    }
    ReleaseWeightWindow();
    // Never shrink below sticky pin floor (MLA residency) or live budget.
    if (ww_pin_budget_floor_ && budgetBytes < ww_pin_budget_floor_)
        budgetBytes = ww_pin_budget_floor_;
    if (ww_budget_bytes_ && budgetBytes && budgetBytes < ww_budget_bytes_)
        budgetBytes = ww_budget_bytes_;
    if (budgetBytes) ww_budget_bytes_ = budgetBytes;
    for (uint32_t i = 0; i < slotCount; ++i) {
        WeightSlot& s = ww_slots_[i];
        if (!CreateDeviceLocalBuffer(slotBytes, s.device.buffer, s.device.memory)) {
            ReleaseWeightWindow();
            return false;
        }
        s.device.bytes = slotBytes;
        if (!CreateHostVisibleBuffer(slotBytes, s.staging, s.stagingMem)) {
            ReleaseWeightWindow();
            return false;
        }
        if (vkMapMemory(device_, s.stagingMem, 0, slotBytes, 0, &s.stagingMap) != VK_SUCCESS) {
            ReleaseWeightWindow();
            return false;
        }
        VkFenceCreateInfo fi{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
        fi.flags = VK_FENCE_CREATE_SIGNALED_BIT;
        if (vkCreateFence(device_, &fi, nullptr, &s.fence) != VK_SUCCESS ||
            vkCreateFence(device_, &fi, nullptr, &s.uploadFence) != VK_SUCCESS ||
            vkCreateFence(device_, &fi, nullptr, &s.computeFence) != VK_SUCCESS) {
            ReleaseWeightWindow();
            return false;
        }
        ++ww_slot_allocs_;
    }
    ww_hotpath_create_buf_ = 0;
    ww_hotpath_destroy_buf_ = 0;
    ww_slot_count_ = slotCount;
    ww_slot_bytes_ = slotBytes;
    ww_peak_bytes_ = (uint64_t)slotCount * (uint64_t)slotBytes;
    ww_active_ = true;
    ww_init_done_ = true;
    ww_prefetch_ = WantWeightPrefetch();
    ww_cursor_ = 0;
    ww_layer_used_ = 0;
    return true;
}

bool VulkanCompute::WantWeightPin() {
    const char* e = std::getenv("DEEP2_WEIGHT_PIN");
    if (e && e[0] == '1') return true;
    // Production reuse policy: GPU MLA implies resident pin (PROMOTE_GPU_MLA_REUSE).
    const char* mla = std::getenv("DEEP2_K2_GPU_MLA");
    return mla && mla[0] == '1';
}

uintptr_t VulkanCompute::WeightContentFingerprint(const void* p, size_t bytes) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    uint64_t h = 14695981039346656037ull ^ (uint64_t)bytes * 0x9e3779b97f4a7c15ull;
    auto mix = [&](uint64_t v) { h = (h ^ v) * 1099511628211ull; };
    if (bytes >= 16) {
        uint64_t head = 0, tail = 0;
        std::memcpy(&head, b, 8);
        std::memcpy(&tail, b + bytes - 8, 8);
        mix(head); mix(tail);
    }
    // Golden-stride samples — regular stride-16 collided on Q4_K blocks.
    if (bytes >= 8) {
        const size_t span = bytes - 7u;
        for (uint32_t i = 1; i <= 96u; ++i) {
            const size_t off = (size_t)(((uint64_t)i * 11400714819323198485ull) % span);
            uint64_t w = 0;
            std::memcpy(&w, b + off, 8);
            mix(w);
        }
    } else {
        for (size_t i = 0; i < bytes; ++i) mix(b[i]);
    }
    return (uintptr_t)h;
}

size_t VulkanCompute::WeightBudgetBytes() const { return ww_budget_bytes_; }
size_t VulkanCompute::WeightPinBudgetFloor() const { return ww_pin_budget_floor_; }
void VulkanCompute::SetPinResidentBudget(size_t bytes) {
    if (!bytes) return;
    ww_budget_bytes_ = bytes;
    ww_pin_budget_floor_ = bytes;
}
uint64_t VulkanCompute::WeightPinCacheCount() const {
    return (uint64_t)gemv_weight_cache_.size();
}
uint64_t VulkanCompute::WeightPinResidentBytes() const {
    return (uint64_t)gemv_resident_bytes_;
}

bool VulkanCompute::HasPinnedGemvWeight(uint64_t pinKey, size_t bytes,
                                        uint32_t rows, uint32_t cols) const {
    if (!pinKey || !bytes) return false;
    auto it = gemv_weight_cache_.find(pinKey);
    if (it == gemv_weight_cache_.end()) return false;
    return it->second.buffer && it->second.bytes == bytes &&
           it->second.rows == rows && it->second.cols == cols;
}

bool VulkanCompute::EnsurePinnedPackedWeight(const void* packed, size_t bytes,
                                             uint32_t rows, uint32_t cols,
                                             VkBuffer& outDev, uint64_t pinKey) {
    if (!device_ || !packed || !bytes) return false;
    size_t budget = ww_budget_bytes_ ? ww_budget_bytes_ : ((size_t)2048 << 20);
    if (ww_pin_budget_floor_ > budget) budget = ww_pin_budget_floor_;
    // Prefer live SetPinResidentBudget; env only if unset (avoid shallow Sync poison).
    if (!ww_budget_bytes_ && !ww_pin_budget_floor_) {
        if (const char* b = std::getenv("DEEP2_WEIGHT_BUDGET_MIB"))
            if (*b) budget = (size_t)std::atoi(b) << 20;
    }
    const uint64_t key = pinKey ? pinKey
        : ((uint64_t)WeightContentFingerprint(packed, bytes) ^
           ((uint64_t)rows * 0x100000001b3ull) ^
           ((uint64_t)cols * 0xcbf29ce484222325ull) ^
           ((uint64_t)bytes * 0x9e3779b97f4a7c15ull));
    auto it = gemv_weight_cache_.find(key);
    // Stable MLA pinKey: trust key+shape — skip content fingerprint on hit.
    if (pinKey && it != gemv_weight_cache_.end() && it->second.bytes == bytes &&
        it->second.rows == rows && it->second.cols == cols && it->second.buffer) {
        it->second.lastUse = ++gemv_pin_clock_;
        outDev = it->second.buffer;
        ++ww_content_hits_;
        ++gemv_weight_hits_;
        Deep2::GpuTransfer_NoteWeightHit(bytes);
        return true;
    }
    const uintptr_t fpNow = WeightContentFingerprint(packed, bytes);
    if (it != gemv_weight_cache_.end() && it->second.bytes == bytes &&
        it->second.rows == rows && it->second.cols == cols && it->second.buffer &&
        it->second.contentFp == fpNow) {
        it->second.lastUse = ++gemv_pin_clock_;
        outDev = it->second.buffer;
        ++ww_content_hits_;
        ++gemv_weight_hits_;
        Deep2::GpuTransfer_NoteWeightHit(bytes);
        return true;
    }
    while (gemv_resident_bytes_ + bytes > budget && !gemv_weight_cache_.empty()) {
        auto victim = gemv_weight_cache_.begin();
        for (auto jt = gemv_weight_cache_.begin(); jt != gemv_weight_cache_.end(); ++jt)
            if (jt->second.lastUse < victim->second.lastUse) victim = jt;
        if (victim->second.buffer)
            vkDestroyBuffer(device_, victim->second.buffer, nullptr);
        if (victim->second.memory)
            vkFreeMemory(device_, victim->second.memory, nullptr);
        gemv_resident_bytes_ -= victim->second.bytes;
        gemv_weight_cache_.erase(victim);
        ++gemv_pin_evicts_;
    }
    if (gemv_resident_bytes_ + bytes > budget) {
        ++ww_pin_rejects_;
        return false;
    }
    GemvResidentWeight rw{};
    if (!CreateDeviceLocalBuffer(bytes, rw.buffer, rw.memory)) return false;
    if (!UploadToDeviceLocal(packed, bytes, rw.buffer)) {
        vkDestroyBuffer(device_, rw.buffer, nullptr);
        vkFreeMemory(device_, rw.memory, nullptr);
        return false;
    }
    rw.bytes = bytes; rw.rows = rows; rw.cols = cols;
    rw.contentFp = fpNow;
    rw.lastUse = ++gemv_pin_clock_;
    if (it != gemv_weight_cache_.end()) {
        if (it->second.buffer) vkDestroyBuffer(device_, it->second.buffer, nullptr);
        if (it->second.memory) vkFreeMemory(device_, it->second.memory, nullptr);
        gemv_resident_bytes_ -= it->second.bytes;
    }
    gemv_weight_cache_[key] = rw;
    gemv_resident_bytes_ += bytes;
    ww_peak_bytes_ = (std::max)(ww_peak_bytes_, gemv_resident_bytes_);
    ++gemv_weight_uploads_;
    Deep2::GpuTransfer_NoteWeightMiss(bytes, true);
    outDev = rw.buffer;
    return true;
}

void VulkanCompute::ReleasePinnedPackedWeight(uint64_t pinKey) {
    if (!device_ || !pinKey) return;
    auto it = gemv_weight_cache_.find(pinKey);
    if (it == gemv_weight_cache_.end()) return;
    if (it->second.buffer)
        vkDestroyBuffer(device_, it->second.buffer, nullptr);
    if (it->second.memory)
        vkFreeMemory(device_, it->second.memory, nullptr);
    if (gemv_resident_bytes_ >= it->second.bytes)
        gemv_resident_bytes_ -= it->second.bytes;
    else
        gemv_resident_bytes_ = 0;
    gemv_weight_cache_.erase(it);
    ++gemv_pin_evicts_;
}

bool VulkanCompute::EnsurePinnedF32(const float* data, uint32_t n, VkBuffer& outDev,
                                    uint64_t pinKey) {
    if (!device_ || !data || !n || !pinKey) return false;
    const size_t bytes = (size_t)n * 4u;
    return EnsurePinnedPackedWeight(data, bytes, n, 1u, outDev, pinKey);
}

bool VulkanCompute::StreamWeightToSlot(const void* weights, size_t bytes, VkBuffer& outDev) {
    if (!ww_active_ || !weights || bytes == 0 || bytes > ww_slot_bytes_) return false;
    const uintptr_t key = WeightContentFingerprint(weights, bytes);
    for (uint32_t j = 0; j < ww_slot_count_; ++j) {
        WeightSlot& h = ww_slots_[j];
        if (h.hasContent && h.contentKey == key && h.contentBytes == bytes && !h.busy) {
            Deep2::GpuTransfer_NoteWeightHit(bytes);
            ++ww_content_hits_;
            outDev = h.device.buffer;
            return true;
        }
    }
    const bool pin = WantWeightPin();
    uint32_t i = ww_cursor_;
    if (pin) {
        uint32_t free = UINT32_MAX;
        for (uint32_t j = 0; j < ww_slot_count_; ++j) {
            if (!ww_slots_[j].hasContent) { free = j; break; }
        }
        if (free == UINT32_MAX) {
            ++ww_pin_rejects_;
            return false; // keep residents; caller falls back to CPU
        }
        i = free;
    } else {
        if (fused_cmd_ && ww_layer_used_ >= ww_slot_count_) {
            if (!FlushFusedRestart()) return false;
            ww_cursor_ = 0;
            ww_slot_reuses_ += ww_layer_used_;
            Deep2::GpuTransfer_NoteSlotReuse();
            ww_prefetch_distance_ = ww_slot_count_ > 1 ? (ww_slot_count_ - 1) : 0;
            ww_layer_used_ = 0;
        }
        if (!fused_cmd_ && ww_layer_used_ >= ww_slot_count_) {
            ww_slot_reuses_ += ww_layer_used_;
            Deep2::GpuTransfer_NoteSlotReuse();
            ww_layer_used_ = 0;
            ww_prefetch_distance_ = ww_slot_count_ > 1 ? (ww_slot_count_ - 1) : 0;
        }
        i = ww_cursor_;
    }
    WeightSlot& s = ww_slots_[i];
    if (s.fence && s.busy) {
        if (vkWaitForFences(device_, 1, &s.fence, VK_TRUE, 30ull * 1000000000ull) != VK_SUCCESS)
            return false;
        s.busy = false;
    }
    const bool first = Deep2::GpuTransfer_MarkSeenKey(key);
    Deep2::GpuTransfer_NoteWeightMiss(bytes, first);
    if (!first) Deep2::GpuTransfer_NoteRedundantUpload();
    std::memcpy(s.stagingMap, weights, bytes);
    if (fused_cmd_) {
        if (!RecordCopy(s.staging, s.device.buffer, 0, 0, (VkDeviceSize)bytes))
            return false;
    } else {
        if (!s.uploadCmd) {
            VkCommandBufferAllocateInfo cai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
            cai.commandPool = command_pool_;
            cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
            cai.commandBufferCount = 1;
            if (vkAllocateCommandBuffers(device_, &cai, &s.uploadCmd) != VK_SUCCESS)
                return false;
        }
        vkResetCommandBuffer(s.uploadCmd, 0);
        VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        vkBeginCommandBuffer(s.uploadCmd, &bi);
        VkBufferCopy c{}; c.size = bytes;
        vkCmdCopyBuffer(s.uploadCmd, s.staging, s.device.buffer, 1, &c);
        Deep2::GpuTransfer_NoteCopy((uint64_t)bytes, Deep2::GpuCopyKind::Weight);
        vkEndCommandBuffer(s.uploadCmd);
        vkResetFences(device_, 1, &s.fence);
        auto t0 = std::chrono::steady_clock::now();
        VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
        si.commandBufferCount = 1;
        si.pCommandBuffers = &s.uploadCmd;
        if (vkQueueSubmit(compute_queue_, 1, &si, s.fence) != VK_SUCCESS)
            return false;
        auto t1 = std::chrono::steady_clock::now();
        Deep2::GpuTransfer_AddSubmitUs((uint64_t)std::chrono::duration_cast<
            std::chrono::microseconds>(t1 - t0).count());
        s.busy = true;
        if (vkWaitForFences(device_, 1, &s.fence, VK_TRUE, 30ull * 1000000000ull) != VK_SUCCESS)
            return false;
        auto t2 = std::chrono::steady_clock::now();
        Deep2::GpuTransfer_AddWaitUs((uint64_t)std::chrono::duration_cast<
            std::chrono::microseconds>(t2 - t1).count());
        s.busy = false;
        ++xfer_records_;
        ++xfer_submits_;
        ++op_submits_;
    }
    s.hasContent = true;
    s.contentKey = key;
    s.contentBytes = bytes;
    outDev = s.device.buffer;
    if (!pin) ww_cursor_ = (ww_cursor_ + 1u) % ww_slot_count_;
    ++ww_layer_used_;
    ww_stream_bytes_total_ += bytes;
    ++gemv_weight_uploads_;
    return true;
}

} // namespace CPUInference
#endif
