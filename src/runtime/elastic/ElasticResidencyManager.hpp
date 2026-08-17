#pragma once
#include "ElasticTypes.hpp"
#include "ElasticGGUFIndex.hpp"
#include "../governance/HardwareCapabilityProbe.hpp"
#include <cstdint>
#include <vector>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <functional>
#include <windows.h>

namespace RawrXD::Elastic {

// ============================================================================
// ElasticResidencyManager
// ============================================================================
// Manages TWO separate residency layers:
//   1. CPU mmap residency — MapViewOfFile on the GGUF (RAM-backed page cache)
//   2. GPU VRAM residency — actual VkBuffer allocations on the R9700
//
// The budget for (2) comes from HardwareCapabilityProbe::probe().gpus[0].dedicated_bytes
// minus a safety margin (1 GB).  Eviction is LRU on GPU VRAM only.
//
// CPU mmap views are kept as long as the file is open; they are cheap.
// GPU buffers are the scarce resource and are evicted aggressively.
// ============================================================================

class ElasticResidencyManager {
public:
    explicit ElasticResidencyManager(ElasticGGUFIndex& index);

    // ------------------------------------------------------------------------
    // GPU allocator callbacks (must be set before any GPU residency requests)
    // ------------------------------------------------------------------------
    using GpuAllocator = std::function<void*(uint64_t requested_bytes, uint64_t& out_allocated_bytes)>;
    using GpuDeallocator = std::function<void(void* gpu_buffer)>;

    void SetGpuCallbacks(GpuAllocator alloc, GpuDeallocator dealloc);

    // ------------------------------------------------------------------------
    // CPU mmap residency (cheap — just a view into the file mapping)
    // ------------------------------------------------------------------------
    // Returns a CPU-accessible pointer to the block's weight data.
    // This does NOT allocate GPU memory.
    // ------------------------------------------------------------------------
    const void* RequireCpuResident(uint32_t block_id);

    // ------------------------------------------------------------------------
    // GPU VRAM residency (expensive — actual VkBuffer allocation)
    // ------------------------------------------------------------------------
    // Ensure block is resident in GPU VRAM.  If not, allocate and upload.
    // Returns the GPU buffer handle, or nullptr on failure.
    // ------------------------------------------------------------------------
    void* RequireGpuResident(uint32_t block_id);

    // Mark a block as non-evictable (e.g. current layer)
    void PinBlock(uint32_t block_id);
    void UnpinBlock(uint32_t block_id);

    // ------------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------------
    uint64_t GpuResidentBytes() const { return gpu_resident_bytes_.load(); }
    uint64_t GpuBudgetBytes() const { return gpu_budget_bytes_; }
    uint64_t GpuCapacityBytes() const { return gpu_capacity_bytes_; }

private:
    void EvictLruUntilFits(uint64_t required_bytes);

    ElasticGGUFIndex& index_;
    uint64_t gpu_capacity_bytes_ = 0;
    uint64_t gpu_budget_bytes_ = 0;
    std::atomic<uint64_t> gpu_resident_bytes_{0};
    std::atomic<uint64_t> global_tick_{0};
    std::mutex eviction_mutex_;
    GpuAllocator gpu_alloc_;
    GpuDeallocator gpu_dealloc_;
};

} // namespace RawrXD::Elastic
