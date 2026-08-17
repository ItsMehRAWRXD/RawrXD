#include "ElasticResidencyManager.hpp"
#include <windows.h>

namespace RawrXD::Elastic {

// ============================================================================
// Construction: discover GPU capacity from governance probe
// ============================================================================
ElasticResidencyManager::ElasticResidencyManager(ElasticGGUFIndex& index)
    : index_(index) {
    RawrXD::Governance::HardwareCapabilityProbe probe;
    auto snap = probe.probe();
    if (!snap.gpus.empty() && snap.gpus[0].dedicated_bytes > 0) {
        gpu_capacity_bytes_ = snap.gpus[0].dedicated_bytes;
    } else {
        gpu_capacity_bytes_ = 32ULL << 30; // Fallback: 32 GB
    }
    // Reserve 1 GB for OS/driver overhead + transient buffers
    gpu_budget_bytes_ = gpu_capacity_bytes_ > (1ULL << 30)
        ? gpu_capacity_bytes_ - (1ULL << 30)
        : gpu_capacity_bytes_;
}

// ============================================================================
// GPU callbacks
// ============================================================================
void ElasticResidencyManager::SetGpuCallbacks(GpuAllocator alloc, GpuDeallocator dealloc) {
    gpu_alloc_ = std::move(alloc);
    gpu_dealloc_ = std::move(dealloc);
}

// ============================================================================
// CPU mmap residency
// ============================================================================
const void* ElasticResidencyManager::RequireCpuResident(uint32_t block_id) {
    auto* state = index_.GetResidency(block_id);
    const auto* meta = index_.GetBlock(block_id);
    if (!state || !meta) return nullptr;

    // Already mapped?
    if (state->cpu_mapped_ptr != nullptr) {
        return state->cpu_mapped_ptr;
    }

    // Map a view of the GGUF file at the block's offset
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    DWORD allocGran = sysInfo.dwAllocationGranularity;

    size_t mapped_offset = (meta->file_offset / allocGran) * allocGran;
    size_t offset_diff = static_cast<size_t>(meta->file_offset - mapped_offset);
    size_t mapped_size = static_cast<size_t>(meta->byte_size + offset_diff);

    HANDLE hMap = index_.GetLoader().GetMappingHandle();
    if (!hMap) return nullptr;

    void* base_ptr = MapViewOfFile(
        hMap,
        FILE_MAP_READ,
        static_cast<DWORD>(mapped_offset >> 32),
        static_cast<DWORD>(mapped_offset & 0xFFFFFFFF),
        mapped_size
    );

    if (!base_ptr) return nullptr;

    state->cpu_mapped_ptr = static_cast<uint8_t*>(base_ptr) + offset_diff;
    state->cpu_mapped_size = mapped_size;
    state->state.store(ElasticResidencyTier::Warm, std::memory_order_release);
    return state->cpu_mapped_ptr;
}

// ============================================================================
// GPU VRAM residency
// ============================================================================
void* ElasticResidencyManager::RequireGpuResident(uint32_t block_id) {
    auto* state = index_.GetResidency(block_id);
    const auto* meta = index_.GetBlock(block_id);
    if (!state || !meta || !gpu_alloc_) return nullptr;

    uint64_t tick = global_tick_.fetch_add(1, std::memory_order_relaxed);
    state->last_access_tick.store(tick, std::memory_order_relaxed);

    // Already GPU resident?
    if (state->state.load(std::memory_order_acquire) == ElasticResidencyTier::Hot &&
        state->gpu_buffer != nullptr) {
        return state->gpu_buffer;
    }

    // Ensure CPU mapping exists first
    const void* cpu_ptr = RequireCpuResident(block_id);
    if (!cpu_ptr) return nullptr;

    // Evict LRU until we have budget
    EvictLruUntilFits(meta->byte_size);

    // Allocate GPU buffer
    uint64_t allocated = 0;
    void* gpu_buf = gpu_alloc_(meta->byte_size, allocated);
    if (!gpu_buf) return nullptr;

    state->gpu_buffer = gpu_buf;
    state->gpu_buffer_size = allocated;
    state->state.store(ElasticResidencyTier::Hot, std::memory_order_release);
    gpu_resident_bytes_.fetch_add(allocated, std::memory_order_relaxed);

    return gpu_buf;
}

// ============================================================================
// Pin / Unpin
// ============================================================================
void ElasticResidencyManager::PinBlock(uint32_t block_id) {
    auto* state = index_.GetResidency(block_id);
    if (state) {
        state->state.store(ElasticResidencyTier::Pinned, std::memory_order_relaxed);
        state->last_access_tick.store(UINT64_MAX, std::memory_order_relaxed);
    }
}

void ElasticResidencyManager::UnpinBlock(uint32_t block_id) {
    auto* state = index_.GetResidency(block_id);
    if (state) {
        state->state.store(ElasticResidencyTier::Hot, std::memory_order_relaxed);
        uint64_t tick = global_tick_.load(std::memory_order_relaxed);
        state->last_access_tick.store(tick, std::memory_order_relaxed);
    }
}

// ============================================================================
// LRU eviction
// ============================================================================
void ElasticResidencyManager::EvictLruUntilFits(uint64_t required_bytes) {
    std::lock_guard<std::mutex> lock(eviction_mutex_);

    while (gpu_resident_bytes_.load(std::memory_order_relaxed) + required_bytes > gpu_budget_bytes_) {
        const ComputeBlock* lru_meta = nullptr;
        BlockResidencyState* lru_state = nullptr;
        uint64_t oldest_tick = UINT64_MAX;

        for (const auto& block : index_.GetAllBlocks()) {
            auto* state = index_.GetResidency(block.block_id);
            if (!state) continue;

            auto tier = state->state.load(std::memory_order_relaxed);
            if (tier != ElasticResidencyTier::Hot && tier != ElasticResidencyTier::Pinned) continue;

            uint64_t tick = state->last_access_tick.load(std::memory_order_relaxed);
            if (tick < oldest_tick) {
                oldest_tick = tick;
                lru_meta = &block;
                lru_state = state;
            }
        }

        if (!lru_state) break; // Nothing evictable

        // Deallocate GPU buffer
        if (gpu_dealloc_ && lru_state->gpu_buffer) {
            gpu_dealloc_(lru_state->gpu_buffer);
        }
        gpu_resident_bytes_.fetch_sub(lru_state->gpu_buffer_size, std::memory_order_relaxed);
        lru_state->gpu_buffer = nullptr;
        lru_state->gpu_buffer_size = 0;
        lru_state->state.store(ElasticResidencyTier::Warm, std::memory_order_release);
    }
}

} // namespace RawrXD::Elastic
