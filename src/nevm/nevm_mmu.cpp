//============================================================================
// nevm_mmu.cpp
// RawrXD N-EVM Neural Memory Management Unit - Implementation
//============================================================================

#include "nevm_mmu.hpp"
#include <algorithm>
#include <string>

namespace RawrXD {
namespace NEVM {

//============================================================================
// NeuralMMU Implementation
//============================================================================

NeuralMMU::NeuralMMU(const Config& config) : config_(config) {
    // Initialize memory pools
    ram_pool_.size = config.ram_budget;
    ram_pool_.used = 0;
    ram_pool_.base = VirtualAlloc(nullptr, config.ram_budget, 
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    // VRAM would be allocated via CUDA/Vulkan - placeholder
    vram_pool_.size = config.vram_budget;
    vram_pool_.used = 0;
    vram_pool_.base = nullptr;  // Managed by GPU driver
    
    // Cache pool (L3 resident)
    cache_pool_.size = config.cache_budget;
    cache_pool_.used = 0;
    cache_pool_.base = _aligned_malloc(config.cache_budget, 64);
    
    stats_ = {};
}

NeuralMMU::~NeuralMMU() {
    if (ram_pool_.base) {
        VirtualFree(ram_pool_.base, 0, MEM_RELEASE);
    }
    if (cache_pool_.base) {
        _aligned_free(cache_pool_.base);
    }
}

void* NeuralMMU::Translate(VirtualTensorAddress vta, bool allocate_if_missing) {
    uint64_t block_key = vta.BlockKey();
    
    {
        std::shared_lock<std::shared_mutex> lock(tlb_mutex_);
        auto it = tlb_.find(block_key);
        if (it != tlb_.end()) {
            // TLB hit
            it->second.last_access = GetTick();
            {
                std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                stats_.tlb_hits++;
            }
            
            // Calculate actual address
            char* base = static_cast<char*>(it->second.state.physical_ptr);
            return base + vta.fields.block_offset;
        }
    }
    
    // TLB miss
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.tlb_misses++;
    }
    
    if (!allocate_if_missing) {
        return nullptr;
    }
    
    // Page fault - need to load block
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.page_faults++;
    }
    
    // Return nullptr - caller must handle loading
    return nullptr;
}

bool NeuralMMU::LoadBlock(VirtualTensorAddress vta, const void* source_data, size_t size) {
    uint64_t block_key = vta.BlockKey();
    
    // Allocate physical memory
    void* physical = AllocatePhysical(ResidencyTarget::RAM, size);
    if (!physical) {
        // Try eviction
        EvictLRU(size);
        physical = AllocatePhysical(ResidencyTarget::RAM, size);
        if (!physical) {
            return false;
        }
    }
    
    // Copy data
    std::memcpy(physical, source_data, size);
    
    // Create TLB entry
    TLBEntry entry;
    entry.state.vta = vta;
    entry.state.physical_ptr = physical;
    entry.state.physical_size = size;
    entry.state.residency = ResidencyTarget::RAM;
    entry.state.last_access_tick = GetTick();
    entry.last_access = GetTick();
    
    {
        std::unique_lock<std::shared_mutex> lock(tlb_mutex_);
        tlb_[block_key] = std::move(entry);
    }
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.blocks_loaded++;
        stats_.ram_used += size;
    }
    
    return true;
}

bool NeuralMMU::EvictBlock(VirtualTensorAddress vta) {
    uint64_t block_key = vta.BlockKey();
    
    std::unique_lock<std::shared_mutex> lock(tlb_mutex_);
    auto it = tlb_.find(block_key);
    if (it == tlb_.end()) {
        return false;
    }
    
    // Free physical memory
    FreePhysical(it->second.state.residency, 
                 it->second.state.physical_ptr, 
                 it->second.state.physical_size);
    
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.blocks_evicted++;
        if (it->second.state.residency == ResidencyTarget::RAM) {
            stats_.ram_used -= it->second.state.physical_size;
        }
    }
    
    tlb_.erase(it);
    return true;
}

void NeuralMMU::EvictLRU(size_t target_bytes) {
    // Collect entries sorted by last access
    std::vector<std::pair<uint64_t, uint64_t>> entries;  // (last_access, block_key)
    
    {
        std::shared_lock<std::shared_mutex> lock(tlb_mutex_);
        for (const auto& [key, entry] : tlb_) {
            entries.emplace_back(entry.last_access, key);
        }
    }
    
    // Sort by last access (oldest first)
    std::sort(entries.begin(), entries.end());
    
    size_t evicted = 0;
    for (const auto& [access_time, key] : entries) {
        if (evicted >= target_bytes) break;
        
        auto it = tlb_.find(key);
        if (it != tlb_.end()) {
            evicted += it->second.state.physical_size;
            EvictBlock(it->second.state.vta);
        }
    }
}

void* NeuralMMU::AllocatePhysical(ResidencyTarget target, size_t size) {
    // Round up to block size
    size = (size + config_.block_size - 1) & ~(config_.block_size - 1);
    
    switch (target) {
        case ResidencyTarget::RAM:
            if (ram_pool_.used + size > ram_pool_.size) {
                return nullptr;
            }
            {
                void* ptr = static_cast<char*>(ram_pool_.base) + ram_pool_.used;
                ram_pool_.used += size;
                return ptr;
            }
            
        case ResidencyTarget::HOT:
            if (cache_pool_.used + size > cache_pool_.size) {
                return nullptr;
            }
            {
                void* ptr = static_cast<char*>(cache_pool_.base) + cache_pool_.used;
                cache_pool_.used += size;
                return ptr;
            }
            
        default:
            return nullptr;
    }
}

void NeuralMMU::FreePhysical(ResidencyTarget target, void* ptr, size_t size) {
    // Simplified: mark as free in pool
    // Real implementation would use proper allocator
}

NeuralMMU::Stats NeuralMMU::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

uint64_t NeuralMMU::GetTick() const {
    return GetTickCount64();
}

//============================================================================
// DecoderRegistry Implementation
//============================================================================

DecoderRegistry& DecoderRegistry::Instance() {
    static DecoderRegistry instance;
    return instance;
}

void DecoderRegistry::RegisterDecoder(PrecisionMode format, 
                                        std::unique_ptr<BlockDecoder> decoder) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    decoders_[format] = std::move(decoder);
}

BlockDecoder* DecoderRegistry::GetDecoder(PrecisionMode format) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = decoders_.find(format);
    if (it != decoders_.end()) {
        return it->second.get();
    }
    return nullptr;
}

//============================================================================
// GGUFBlockDecoder Implementation
//============================================================================

GGUFBlockDecoder::GGUFBlockDecoder() {}
GGUFBlockDecoder::~GGUFBlockDecoder() {}

bool GGUFBlockDecoder::Decode(const void* source, size_t source_size,
                                PrecisionMode source_format,
                                float* output, size_t output_count) {
    // Direct passthrough - assumes source is already FP32
    // For quantized formats, would call appropriate dequant
    std::memcpy(output, source, output_count * sizeof(float));
    return true;
}

bool GGUFBlockDecoder::Encode(const float* input, size_t input_count,
                                void* output, size_t output_size,
                                PrecisionMode target_format) {
    // Passthrough
    std::memcpy(output, input, input_count * sizeof(float));
    return true;
}

size_t GGUFBlockDecoder::GetDecodedSize(size_t element_count) const {
    return element_count * sizeof(float);
}

bool GGUFBlockDecoder::SupportsFormat(PrecisionMode format) const {
    // Supports all passthrough formats
    return format == PrecisionMode::FP32 || 
           format == PrecisionMode::FP16 ||
           format == PrecisionMode::Q4 ||
           format == PrecisionMode::Q8;
}

} // namespace NEVM
} // namespace RawrXD
