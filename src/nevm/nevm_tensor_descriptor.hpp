//============================================================================
// nevm_tensor_descriptor.hpp
// Cached execution descriptor for Virtual Tensor Addresses
// Enables branchless dispatch through descriptor cache
//============================================================================

#pragma once

#include "nevm_kernel_bridge.hpp"
#include <unordered_map>
#include <shared_mutex>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Tensor Execution Descriptor
// Cached metadata for fast dispatch
//============================================================================

struct TensorExecutionDescriptor {
    // Kernel selection (cached)
    Kernels::KernelID kernel_id;
    Kernels::QuantType quant_type;
    Kernels::KernelCaps required_isa;
    void* kernel_entry;  // Direct function pointer
    
    // Precision state
    ISA::PrecisionMode precision_mode;
    float estimated_error;
    float estimated_latency_ms;
    
    // Residency state
    enum class ResidencyTier {
        HOST_ONLY,      // CPU memory only
        DEVICE_ONLY,    // GPU/VRAM only
        HOST_DEVICE,    // Both (coherent)
        MIGRATING       // In transition
    };
    ResidencyTier residency_tier;
    void* host_ptr;
    void* device_ptr;
    
    // Execution flags
    uint32_t flags;
    static constexpr uint32_t FLAG_PREFETCHED = 1 << 0;
    static constexpr uint32_t FLAG_DIRTY = 1 << 1;
    static constexpr uint32_t FLAG_PINNED = 1 << 2;
    static constexpr uint32_t FLAG_HOT = 1 << 3;  // Frequently accessed
    
    // Validation
    uint64_t version;  // Incremented on changes
    uint64_t last_access;
    uint32_t access_count;
};

//============================================================================
// Descriptor Cache
// Maps VTA → TensorExecutionDescriptor
//============================================================================

class DescriptorCache {
public:
    struct Config {
        size_t max_entries{10000};
        size_t hot_threshold{100};  // Access count for "hot" marking
        uint64_t ttl_ms{60000};      // Time-to-live for entries
    };
    
    static Config DefaultConfig();
    
    explicit DescriptorCache(const Config& config);
    ~DescriptorCache();
    
    // Lookup descriptor (fast path)
    const TensorExecutionDescriptor* Lookup(VirtualTensorAddress vta) const;
    
    // Get or create descriptor
    TensorExecutionDescriptor* GetOrCreate(VirtualTensorAddress vta);
    
    // Update descriptor
    void Update(VirtualTensorAddress vta, const TensorExecutionDescriptor& desc);
    
    // Invalidate entry
    void Invalidate(VirtualTensorAddress vta);
    void InvalidateAll();
    
    // Mark as accessed (updates LRU)
    void Touch(VirtualTensorAddress vta);
    
    // Mark residency change
    void OnResidencyChange(VirtualTensorAddress vta, TensorExecutionDescriptor::ResidencyTier new_tier);
    
    // Mark precision change
    void OnPrecisionChange(VirtualTensorAddress vta, ISA::PrecisionMode new_mode);
    
    // Get hot entries for prefetching
    std::vector<VirtualTensorAddress> GetHotEntries(size_t max_count) const;
    
    // Stats
    struct Stats {
        size_t entries;
        size_t hits;
        size_t misses;
        size_t evictions;
        float hit_rate;
    };
    Stats GetStats() const;
    void ResetStats();

private:
    Config config_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<VirtualTensorAddress, TensorExecutionDescriptor> cache_;
    
    // LRU tracking
    mutable std::vector<VirtualTensorAddress> lru_list_;
    mutable size_t lru_pos_;
    
    // Stats
    mutable size_t hits_;
    mutable size_t misses_;
    mutable size_t evictions_;
    
    void EvictIfNeeded();
    void UpdateLRU(VirtualTensorAddress vta) const;
};

//============================================================================
// Fast Dispatcher
// Branchless dispatch using cached descriptors
//============================================================================

class FastDispatcher {
public:
    explicit FastDispatcher(DescriptorCache* cache);
    ~FastDispatcher();
    
    // Initialize with kernel registry
    void Initialize();
    
    // Fast dispatch (branchless path)
    // Returns true if fast path succeeded
    bool DispatchFast(VirtualTensorAddress vta_a,
                      VirtualTensorAddress vta_b,
                      VirtualTensorAddress vta_out,
                      void* output_buffer);
    
    // Slow path (builds cache entry)
    bool DispatchSlow(VirtualTensorAddress vta_a,
                      VirtualTensorAddress vta_b,
                      VirtualTensorAddress vta_out,
                      void* output_buffer);
    
    // Combined dispatch (tries fast, falls back to slow)
    bool Dispatch(VirtualTensorAddress vta_a,
                  VirtualTensorAddress vta_b,
                  VirtualTensorAddress vta_out,
                  void* output_buffer);
    
    // Pre-warm cache for known tensors
    void Prewarm(const std::vector<VirtualTensorAddress>& vtas);
    
    // Stats
    struct Stats {
        uint64_t fast_dispatches;
        uint64_t slow_dispatches;
        float fast_path_percentage;
    };
    Stats GetStats() const;

private:
    DescriptorCache* cache_;
    std::atomic<uint64_t> fast_count_{0};
    std::atomic<uint64_t> slow_count_{0};
    
    bool ValidateDescriptor(const TensorExecutionDescriptor* desc) const;
    TensorExecutionDescriptor BuildDescriptor(VirtualTensorAddress vta);
};

//============================================================================
// Kernel ID Registry
// Maps kernel types to IDs for fast lookup
//============================================================================

namespace Kernels {

enum class KernelID : uint32_t {
    INVALID = 0,
    
    // Q4 kernels
    Q4_PREPROCESSED_AVX512 = 1,
    Q4_PREPROCESSED_AVX2 = 2,
    Q4_PREPROCESSED_SCALAR = 3,
    
    // Q8 kernels
    Q8_AVX512 = 10,
    Q8_AVX2 = 11,
    Q8_SCALAR = 12,
    
    // FP16 kernels
    FP16_AVX512 = 20,
    FP16_AVX2 = 21,
    
    // FP32 kernels
    FP32_AVX512 = 30,
    FP32_AVX2 = 31,
    FP32_SCALAR = 32,
    
    // GPU kernels
    Q4_CUDA = 100,
    Q4_VULKAN = 101,
    
    MAX_KERNEL_ID
};

// Get kernel entry point by ID
void* GetKernelEntry(KernelID id);

// Get kernel descriptor by ID
KernelDesc GetKernelDesc(KernelID id);

} // namespace Kernels

} // namespace NEVM
} // namespace RawrXD
