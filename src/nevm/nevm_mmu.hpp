//============================================================================
// nevm_mmu.hpp
// RawrXD N-EVM Neural Memory Management Unit
// Virtual Tensor Address → Physical Translation
//============================================================================

#pragma once

#include "nevm_core.hpp"
#include "nevm_isa.hpp"
#include <unordered_map>
#include <mutex>
#include <shared_mutex>

namespace RawrXD {
namespace NEVM {

using ISA::VirtualTensorAddress;
using ISA::BlockState;
using ISA::PrecisionMode;
using ISA::ResidencyTarget;

//============================================================================
// Neural MMU
// Translates virtual tensor addresses to physical memory
// Manages multi-state tensor representations
//============================================================================

class NeuralMMU {
public:
    struct Config {
        size_t ram_budget;
        size_t vram_budget;
        size_t cache_budget;
        size_t block_size;          // Default: 4MB blocks
        float eviction_threshold;   // When to evict (0.0-1.0)
    };
    
    explicit NeuralMMU(const Config& config);
    ~NeuralMMU();
    
    // Disable copy/move
    NeuralMMU(const NeuralMMU&) = delete;
    NeuralMMU& operator=(const NeuralMMU&) = delete;
    
    // Virtual Address Translation
    // Returns physical pointer or nullptr if not resident
    void* Translate(VirtualTensorAddress vta, bool allocate_if_missing = true);
    
    // Block-level operations
    bool LoadBlock(VirtualTensorAddress vta, const void* source_data, size_t size);
    bool EvictBlock(VirtualTensorAddress vta);
    bool PromoteBlock(VirtualTensorAddress vta, PrecisionMode target_format);
    bool IsResident(VirtualTensorAddress vta) const;
    
    // Multi-state representation
    bool AddRepresentation(VirtualTensorAddress vta, PrecisionMode format, 
                           const void* data, size_t size);
    bool SelectRepresentation(VirtualTensorAddress vta, PrecisionMode format);
    PrecisionMode GetCurrentFormat(VirtualTensorAddress vta) const;
    
    // Memory pressure management
    void EvictLRU(size_t target_bytes);
    void CompactMemory();
    
    // Statistics
    struct Stats {
        uint64_t translations;
        uint64_t tlb_hits;
        uint64_t tlb_misses;
        uint64_t page_faults;
        uint64_t blocks_loaded;
        uint64_t blocks_evicted;
        size_t ram_used;
        size_t vram_used;
        size_t cache_used;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    
    // Translation Lookaside Buffer (TLB)
    // Maps block keys to BlockState
    struct TLBEntry {
        BlockState state;
        uint64_t last_access;
    };
    
    std::unordered_map<uint64_t, TLBEntry> tlb_;
    mutable std::shared_mutex tlb_mutex_;
    
    // Physical memory allocators
    struct MemoryPool {
        void* base;
        size_t size;
        size_t used;
        std::vector<std::pair<void*, size_t>> free_list;
    };
    
    MemoryPool ram_pool_;
    MemoryPool vram_pool_;
    MemoryPool cache_pool_;
    
    // Statistics
    mutable Stats stats_;
    mutable std::mutex stats_mutex_;
    
    // Private methods
    void* AllocatePhysical(ResidencyTarget target, size_t size);
    void FreePhysical(ResidencyTarget target, void* ptr, size_t size);
    bool EnsureResidency(VirtualTensorAddress vta, ResidencyTarget min_residency);
    uint64_t GetTick() const;
};

//============================================================================
// Block Decoder Interface
// Pluggable decoder for different formats
//============================================================================

class BlockDecoder {
public:
    virtual ~BlockDecoder() = default;
    
    // Decode block from source format to FP32
    virtual bool Decode(const void* source, size_t source_size,
                        PrecisionMode source_format,
                        float* output, size_t output_count) = 0;
    
    // Encode block from FP32 to target format
    virtual bool Encode(const float* input, size_t input_count,
                        void* output, size_t output_size,
                        PrecisionMode target_format) = 0;
    
    // Get decoded size for a given format
    virtual size_t GetDecodedSize(size_t element_count) const = 0;
    
    // Check if this decoder supports the format
    virtual bool SupportsFormat(PrecisionMode format) const = 0;
};

//============================================================================
// Decoder Registry
// Factory for block decoders
//============================================================================

class DecoderRegistry {
public:
    static DecoderRegistry& Instance();
    
    void RegisterDecoder(PrecisionMode format, std::unique_ptr<BlockDecoder> decoder);
    BlockDecoder* GetDecoder(PrecisionMode format) const;
    
private:
    DecoderRegistry() = default;
    std::unordered_map<PrecisionMode, std::unique_ptr<BlockDecoder>> decoders_;
    mutable std::shared_mutex mutex_;
};

//============================================================================
// GGUF Passthrough Decoder
// Reads GGUF blocks without conversion
//============================================================================

class GGUFBlockDecoder : public BlockDecoder {
public:
    GGUFBlockDecoder();
    ~GGUFBlockDecoder() override;
    
    bool Decode(const void* source, size_t source_size,
                PrecisionMode source_format,
                float* output, size_t output_count) override;
    
    bool Encode(const float* input, size_t input_count,
                void* output, size_t output_size,
                PrecisionMode target_format) override;
    
    size_t GetDecodedSize(size_t element_count) const override;
    bool SupportsFormat(PrecisionMode format) const override;
};

//============================================================================
// Nano Adaptive Decoder
// Multi-state representation decoder
//============================================================================

class NanoAdaptiveDecoder : public BlockDecoder {
public:
    struct StateConfig {
        PrecisionMode base_format;
        PrecisionMode residual_format;
        float sparsity_threshold;
    };
    
    explicit NanoAdaptiveDecoder(const StateConfig& config);
    ~NanoAdaptiveDecoder() override;
    
    bool Decode(const void* source, size_t source_size,
                PrecisionMode source_format,
                float* output, size_t output_count) override;
    
    bool Encode(const float* input, size_t input_count,
                void* output, size_t output_size,
                PrecisionMode target_format) override;
    
    size_t GetDecodedSize(size_t element_count) const override;
    bool SupportsFormat(PrecisionMode format) const override;
    
    // Multi-state specific
    bool DecodeState(const void* source, size_t source_size,
                     int state_level, float* output, size_t output_count);
    
private:
    StateConfig config_;
};

} // namespace NEVM
} // namespace RawrXD
