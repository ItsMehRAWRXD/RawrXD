//============================================================================
// nevm_components.hpp
// RawrXD N-EVM Component Implementations
//============================================================================

#pragma once

#include "nevm_core.hpp"
#include <queue>
#include <condition_variable>
#include <thread>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Tensor Virtualizer
// Manages virtual tensor addressing and lazy loading
//============================================================================

class TensorVirtualizer {
public:
    TensorVirtualizer();
    ~TensorVirtualizer();
    
    // Map a tensor to virtual address space
    void* MapTensor(const TensorStreamDesc& desc, void* file_base);
    void UnmapTensor(void* virtual_addr);
    
    // Translate virtual to physical address
    void* Translate(void* virtual_addr);
    
    // Prefetch hint
    void Prefetch(void* virtual_addr, size_t size);
    
private:
    struct VirtualMapping {
        void* virtual_base;
        void* physical_base;
        size_t size;
        uint64_t last_access;
    };
    
    std::unordered_map<void*, VirtualMapping> mappings_;
    std::mutex mutex_;
    uint64_t next_virtual_addr_;
};

//============================================================================
// Residency Manager
// Manages memory tiers: COLD → MAPPED → RAM → VRAM → HOT
//============================================================================

class ResidencyManager {
public:
    ResidencyManager(size_t ram_budget, size_t vram_budget);
    ~ResidencyManager();
    
    // Promote/demote residency
    bool Promote(ExecutionView* view, ResidencyState target);
    bool Demote(ExecutionView* view, ResidencyState target);
    
    // Check if promotion is possible
    bool CanPromote(ResidencyState from, ResidencyState to) const;
    
    // Get current usage
    size_t GetRAMUsage() const { return ram_used_; }
    size_t GetVRAMUsage() const { return vram_used_; }
    
    // Eviction
    void EvictLRU(size_t target_ram, size_t target_vram);
    
    // Force sync
    void Sync();
    
private:
    size_t ram_budget_;
    size_t vram_budget_;
    std::atomic<size_t> ram_used_;
    std::atomic<size_t> vram_used_;
    
    struct EvictionEntry {
        ExecutionView* view;
        uint64_t last_access;
        
        bool operator<(const EvictionEntry& other) const {
            return last_access > other.last_access;  // Min-heap
        }
    };
    
    std::priority_queue<EvictionEntry> eviction_queue_;
    std::mutex queue_mutex_;
};

//============================================================================
// Codec Engine
// Compression/decompression for tensor data
//============================================================================

class CodecEngine {
public:
    CodecEngine();
    ~CodecEngine();
    
    // FP16 conversion
    void ConvertFP16ToFP32(const uint16_t* input, float* output, uint64_t count);
    void ConvertFP32ToFP16(const float* input, uint16_t* output, uint64_t count);
    
    // Quantization
    void QuantizeQ4(const float* input, uint8_t* output, uint64_t count, 
                     float scale, float zero_point);
    void DequantizeQ4(const uint8_t* input, float* output, uint64_t count,
                       float scale, float zero_point);
    
    void QuantizeQ8(const float* input, uint8_t* output, uint64_t count, float scale);
    void DequantizeQ8(const uint8_t* input, float* output, uint64_t count, float scale);
    
    // Compression
    size_t CompressLZ4(const void* input, size_t input_size, void* output, size_t output_size);
    size_t DecompressLZ4(const void* input, size_t input_size, void* output, size_t output_size);
    
    size_t CompressZSTD(const void* input, size_t input_size, void* output, size_t output_size);
    size_t DecompressZSTD(const void* input, size_t input_size, void* output, size_t output_size);
};

//============================================================================
// Kernel Dispatcher
// Dispatches to optimal kernel based on format and hardware
//============================================================================

class KernelDispatcher {
public:
    KernelDispatcher();
    ~KernelDispatcher();
    
    // GEMM operations
    void GEMM_FP32(const float* A, const float* B, float* C,
                    uint32_t M, uint32_t K, uint32_t N);
    void GEMM_FP16(const uint16_t* A, const uint16_t* B, float* C,
                    uint32_t M, uint32_t K, uint32_t N);
    void GEMM_Q4(const uint8_t* A, const float* B, float* C,
                  uint32_t M, uint32_t K, uint32_t N,
                  const float* scales, const float* zero_points);
    void GEMM_Q8(const uint8_t* A, const float* B, float* C,
                  uint32_t M, uint32_t K, uint32_t N, const float* scales);
    
    // Nano kernels
    void GEMM_NANO_LUT2(const uint8_t* indices, const float* activations,
                         float* output, const float* codebook,
                         uint32_t M, uint32_t K, uint32_t N);
    void GEMM_NANO_XNOR(const uint8_t* weights, const float* activations,
                         float* output, uint32_t M, uint32_t K, uint32_t N);
    
    // Attention kernels
    void Attention_Flash(const float* Q, const float* K, const float* V,
                          float* output, uint32_t seq_len, uint32_t head_dim);
    
    // Check capabilities
    bool HasAVX512() const { return has_avx512_; }
    bool HasAVX2() const { return has_avx2_; }
    bool HasAMX() const { return has_amx_; }
    
private:
    bool has_avx512_;
    bool has_avx2_;
    bool has_amx_;
    bool has_vnni_;
    
    void DetectFeatures();
};

} // namespace NEVM
} // namespace RawrXD
