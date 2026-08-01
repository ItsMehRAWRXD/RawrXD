// ============================================================================
// CompressedKVCache.h - Quantized KV Cache with Q8_0/Q4_K compression
//
// VAL-000 Component: Memory Engine → KV Compression
//
// Reduces KV cache memory by 4x (Q8_0) or 8x (Q4_K) vs raw F32 storage.
// Dequantizes on-the-fly during attention computation.
//
// Memory savings (DeepSeek-V3 671B, 61 layers, 8 KV heads, 128 head_dim):
//   F32 KV:  61 * 4096 * 8 * 128 * 4 * 2 = 1.0 GB per 4K context
//   Q8_0 KV: 61 * 4096 * 8 * 128 * 1 * 2 = 256 MB (4x compression)
//   Q4_K KV: 61 * 4096 * 8 * 128 * 0.5 * 2 = 128 MB (8x compression)
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
// ============================================================================

#ifndef DEEP2_COMPRESSED_KV_CACHE_H
#define DEEP2_COMPRESSED_KV_CACHE_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace Deep2 {

// ---------------------------------------------------------------------------
// KV compression format
// ---------------------------------------------------------------------------
enum class KVQuantType {
    KV_F32,    // No compression (baseline)
    KV_Q8_0,   // 8-bit quantization (4x compression)
    KV_Q4_K,   // 4-bit K-quant (8x compression)
    KV_Q4_0    // 4-bit (8x compression, simpler)
};

// ---------------------------------------------------------------------------
// Q8_0 block (32 elements per block)
// ---------------------------------------------------------------------------
struct KVBlock_Q8_0 {
    float   d;          // scale (4 bytes)
    int8_t  qs[32];     // quantized values (32 bytes)
    // Total: 36 bytes per 32 floats (vs 128 bytes F32 = 3.56x compression)
};

// ---------------------------------------------------------------------------
// Q4_0 block (32 elements per block)
// ---------------------------------------------------------------------------
struct KVBlock_Q4_0 {
    float   d;          // scale (4 bytes)
    uint8_t qs[16];     // 32 x 4-bit packed (16 bytes)
    // Total: 20 bytes per 32 floats (vs 128 bytes F32 = 6.4x compression)
};

// ---------------------------------------------------------------------------
// Compressed KV Cache Configuration
// ---------------------------------------------------------------------------
struct CompressedKVConfig {
    size_t numLayers;
    size_t maxSeqLen;
    size_t numHeads;
    size_t numKVHeads;
    size_t headDim;
    KVQuantType quantType = KVQuantType::KV_Q8_0;
    
    // Compression ratio
    float compressionRatio() const {
        switch (quantType) {
            case KVQuantType::KV_F32:  return 1.0f;
            case KVQuantType::KV_Q8_0: return 3.56f;
            case KVQuantType::KV_Q4_K: return 8.0f;
            case KVQuantType::KV_Q4_0: return 6.4f;
        }
        return 1.0f;
    }
    
    // Compressed size per layer
    size_t compressedLayerSize() const {
        size_t elementsPerLayer = maxSeqLen * numKVHeads * headDim;
        size_t f32Size = elementsPerLayer * sizeof(float);
        return (size_t)(f32Size / compressionRatio());
    }
    
    // Total compressed size (K + V)
    size_t totalCompressedSize() const {
        return compressedLayerSize() * numLayers * 2;
    }
};

// ---------------------------------------------------------------------------
// CompressedKVCache - Quantized KV storage with on-the-fly dequantization
// ---------------------------------------------------------------------------
class CompressedKVCache {
public:
    CompressedKVCache();
    ~CompressedKVCache();
    
    // Initialize with configuration
    bool initialize(const CompressedKVConfig& config);
    
    // Store K/V for current position (compresses on store)
    void storeKV(size_t layer, size_t head, size_t pos,
                 const float* k, const float* v);
    
    // Retrieve K/V for attention (dequantizes on load)
    // Returns dequantized values into provided buffers
    void loadK(size_t layer, size_t head, size_t pos, float* kOut) const;
    void loadV(size_t layer, size_t head, size_t pos, float* vOut) const;
    
    // Batch load: dequantize all positions for a head (for attention)
    void loadKRange(size_t layer, size_t head, size_t startPos,
                    size_t count, float* kOut) const;
    void loadVRange(size_t layer, size_t head, size_t startPos,
                    size_t count, float* vOut) const;
    
    // Reset cache
    void reset();
    
    // Advance position
    void advance() { currentPos++; }
    
    // Queries
    size_t currentLength() const { return currentPos; }
    size_t maxLength() const { return config.maxSeqLen; }
    size_t memoryUsed() const;
    float  compressionRatio() const { return config.compressionRatio(); }
    
private:
    CompressedKVConfig config;
    
    // Compressed storage
    // K: [layers][seq][kvHeads][headDim] compressed
    // V: [layers][seq][kvHeads][headDim] compressed
    uint8_t* kCacheCompressed = nullptr;
    uint8_t* vCacheCompressed = nullptr;
    size_t   kCacheBytes = 0;
    size_t   vCacheBytes = 0;
    
    size_t currentPos = 0;
    bool initialized = false;
    
    // Compression helpers
    void compressQ8_0(const float* src, KVBlock_Q8_0* dst, size_t n);
    void decompressQ8_0(const KVBlock_Q8_0* src, float* dst, size_t n) const;
    void compressQ4_0(const float* src, KVBlock_Q4_0* dst, size_t n);
    void decompressQ4_0(const KVBlock_Q4_0* src, float* dst, size_t n) const;
    
    // Offset calculations
    size_t getBlockOffset(size_t layer, size_t head, size_t pos) const;
    size_t getBlocksPerHead() const;
};

} // namespace Deep2

#endif // DEEP2_COMPRESSED_KV_CACHE_H
