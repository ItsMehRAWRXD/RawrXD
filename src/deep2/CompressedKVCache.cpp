// ============================================================================
// CompressedKVCache.cpp - Implementation
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 2
// ============================================================================

#include "CompressedKVCache.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {

CompressedKVCache::CompressedKVCache() {}
CompressedKVCache::~CompressedKVCache() {
    if (kCacheCompressed) free(kCacheCompressed);
    if (vCacheCompressed) free(vCacheCompressed);
}

bool CompressedKVCache::initialize(const CompressedKVConfig& cfg) {
    config = cfg;
    
    // Calculate compressed sizes
    size_t elementsPerLayer = config.maxSeqLen * config.numKVHeads * config.headDim;
    size_t f32BytesPerLayer = elementsPerLayer * sizeof(float);
    
    float ratio = config.compressionRatio();
    kCacheBytes = (size_t)(f32BytesPerLayer / ratio);
    vCacheBytes = (size_t)(f32BytesPerLayer / ratio);
    
    // Allocate aligned
    kCacheCompressed = (uint8_t*)_aligned_malloc(kCacheBytes * config.numLayers, 64);
    vCacheCompressed = (uint8_t*)_aligned_malloc(vCacheBytes * config.numLayers, 64);
    
    if (!kCacheCompressed || !vCacheCompressed) {
        printf("[CompressedKVCache] ERROR: Failed to allocate %zu MB\n",
               (kCacheBytes + vCacheBytes) * config.numLayers / (1024*1024));
        return false;
    }
    
    memset(kCacheCompressed, 0, kCacheBytes * config.numLayers);
    memset(vCacheCompressed, 0, vCacheBytes * config.numLayers);
    
    currentPos = 0;
    initialized = true;
    
    size_t totalMB = (kCacheBytes + vCacheBytes) * config.numLayers / (1024*1024);
    size_t f32MB = (f32BytesPerLayer * 2 * config.numLayers) / (1024*1024);
    
    printf("[CompressedKVCache] Initialized: %zu MB compressed (vs %zu MB F32, %.1fx ratio)\n",
           totalMB, f32MB, ratio);
    
    return true;
}

size_t CompressedKVCache::getBlocksPerHead() const {
    // Number of blocks per head per position
    if (config.quantType == KVQuantType::KV_Q8_0) {
        return (config.headDim + 31) / 32;
    } else if (config.quantType == KVQuantType::KV_Q4_0) {
        return (config.headDim + 31) / 32;
    }
    return config.headDim;
}

size_t CompressedKVCache::getBlockOffset(size_t layer, size_t head, size_t pos) const {
    size_t blocksPerHead = getBlocksPerHead();
    size_t blockSize;
    
    if (config.quantType == KVQuantType::KV_Q8_0) {
        blockSize = sizeof(KVBlock_Q8_0);
    } else if (config.quantType == KVQuantType::KV_Q4_0) {
        blockSize = sizeof(KVBlock_Q4_0);
    } else {
        blockSize = sizeof(float);
    }
    
    // Layout: [layer][pos][head][block]
    size_t offset = layer * config.maxSeqLen * config.numKVHeads * blocksPerHead * blockSize;
    offset += pos * config.numKVHeads * blocksPerHead * blockSize;
    offset += head * blocksPerHead * blockSize;
    
    return offset;
}

void CompressedKVCache::compressQ8_0(const float* src, KVBlock_Q8_0* dst, size_t n) {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        // Find max absolute value in block
        float maxAbs = 0.0f;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) {
                maxAbs = std::max(maxAbs, std::abs(src[idx]));
            }
        }
        
        // Scale: d = maxAbs / 127
        float d = maxAbs / 127.0f;
        if (d == 0.0f) d = 1e-10f;
        dst[b].d = d;
        
        // Quantize
        float invD = 1.0f / d;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) {
                float q = src[idx] * invD;
                int qi = (int)std::round(q);
                if (qi > 127) qi = 127;
                if (qi < -128) qi = -128;
                dst[b].qs[i] = (int8_t)qi;
            } else {
                dst[b].qs[i] = 0;
            }
        }
    }
}

void CompressedKVCache::decompressQ8_0(const KVBlock_Q8_0* src, float* dst, size_t n) const {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = src[b].d;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) {
                dst[idx] = d * (float)src[b].qs[i];
            }
        }
    }
}

void CompressedKVCache::compressQ4_0(const float* src, KVBlock_Q4_0* dst, size_t n) {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float maxAbs = 0.0f;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) {
                maxAbs = std::max(maxAbs, std::abs(src[idx]));
            }
        }
        
        float d = maxAbs / 7.0f;  // 4-bit: -8 to 7
        if (d == 0.0f) d = 1e-10f;
        dst[b].d = d;
        
        float invD = 1.0f / d;
        for (int i = 0; i < 16; ++i) {
            int qi0 = 0, qi1 = 0;
            size_t idx0 = b * 32 + i * 2;
            size_t idx1 = b * 32 + i * 2 + 1;
            
            if (idx0 < n) {
                int q = (int)std::round(src[idx0] * invD) + 8;
                if (q > 15) q = 15;
                if (q < 0) q = 0;
                qi0 = q;
            }
            if (idx1 < n) {
                int q = (int)std::round(src[idx1] * invD) + 8;
                if (q > 15) q = 15;
                if (q < 0) q = 0;
                qi1 = q;
            }
            dst[b].qs[i] = (uint8_t)(qi0 | (qi1 << 4));
        }
    }
}

void CompressedKVCache::decompressQ4_0(const KVBlock_Q4_0* src, float* dst, size_t n) const {
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = src[b].d;
        for (int i = 0; i < 16; ++i) {
            uint8_t byte = src[b].qs[i];
            size_t idx0 = b * 32 + i * 2;
            size_t idx1 = b * 32 + i * 2 + 1;
            if (idx0 < n) dst[idx0] = d * ((float)(byte & 0x0F) - 8.0f);
            if (idx1 < n) dst[idx1] = d * ((float)(byte >> 4) - 8.0f);
        }
    }
}

void CompressedKVCache::storeKV(size_t layer, size_t head, size_t pos,
                                 const float* k, const float* v) {
    if (!initialized || layer >= config.numLayers || pos >= config.maxSeqLen) return;
    
    size_t kOffset = getBlockOffset(layer, head, pos);
    size_t vOffset = getBlockOffset(layer, head, pos);
    
    if (config.quantType == KVQuantType::KV_Q8_0) {
        compressQ8_0(k, reinterpret_cast<KVBlock_Q8_0*>(kCacheCompressed + kOffset),
                     config.headDim);
        compressQ8_0(v, reinterpret_cast<KVBlock_Q8_0*>(vCacheCompressed + vOffset),
                     config.headDim);
    } else if (config.quantType == KVQuantType::KV_Q4_0) {
        compressQ4_0(k, reinterpret_cast<KVBlock_Q4_0*>(kCacheCompressed + kOffset),
                     config.headDim);
        compressQ4_0(v, reinterpret_cast<KVBlock_Q4_0*>(vCacheCompressed + vOffset),
                     config.headDim);
    } else {
        // F32: direct copy
        memcpy(kCacheCompressed + kOffset, k, config.headDim * sizeof(float));
        memcpy(vCacheCompressed + vOffset, v, config.headDim * sizeof(float));
    }
}

void CompressedKVCache::loadK(size_t layer, size_t head, size_t pos, float* kOut) const {
    if (!initialized) return;
    
    size_t offset = getBlockOffset(layer, head, pos);
    
    if (config.quantType == KVQuantType::KV_Q8_0) {
        decompressQ8_0(reinterpret_cast<const KVBlock_Q8_0*>(kCacheCompressed + offset),
                       kOut, config.headDim);
    } else if (config.quantType == KVQuantType::KV_Q4_0) {
        decompressQ4_0(reinterpret_cast<const KVBlock_Q4_0*>(kCacheCompressed + offset),
                       kOut, config.headDim);
    } else {
        memcpy(kOut, kCacheCompressed + offset, config.headDim * sizeof(float));
    }
}

void CompressedKVCache::loadV(size_t layer, size_t head, size_t pos, float* vOut) const {
    if (!initialized) return;
    
    size_t offset = getBlockOffset(layer, head, pos);
    
    if (config.quantType == KVQuantType::KV_Q8_0) {
        decompressQ8_0(reinterpret_cast<const KVBlock_Q8_0*>(vCacheCompressed + offset),
                       vOut, config.headDim);
    } else if (config.quantType == KVQuantType::KV_Q4_0) {
        decompressQ4_0(reinterpret_cast<const KVBlock_Q4_0*>(vCacheCompressed + offset),
                       vOut, config.headDim);
    } else {
        memcpy(vOut, vCacheCompressed + offset, config.headDim * sizeof(float));
    }
}

void CompressedKVCache::loadKRange(size_t layer, size_t head, size_t startPos,
                                    size_t count, float* kOut) const {
    for (size_t i = 0; i < count; ++i) {
        loadK(layer, head, startPos + i, kOut + i * config.headDim);
    }
}

void CompressedKVCache::loadVRange(size_t layer, size_t head, size_t startPos,
                                    size_t count, float* vOut) const {
    for (size_t i = 0; i < count; ++i) {
        loadV(layer, head, startPos + i, vOut + i * config.headDim);
    }
}

void CompressedKVCache::reset() {
    currentPos = 0;
    if (kCacheCompressed) memset(kCacheCompressed, 0, kCacheBytes * config.numLayers);
    if (vCacheCompressed) memset(vCacheCompressed, 0, vCacheBytes * config.numLayers);
}

size_t CompressedKVCache::memoryUsed() const {
    return (kCacheBytes + vCacheBytes) * config.numLayers;
}

} // namespace Deep2