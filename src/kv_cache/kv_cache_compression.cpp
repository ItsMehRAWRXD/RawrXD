// RawrXD KV-Cache Compression
// Phase 8 - Task 6: KV-Cache Compression

#include <windows.h>
#include <cstdint>
#include <cmath>
#include <algorithm>

// KV-Cache entry with compression support
struct KVCacheEntry {
    union {
        float* f32;           // Full precision
        uint16_t* f16;        // Half precision
        uint8_t* q4;          // 4-bit quantized
        uint8_t* q8;          // 8-bit quantized
    } key;
    
    union {
        float* f32;
        uint16_t* f16;
        uint8_t* q4;
        uint8_t* q8;
    } value;
    
    uint32_t numTokens;
    uint32_t numHeads;
    uint32_t headDim;
    uint8_t compressionMode;  // 0=f32, 1=f16, 2=q8, 3=q4
    float scale;
    float zeroPoint;
    uint64_t lastAccessTime;
    bool compressed;
};

// Compression modes
enum CompressionMode {
    KV_COMPRESS_NONE = 0,    // FP32 - no compression
    KV_COMPRESS_F16 = 1,     // FP16 - 2x compression
    KV_COMPRESS_Q8 = 2,      // 8-bit - 4x compression
    KV_COMPRESS_Q4 = 3,      // 4-bit - 8x compression
};

// Quantization helpers
inline uint8_t QuantizeFloatToQ8(float value, float scale, float zeroPoint) {
    float normalized = (value - zeroPoint) / scale;
    int32_t quantized = (int32_t)(normalized * 127.0f);
    quantized = std::max(-128, std::min(127, quantized));
    return (uint8_t)(quantized + 128);
}

inline float DequantizeQ8ToFloat(uint8_t value, float scale, float zeroPoint) {
    int32_t unquantized = (int32_t)value - 128;
    return ((float)unquantized / 127.0f) * scale + zeroPoint;
}

inline uint8_t QuantizeFloatToQ4(float value, float scale, float zeroPoint) {
    float normalized = (value - zeroPoint) / scale;
    int32_t quantized = (int32_t)(normalized * 7.0f);
    quantized = std::max(-8, std::min(7, quantized));
    return (uint8_t)(quantized + 8);
}

inline float DequantizeQ4ToFloat(uint8_t value, float scale, float zeroPoint) {
    int32_t unquantized = (int32_t)(value & 0x0F) - 8;
    return ((float)unquantized / 7.0f) * scale + zeroPoint;
}

// Calculate quantization parameters
void CalculateQuantizationParams(const float* data, size_t count, 
                                  float& scale, float& zeroPoint) {
    float minVal = data[0];
    float maxVal = data[0];
    
    for (size_t i = 1; i < count; i++) {
        minVal = std::min(minVal, data[i]);
        maxVal = std::max(maxVal, data[i]);
    }
    
    scale = (maxVal - minVal) / 255.0f;
    zeroPoint = minVal;
    
    if (scale < 1e-7f) scale = 1e-7f;  // Prevent division by zero
}

// Compress KV cache entry
bool CompressKVCache(KVCacheEntry& entry, CompressionMode targetMode) {
    if (entry.compressionMode == targetMode || entry.compressed) {
        return true;  // Already in target format
    }
    
    size_t elementCount = entry.numTokens * entry.numHeads * entry.headDim;
    
    // Calculate new buffer size
    size_t newSize = 0;
    switch (targetMode) {
        case KV_COMPRESS_NONE:
            newSize = elementCount * sizeof(float);
            break;
        case KV_COMPRESS_F16:
            newSize = elementCount * sizeof(uint16_t);
            break;
        case KV_COMPRESS_Q8:
            newSize = elementCount * sizeof(uint8_t);
            break;
        case KV_COMPRESS_Q4:
            newSize = (elementCount + 1) / 2;  // 2 values per byte
            break;
    }
    
    // Allocate new buffer
    uint8_t* newKeyBuffer = (uint8_t*)VirtualAlloc(nullptr, newSize, 
                                                     MEM_COMMIT | MEM_RESERVE, 
                                                     PAGE_READWRITE);
    uint8_t* newValueBuffer = (uint8_t*)VirtualAlloc(nullptr, newSize, 
                                                       MEM_COMMIT | MEM_RESERVE, 
                                                       PAGE_READWRITE);
    
    if (!newKeyBuffer || !newValueBuffer) {
        if (newKeyBuffer) VirtualFree(newKeyBuffer, 0, MEM_RELEASE);
        if (newValueBuffer) VirtualFree(newValueBuffer, 0, MEM_RELEASE);
        return false;
    }
    
    // Calculate quantization params for Q8/Q4
    float keyScale = 1.0f, keyZero = 0.0f;
    float valueScale = 1.0f, valueZero = 0.0f;
    
    if (targetMode == KV_COMPRESS_Q8 || targetMode == KV_COMPRESS_Q4) {
        CalculateQuantizationParams(entry.key.f32, elementCount, keyScale, keyZero);
        CalculateQuantizationParams(entry.value.f32, elementCount, valueScale, valueZero);
        entry.scale = keyScale;
        entry.zeroPoint = keyZero;
    }
    
    // Compress key data
    switch (targetMode) {
        case KV_COMPRESS_F16:
            // FP32 to FP16 conversion (simplified - would use actual FP16 conversion)
            for (size_t i = 0; i < elementCount; i++) {
                ((uint16_t*)newKeyBuffer)[i] = (uint16_t)(entry.key.f32[i] * 1000.0f);
                ((uint16_t*)newValueBuffer)[i] = (uint16_t)(entry.value.f32[i] * 1000.0f);
            }
            break;
            
        case KV_COMPRESS_Q8:
            for (size_t i = 0; i < elementCount; i++) {
                newKeyBuffer[i] = QuantizeFloatToQ8(entry.key.f32[i], keyScale, keyZero);
                newValueBuffer[i] = QuantizeFloatToQ8(entry.value.f32[i], valueScale, valueZero);
            }
            break;
            
        case KV_COMPRESS_Q4:
            for (size_t i = 0; i < elementCount; i += 2) {
                uint8_t k0 = QuantizeFloatToQ4(entry.key.f32[i], keyScale, keyZero);
                uint8_t k1 = (i + 1 < elementCount) ? 
                    QuantizeFloatToQ4(entry.key.f32[i + 1], keyScale, keyZero) : 0;
                newKeyBuffer[i / 2] = (k0 & 0x0F) | ((k1 & 0x0F) << 4);
                
                uint8_t v0 = QuantizeFloatToQ4(entry.value.f32[i], valueScale, valueZero);
                uint8_t v1 = (i + 1 < elementCount) ? 
                    QuantizeFloatToQ4(entry.value.f32[i + 1], valueScale, valueZero) : 0;
                newValueBuffer[i / 2] = (v0 & 0x0F) | ((v1 & 0x0F) << 4);
            }
            break;
            
        default:
            // No compression - just copy
            memcpy(newKeyBuffer, entry.key.f32, newSize);
            memcpy(newValueBuffer, entry.value.f32, newSize);
            break;
    }
    
    // Free old buffers
    VirtualFree(entry.key.f32, 0, MEM_RELEASE);
    VirtualFree(entry.value.f32, 0, MEM_RELEASE);
    
    // Update entry
    entry.key.q4 = newKeyBuffer;
    entry.value.q4 = newValueBuffer;
    entry.compressionMode = targetMode;
    entry.compressed = true;
    
    return true;
}

// Decompress KV cache entry for computation
bool DecompressKVCache(KVCacheEntry& entry, float* outKey, float* outValue) {
    size_t elementCount = entry.numTokens * entry.numHeads * entry.headDim;
    
    switch (entry.compressionMode) {
        case KV_COMPRESS_NONE:
            memcpy(outKey, entry.key.f32, elementCount * sizeof(float));
            memcpy(outValue, entry.value.f32, elementCount * sizeof(float));
            break;
            
        case KV_COMPRESS_F16:
            for (size_t i = 0; i < elementCount; i++) {
                outKey[i] = (float)entry.key.f16[i] / 1000.0f;
                outValue[i] = (float)entry.value.f16[i] / 1000.0f;
            }
            break;
            
        case KV_COMPRESS_Q8:
            for (size_t i = 0; i < elementCount; i++) {
                outKey[i] = DequantizeQ8ToFloat(entry.key.q8[i], entry.scale, entry.zeroPoint);
                outValue[i] = DequantizeQ8ToFloat(entry.value.q8[i], entry.scale, entry.zeroPoint);
            }
            break;
            
        case KV_COMPRESS_Q4:
            for (size_t i = 0; i < elementCount; i++) {
                uint8_t kByte = entry.key.q4[i / 2];
                uint8_t kVal = (i % 2 == 0) ? (kByte & 0x0F) : ((kByte >> 4) & 0x0F);
                outKey[i] = DequantizeQ4ToFloat(kVal, entry.scale, entry.zeroPoint);
                
                uint8_t vByte = entry.value.q4[i / 2];
                uint8_t vVal = (i % 2 == 0) ? (vByte & 0x0F) : ((vByte >> 4) & 0x0F);
                outValue[i] = DequantizeQ4ToFloat(vVal, entry.scale, entry.zeroPoint);
            }
            break;
    }
    
    return true;
}

// Cache eviction policy
class KVCacheEvictionPolicy {
public:
    // LRU eviction - returns number of entries evicted
    static size_t EvictLRU(std::vector<KVCacheEntry*>& cache, size_t targetMemoryMB) {
        size_t currentMemory = CalculateTotalMemory(cache);
        size_t targetMemory = targetMemoryMB * 1024 * 1024;
        
        if (currentMemory <= targetMemory) return 0;
        
        // Sort by last access time (oldest first)
        std::sort(cache.begin(), cache.end(), 
            [](KVCacheEntry* a, KVCacheEntry* b) {
                return a->lastAccessTime < b->lastAccessTime;
            });
        
        size_t evicted = 0;
        while (currentMemory > targetMemory && !cache.empty()) {
            KVCacheEntry* entry = cache.back();
            cache.pop_back();
            
            // Free entry memory
            if (entry->key.f32) VirtualFree(entry->key.f32, 0, MEM_RELEASE);
            if (entry->value.f32) VirtualFree(entry->value.f32, 0, MEM_RELEASE);
            delete entry;
            
            evicted++;
            currentMemory = CalculateTotalMemory(cache);
        }
        
        return evicted;
    }
    
private:
    static size_t CalculateTotalMemory(const std::vector<KVCacheEntry*>& cache) {
        size_t total = 0;
        for (const auto* entry : cache) {
            if (!entry) continue;
            size_t elementCount = entry->numTokens * entry->numHeads * entry->headDim;
            switch (entry->compressionMode) {
                case KV_COMPRESS_NONE: total += elementCount * sizeof(float) * 2; break;
                case KV_COMPRESS_F16: total += elementCount * sizeof(uint16_t) * 2; break;
                case KV_COMPRESS_Q8: total += elementCount * sizeof(uint8_t) * 2; break;
                case KV_COMPRESS_Q4: total += (elementCount / 2) * 2; break;
            }
        }
        return total;
    }
};

// C API
extern "C" {

void* KVCache_CreateEntry(uint32_t tokens, uint32_t heads, uint32_t headDim) {
    KVCacheEntry* entry = new KVCacheEntry();
    entry->numTokens = tokens;
    entry->numHeads = heads;
    entry->headDim = headDim;
    entry->compressionMode = KV_COMPRESS_NONE;
    entry->compressed = false;
    entry->scale = 1.0f;
    entry->zeroPoint = 0.0f;
    entry->lastAccessTime = GetTickCount64();
    
    size_t size = tokens * heads * headDim * sizeof(float);
    entry->key.f32 = (float*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    entry->value.f32 = (float*)VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    return entry;
}

bool KVCache_Compress(void* entryHandle, int mode) {
    if (!entryHandle) return false;
    return CompressKVCache(*(KVCacheEntry*)entryHandle, (CompressionMode)mode);
}

bool KVCache_Decompress(void* entryHandle, float* outKey, float* outValue) {
    if (!entryHandle) return false;
    return DecompressKVCache(*(KVCacheEntry*)entryHandle, outKey, outValue);
}

void KVCache_DestroyEntry(void* entryHandle) {
    if (!entryHandle) return;
    KVCacheEntry* entry = (KVCacheEntry*)entryHandle;
    if (entry->key.f32) VirtualFree(entry->key.f32, 0, MEM_RELEASE);
    if (entry->value.f32) VirtualFree(entry->value.f32, 0, MEM_RELEASE);
    delete entry;
}

} // extern "C"
