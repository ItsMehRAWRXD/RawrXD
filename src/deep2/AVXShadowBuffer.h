// ============================================================================
// Blocker #26: AVX Alignment Shadow Buffers
// Provides 64-byte aligned shadow buffers for misaligned tensor data.
// Ensures AVX2/AVX-512 loads don't fault on unaligned memory.
// ============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <mutex>

#ifdef _WIN32
#include <malloc.h>
#else
#include <stdlib.h>
#endif

namespace Deep2 {

class AVXShadowBuffer {
public:
    ~AVXShadowBuffer() { ClearAll(); }

    // Get or create a 64-byte aligned shadow buffer for tensor data
    // Returns aligned pointer that can be safely used with AVX2/AVX-512 loads
    float* GetAlignedShadow(uint64_t tensorId, const void* data, size_t numFloats) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = shadows_.find(tensorId);
        if (it != shadows_.end()) {
            // Reuse existing shadow if size matches
            if (it->second.numFloats >= numFloats) {
                return static_cast<float*>(it->second.alignedPtr);
            }
            // Need larger buffer - free old one
            FreeShadow(it->second);
            shadows_.erase(it);
        }
        
        // Allocate new aligned shadow buffer
        ShadowEntry entry;
        entry.numFloats = numFloats;
        entry.alignedPtr = AllocateAligned(numFloats * sizeof(float), 64);
        entry.originalData = data;
        
        // Copy data to aligned buffer
        std::memcpy(entry.alignedPtr, data, numFloats * sizeof(float));
        
        float* result = reinterpret_cast<float*>(entry.alignedPtr);
        shadows_[tensorId] = std::move(entry);
        return result;
    }

    // Update shadow buffer with new data (e.g., after hotpatch)
    void UpdateShadow(uint64_t tensorId, const void* data, size_t numFloats) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = shadows_.find(tensorId);
        if (it != shadows_.end() && it->second.numFloats >= numFloats) {
            std::memcpy(it->second.alignedPtr, data, numFloats * sizeof(float));
            it->second.originalData = data;
        }
    }

    // Release shadow buffer for a tensor
    void ReleaseShadow(uint64_t tensorId) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = shadows_.find(tensorId);
        if (it != shadows_.end()) {
            FreeShadow(it->second);
            shadows_.erase(it);
        }
    }

    // Clear all shadow buffers
    void ClearAll() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& pair : shadows_) {
            FreeShadow(pair.second);
        }
        shadows_.clear();
    }

    // Check if a pointer is already 64-byte aligned
    static bool Is64ByteAligned(const void* ptr) {
        return (reinterpret_cast<uintptr_t>(ptr) & 0x3F) == 0;
    }

    // Get recommended alignment for a given instruction set
    static size_t GetRecommendedAlignment(bool useAVX512) {
        return useAVX512 ? 64 : 32;
    }

    size_t GetShadowCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shadows_.size();
    }

    size_t GetTotalShadowBytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        size_t total = 0;
        for (const auto& pair : shadows_) {
            total += pair.second.numFloats * sizeof(float);
        }
        return total;
    }

private:
    struct ShadowEntry {
        void* alignedPtr;
        const void* originalData;
        size_t numFloats;
    };

    void* AllocateAligned(size_t bytes, size_t alignment) {
#ifdef _WIN32
        return _aligned_malloc(bytes, alignment);
#else
        void* ptr = nullptr;
        posix_memalign(&ptr, alignment, bytes);
        return ptr;
#endif
    }

    void FreeShadow(ShadowEntry& entry) {
        if (entry.alignedPtr) {
#ifdef _WIN32
            _aligned_free(entry.alignedPtr);
#else
            free(entry.alignedPtr);
#endif
            entry.alignedPtr = nullptr;
        }
    }

    std::unordered_map<uint64_t, ShadowEntry> shadows_;
    mutable std::mutex mutex_;
};

} // namespace Deep2
