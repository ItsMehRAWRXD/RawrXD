#pragma once

#include <windows.h>
#include <cstdint>
#include <memory>
#include <malloc.h>

extern "C" {
    float ComputeTernaryDotProduct512(const uint64_t* bp0, const uint64_t* bp1, const int8_t* act, float scale);
}

class Deep2Quantization {
public:
    struct alignas(64) QuantizedBlock512 {
        uint64_t weightPlane0;      // 64 bits (Sign)
        uint64_t weightPlane1;      // 64 bits (Mask)
        int8_t   activations[64];   // 64 bytes of INT8 values
        float    blockScale;        // Q8_0 normalization scale
    };

    static std::shared_ptr<QuantizedBlock512> AllocateCacheAlignedBlock() {
        // Allocate raw physical blocks bound to 64-byte L1 cache-line structures
        void* rawMemory = _aligned_malloc(sizeof(QuantizedBlock512), 64);
        if (!rawMemory) {
            throw std::bad_alloc();
        }
        return std::shared_ptr<QuantizedBlock512>(
            static_cast<QuantizedBlock512*>(rawMemory),
            [](QuantizedBlock512* p) { _aligned_free(p); }
        );
    }
};
