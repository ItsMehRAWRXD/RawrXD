#pragma once
#include <cstdint>
#include <cstring>
#include <iostream>
#include "TITAN_MEMORY_ALLOCATOR.hpp"

// =============================================================================
// TITAN CACHE-LINE DETERMINISTIC PACKING LAYER
// =============================================================================
// Transitions the architecture from "Optimizing Execution" to 
// "Pre-Shaping Memory into CPU-Consumable Geometry".
// 
// Takes arbitrary tensor shapes and repacks them into strictly 64-byte aligned,
// zero-padded, contiguous memory blocks perfectly tailored for the 8-lane 
// FMA interleave pattern. Guarantees 0 cache-line splits and 0 loop-tail stalls.
// =============================================================================

namespace Titan {
namespace Memory {

    // 64 floats = 256 bytes = exactly one 8-way YMM consume-stride
    constexpr size_t YMM_8WAY_STRIDE_FLOATS = 64; 

    struct PackedGeometry {
        float* data;
        size_t original_elements;
        size_t padded_elements;
        size_t allocated_bytes;
        size_t tile_count;
    };

    class CacheLinePacker {
    public:
        // Shapes a raw linear tensor into a geometry specifically designed 
        // to feed the 256-byte stride of the unrolled execution engine.
        static PackedGeometry PackVector_8xYMM(const float* raw_data, size_t elements) {
            PackedGeometry geom;
            geom.original_elements = elements;

            // Pad up to the nearest clean 8-way YMM boundary (256-byte aligned)
            size_t remainder = elements % YMM_8WAY_STRIDE_FLOATS;
            geom.padded_elements = elements;
            if (remainder != 0) {
                geom.padded_elements += (YMM_8WAY_STRIDE_FLOATS - remainder);
            }

            geom.allocated_bytes = geom.padded_elements * sizeof(float);
            geom.tile_count = geom.padded_elements / YMM_8WAY_STRIDE_FLOATS;

            // Allocate strictly aligned block
            geom.data = static_cast<float*>(AlignedAllocator::Allocate(geom.allocated_bytes, L1_CACHE_LINE_SIZE));

            // Copy original data
            std::memcpy(geom.data, raw_data, elements * sizeof(float));

            // Zero-pad the tail to prevent garbage data interacting with FMA execution,
            // entirely eliminating the need for scalar tail-loops in assembly.
            if (geom.padded_elements > elements) {
                size_t pad_bytes = (geom.padded_elements - elements) * sizeof(float);
                std::memset(geom.data + elements, 0, pad_bytes);
            }

            return geom;
        }

        static void FreeGeometry(PackedGeometry& geom) {
            AlignedAllocator::Free(geom.data);
            geom.data = nullptr;
            geom.allocated_bytes = 0;
            geom.padded_elements = 0;
            geom.tile_count = 0;
        }

        static void PrintPackingStats(const PackedGeometry& geom, const std::string& name) {
            std::cout << "=== CACHE-LINE PACKING: " << name << " ===\n"
                      << " Original Elements : " << geom.original_elements << "\n"
                      << " Padded Elements   : " << geom.padded_elements << "\n"
                      << " Padding Added     : " << (geom.padded_elements - geom.original_elements) << " floats\n"
                      << " 8-Way YMM Tiles   : " << geom.tile_count << " (Perfect Loop Iterations)\n"
                      << " Allocated Memory  : " << geom.allocated_bytes << " bytes (64-byte boundary aligned)\n"
                      << " Status            : L1 Split-Line Mode AVOIDED\n"
                      << "========================================\n";
        }
    };

} // namespace Memory
} // namespace Titan