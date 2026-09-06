#pragma once

#include "Deep2Quantization.hpp"
#include "Deep2ThreadTuning.hpp"
#include <windows.h>
#include <vector>
#include <stdexcept>

class Deep2MatrixWrapper {
public:
    /**
     * Executes a high-performance asymmetric tiled matrix-vector multiplication layer.
     * Maps packed 1.5-bit weight layouts against continuous Q8_0 activations.
     * 
     * @param weightBlocks Pointer to the contiguous array of 64-byte aligned QuantizedBlock512 structures.
     * @param totalRows Total row count (M-dimension) of the target transformation weight layer.
     * @param totalCols Total column count (K-dimension), must be a multiple of 512.
     * @param outActivations Destination FP32 pointer for final uncompressed layer activations.
     */
    static void ComputeAsymmetricLayerGEMV(
        const Deep2Quantization::QuantizedBlock512* __restrict weightBlocks,
        uint32_t totalRows,
        uint32_t totalCols,
        float* __restrict outActivations)
    {
        if (totalCols % 512 != 0) {
            throw std::invalid_argument("[-] Matrix Topology Error: Columns must align to 512-element bitplane bounds.");
        }

        uint32_t blocksPerRow = totalCols / 512;

        // Loop Tiling (M-dimension / Rows)
        // Parallelizing across our isolated compute layers via strip-mining
        // Using standard loop since OpenMP might not be configured in this bare-metal setup
        for (uint32_t r = 0; r < totalRows; ++r) {
            float rowAccumulator = 0.0f;
            uint64_t rowOffset = static_cast<uint64_t>(r) * blocksPerRow;

            // Inner Processing (K-dimension / Columns in 512-element steps)
            // Loops linearly across L1-cache lines to secure absolute streaming data locality
            for (uint32_t c = 0; c < blocksPerRow; ++c) {
                const auto& activeBlock = weightBlocks[rowOffset + c];

                // Direct linkage into the raw AVX-512 assembly kernel
                rowAccumulator += ComputeTernaryDotProduct512(
                    &activeBlock.weightPlane0,
                    &activeBlock.weightPlane1,
                    &activeBlock.activations[0],
                    activeBlock.blockScale
                );
            }

            // Store finalized node transformation out to our cache-aligned FP32 target array
            outActivations[r] = rowAccumulator;
        }
    }
};
