// =============================================================================
// sovereign_gguf_tensor_mapper.h
// GGUF tensor mapping and Q3_K_S dequantization
// =============================================================================

#ifndef SOVEREIGN_GGUF_TENSOR_MAPPER_H
#define SOVEREIGN_GGUF_TENSOR_MAPPER_H

#include "sovereign_transformer_forward.h"

namespace Sovereign {

// Q3_K_S block structure for dequantization
struct Q3_K_S_Block {
    uint8_t scales[2];     // 2 bytes for block scales
    uint8_t quants[96];    // 96 bytes for 256 3-bit weights
};

// Dequantize Q3_K_S blocks to float32
// C++ fallback - MASM version would be faster
void Dequantize_Q3_K_S_Block(const Q3_K_S_Block* block, float* output, uint32_t n_elements);

// Map Llama GGUF tensors to ModelWeights structure
// Returns true on success, false on failure
bool MapLlamaGGUFTensors(void* gguf_handle, ModelWeights& weights);

// Free mapped weights
void FreeMappedWeights(ModelWeights& weights);

} // namespace Sovereign

#endif // SOVEREIGN_GGUF_TENSOR_MAPPER_H
