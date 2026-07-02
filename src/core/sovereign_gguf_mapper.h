// =============================================================================
// sovereign_gguf_mapper.h
// GGUF Tensor to ModelWeights Mapping
// Maps real GGUF tensor pointers to the transformer weight structure
// =============================================================================

#ifndef SOVEREIGN_GGUF_MAPPER_H
#define SOVEREIGN_GGUF_MAPPER_H

#include "sovereign_transformer_forward.h"
#include "../RawrXD_Interfaces.h"

// Forward declaration
namespace RawrXD {
    class StreamingGGUFLoader;
}

namespace Sovereign {

// =============================================================================
// Map GGUF Tensors to ModelWeights
// =============================================================================
// 
// This function walks the GGUF tensor list and maps each tensor to the
// appropriate slot in the ModelWeights structure.
//
// Parameters:
//   loader  - Pointer to initialized StreamingGGUFLoader
//   weights - ModelWeights structure to populate
//   verbose - Print mapping details (default: true)
//
// Returns:
//   true if at least one tensor was mapped successfully
//
// Example:
//   RawrXD::StreamingGGUFLoader loader;
//   loader.Open("model.gguf");
//   loader.ParseHeader();
//   
//   Sovereign::ModelWeights weights;
//   if (MapGGUFTensorsToModelWeights(&loader, weights)) {
//       // Weights are now mapped, ready for inference
//   }
//
bool MapGGUFTensorsToModelWeights(
    RawrXD::StreamingGGUFLoader* loader,
    ModelWeights& weights,
    bool verbose = true
);

// =============================================================================
// Print Weight Map (for debugging)
// =============================================================================
// Prints a summary of all mapped weights to stdout
void PrintWeightMap(const ModelWeights& weights);

// =============================================================================
// Dry Load Test
// =============================================================================
// Runs a synthetic test of the GGUF mapping and dequantization code paths
// without requiring a real GGUF file. Useful for validation.
// Returns true if all tests pass.
bool RunDryLoadTest(bool verbose = true);

// =============================================================================
// Get GGML Type Name
// =============================================================================
// Returns human-readable name for GGML quantization types
const char* GetGGMLTypeName(::RawrXD::GGMLType type);

} // namespace Sovereign

#endif // SOVEREIGN_GGUF_MAPPER_H
