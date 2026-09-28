// =============================================================================
// sovereign_gguf_mapper.h
// GGUF Tensor to ModelWeights Mapping
// Maps real GGUF tensor pointers to the transformer weight structure
// =============================================================================

#ifndef SOVEREIGN_GGUF_MAPPER_H
#define SOVEREIGN_GGUF_MAPPER_H

#include "sovereign_transformer_forward.h"
#include "gguf_loader.h"             // RawrXD::GGUFLoader (real file-backed loader)
#include "../deep2/GGUFLoader.hpp"   // Deep2::GGMLType (real enum)
// RawrXD_Interfaces.h no longer exists. The mapper is now bound to the REAL
// production loader (RawrXD::GGUFLoader — real CreateFileA/ReadFile surface
// in gguf_loader.h). The orphaned StreamingGGUFLoader contract had no
// implementation TU and is not used.

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
    RawrXD::GGUFLoader* loader,
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
// Returns human-readable name for GGML quantization types. The real enum
// lives in namespace Deep2 (src/deep2/GGUFLoader.hpp) — the old
// ::RawrXD::GGMLType no longer exists.
const char* GetGGMLTypeName(Deep2::GGMLType type);

} // namespace Sovereign

#endif // SOVEREIGN_GGUF_MAPPER_H
