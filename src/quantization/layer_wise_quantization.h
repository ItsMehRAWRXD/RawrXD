// =============================================================================
// layer_wise_quantization.h
// Mixed-Precision Quantization Header
// =============================================================================

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Forward declaration for ggml_type
enum ggml_type;

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Configuration API
// =============================================================================

// Set quantization type for a specific layer
__declspec(dllexport) void LayerQuant_SetLayerType(uint32_t layer_idx, int type);

// Get quantization type for a specific layer
__declspec(dllexport) int LayerQuant_GetLayerType(uint32_t layer_idx);

// Enable/disable mixed precision (disable = all Q4_K)
__declspec(dllexport) void LayerQuant_EnableMixedPrecision(bool enable);

// Get estimated memory savings in GB
__declspec(dllexport) float LayerQuant_GetEstimatedSavingsGB(void);

// Get configuration as string (for debugging)
__declspec(dllexport) void LayerQuant_GetConfigString(char* out_buffer, size_t buffer_size);

// Load a preset configuration
__declspec(dllexport) void LayerQuant_LoadPreset(const char* preset_name);

// =============================================================================
// Presets
// =============================================================================

#define LAYER_QUANT_PRESET_QUALITY     "quality"      // All Q4_K
#define LAYER_QUANT_PRESET_BALANCED    "balanced"     // Mixed Q4_K/Q3_K
#define LAYER_QUANT_PRESET_SPEED       "speed"        // More Q3_K
#define LAYER_QUANT_PRESET_AGGRESSIVE  "aggressive"   // Maximum compression

// =============================================================================
// Constants
// =============================================================================

#define LAYER_QUANT_DEFAULT_LAYERS      32
#define LAYER_QUANT_Q4K_BITS            45   // 4.5 bits per weight
#define LAYER_QUANT_Q3K_BITS            34   // 3.4 bits per weight
#define LAYER_QUANT_Q2K_BITS            27   // 2.7 bits per weight

#ifdef __cplusplus
}
#endif
