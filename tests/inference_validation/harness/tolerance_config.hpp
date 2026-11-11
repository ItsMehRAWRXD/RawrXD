#pragma once

namespace rawrxd {
namespace validation {

/**
 * Tolerance configuration for different precision formats
 * These values are empirically determined based on quantization error
 */
struct ToleranceConfig {
    // Absolute error tolerance
    float abs_tolerance;
    
    // Relative error tolerance
    float rel_tolerance;
    
    // Maximum acceptable mismatches (0 for strict)
    size_t max_mismatches;
};

// Tolerance presets for different formats
namespace tolerances {
    // F16: Very strict - should be nearly identical
    constexpr ToleranceConfig F16 = {
        1e-5f,   // abs_tolerance
        1e-4f,   // rel_tolerance
        0        // max_mismatches
    };
    
    // Q8_0: Strict but allows some quantization error
    constexpr ToleranceConfig Q8_0 = {
        1e-4f,   // abs_tolerance
        1e-3f,   // rel_tolerance
        0        // max_mismatches
    };
    
    // Q4_0: Moderate tolerance for 4-bit quantization
    constexpr ToleranceConfig Q4_0 = {
        5e-3f,   // abs_tolerance
        5e-2f,   // rel_tolerance
        10       // max_mismatches (allow small number)
    };
    
    // Q4_K: Similar to Q4_0
    constexpr ToleranceConfig Q4_K = {
        5e-3f,   // abs_tolerance
        5e-2f,   // rel_tolerance
        10       // max_mismatches
    };
    
    // Q2_K: Very relaxed due to aggressive quantization
    constexpr ToleranceConfig Q2_K = {
        1e-2f,   // abs_tolerance
        1e-1f,   // rel_tolerance
        100      // max_mismatches
    };
}

/**
 * Get tolerance config for format name
 */
inline ToleranceConfig getTolerance(const char* format) {
    if (strcmp(format, "F16") == 0) return tolerances::F16;
    if (strcmp(format, "Q8_0") == 0) return tolerances::Q8_0;
    if (strcmp(format, "Q4_0") == 0) return tolerances::Q4_0;
    if (strcmp(format, "Q4_K") == 0) return tolerances::Q4_K;
    if (strcmp(format, "Q2_K") == 0) return tolerances::Q2_K;
    return tolerances::F16; // Default
}

} // namespace validation
} // namespace rawrxd
