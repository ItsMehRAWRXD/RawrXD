//============================================================================
// nevm_math_mode.cpp
// RawrXD N-EVM - Math Mode Controller Implementation
//============================================================================

#include "nevm_math_mode.hpp"
#include <iostream>
#include <intrin.h>

namespace RawrXD {
namespace NEVM {

MathModeConfiguration MathModeController::GetConfiguration(MathMode mode) {
    MathModeConfiguration config;
    config.mode = mode;
    
    switch (mode) {
        case MathMode::Fast:
            config.fma_enabled = true;
            config.parallel_reduction = true;
            config.tree_reduction = false;
            config.sequential_final = false;
            config.kahan_summation = false;
            config.mxcsr = 0x00001F80;  // Default MXCSR
            break;
            
        case MathMode::Reproducible:
            config.fma_enabled = false;
            config.parallel_reduction = true;
            config.tree_reduction = true;
            config.sequential_final = true;
            config.kahan_summation = false;
            config.mxcsr = 0x00001F80 | 0x00008000 | 0x00000040;  // FTZ + DAZ
            break;
            
        case MathMode::BitExact:
            config.fma_enabled = false;
            config.parallel_reduction = false;
            config.tree_reduction = false;
            config.sequential_final = true;
            config.kahan_summation = true;
            config.mxcsr = 0x00001F80 | 0x00008000 | 0x00000040;  // FTZ + DAZ
            break;
    }
    
    return config;
}

void MathModeController::ApplyConfiguration(const MathModeConfiguration& config) {
    // Set MXCSR for floating-point control
    _mm_setcsr(config.mxcsr);
    
    // Store current configuration
    current_config_ = config;
}

void MathModeController::PrintConfiguration(const MathModeConfiguration& config) {
    std::cout << "Math Mode Configuration:\n";
    std::cout << "  Mode: " << config.ToString() << "\n";
    std::cout << "  FMA: " << (config.fma_enabled ? "enabled" : "disabled") << "\n";
    std::cout << "  Parallel Reduction: " << (config.parallel_reduction ? "yes" : "no") << "\n";
    std::cout << "  Tree Reduction: " << (config.tree_reduction ? "yes" : "no") << "\n";
    std::cout << "  Sequential Final: " << (config.sequential_final ? "yes" : "no") << "\n";
    std::cout << "  Kahan Summation: " << (config.kahan_summation ? "yes" : "no") << "\n";
    std::cout << "  MXCSR: 0x" << std::hex << config.mxcsr << std::dec << "\n\n";
}

float MathModeController::GetOptimizationTax(MathMode from, MathMode to) {
    if (from == to) return 0.0f;
    
    if (from == MathMode::Fast && to == MathMode::Reproducible) {
        return 3.2f;
    }
    if (from == MathMode::Reproducible && to == MathMode::BitExact) {
        return 5.3f;
    }
    if (from == MathMode::Fast && to == MathMode::BitExact) {
        return 8.5f;
    }
    
    return 0.0f;
}

MathModeConfiguration MathModeController::current_config_;

} // namespace NEVM
} // namespace RawrXD
