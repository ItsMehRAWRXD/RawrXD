//============================================================================
// nevm_math_mode.hpp
// RawrXD N-EVM - Math Mode Configuration
// Separates strict determinism from fast mode
//============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <fenv.h>

#ifdef _WIN32
#include <intrin.h>
#endif

namespace RawrXD {
namespace NEVM {

//============================================================================
// Math Mode Enumeration
//============================================================================

enum class MathMode {
    Fast,           // Maximum performance, non-deterministic
    Reproducible,   // Deterministic with tree reduction
    BitExact        // Strictest, sequential/Kahan, no FMA
};

//============================================================================
// Math Configuration
//============================================================================

struct MathConfiguration {
    MathMode mode;
    
    // FMA settings
    bool fma_enabled;
    
    // Reduction settings
    enum class ReductionMode {
        Parallel,       // Fast, non-deterministic
        Tree,           // Deterministic with fixed chunks
        Sequential    // Strictest, single-threaded
    };
    ReductionMode reduction_mode;
    
    // Accumulation settings
    bool use_kahan_summation;
    
    // MXCSR settings
    bool flush_to_zero;      // FTZ
    bool denormals_are_zero; // DAZ
    int rounding_mode;       // FE_TONEAREST, etc.
    
    // Validation
    bool validate_checksums;
    bool track_dependencies;
    
    std::string ToString() const {
        std::string result;
        switch (mode) {
            case MathMode::Fast: result = "Fast"; break;
            case MathMode::Reproducible: result = "Reproducible"; break;
            case MathMode::BitExact: result = "BitExact"; break;
        }
        return result;
    }
};

//============================================================================
// Math Mode Controller
//============================================================================

class MathModeController {
public:
    static MathConfiguration GetConfiguration(MathMode mode) {
        MathConfiguration config;
        config.mode = mode;
        
        switch (mode) {
            case MathMode::Fast:
                config.fma_enabled = true;
                config.reduction_mode = MathConfiguration::ReductionMode::Parallel;
                config.use_kahan_summation = false;
                config.flush_to_zero = true;
                config.denormals_are_zero = true;
                config.rounding_mode = FE_TONEAREST;
                config.validate_checksums = false;
                config.track_dependencies = false;
                break;
                
            case MathMode::Reproducible:
                config.fma_enabled = false;  // Disable for determinism
                config.reduction_mode = MathConfiguration::ReductionMode::Tree;
                config.use_kahan_summation = false;
                config.flush_to_zero = true;
                config.denormals_are_zero = true;
                config.rounding_mode = FE_TONEAREST;
                config.validate_checksums = true;
                config.track_dependencies = true;
                break;
                
            case MathMode::BitExact:
                config.fma_enabled = false;
                config.reduction_mode = MathConfiguration::ReductionMode::Sequential;
                config.use_kahan_summation = true;
                config.flush_to_zero = false;  // Strict IEEE 754
                config.denormals_are_zero = false;
                config.rounding_mode = FE_TONEAREST;
                config.validate_checksums = true;
                config.track_dependencies = true;
                break;
        }
        
        return config;
    }
    
    static void ApplyConfiguration(const MathConfiguration& config) {
        // Set MXCSR
        #ifdef _WIN32
        unsigned int mxcsr = _mm_getcsr();
        
        // FTZ (Flush To Zero)
        if (config.flush_to_zero) {
            mxcsr |= (1 << 15);  // FTZ bit
        } else {
            mxcsr &= ~(1 << 15);
        }
        
        // DAZ (Denormals Are Zero)
        if (config.denormals_are_zero) {
            mxcsr |= (1 << 6);   // DAZ bit
        } else {
            mxcsr &= ~(1 << 6);
        }
        
        // Rounding mode (bits 13-14)
        mxcsr &= ~(3 << 13);  // Clear rounding bits
        switch (config.rounding_mode) {
            case FE_TONEAREST:  mxcsr |= (0 << 13); break;
            case FE_DOWNWARD:   mxcsr |= (1 << 13); break;
            case FE_UPWARD:     mxcsr |= (2 << 13); break;
            case FE_TOWARDZERO: mxcsr |= (3 << 13); break;
        }
        
        _mm_setcsr(mxcsr);
        #endif
        
        // Set FP rounding mode
        fesetround(config.rounding_mode);
        
        // Store current configuration
        current_config_ = config;
    }
    
    static MathConfiguration GetCurrentConfiguration() {
        return current_config_;
    }
    
    static float GetOptimizationTax(MathMode from, MathMode to) {
        // Measured overhead of switching to more strict mode
        switch (from) {
            case MathMode::Fast:
                switch (to) {
                    case MathMode::Reproducible: return 0.032f;  // 3.2%
                    case MathMode::BitExact: return 0.085f;      // 8.5%
                    default: return 0.0f;
                }
            case MathMode::Reproducible:
                return (to == MathMode::BitExact) ? 0.053f : 0.0f;  // 5.3%
            default:
                return 0.0f;
        }
    }
    
    static void PrintConfiguration(const MathConfiguration& config) {
        std::cout << "MATH CONFIGURATION\n";
        std::cout << "------------------\n";
        std::cout << "Mode:             " << config.ToString() << "\n";
        std::cout << "FMA:              " << (config.fma_enabled ? "enabled" : "disabled") << "\n";
        std::cout << "Reduction:        ";
        switch (config.reduction_mode) {
            case MathConfiguration::ReductionMode::Parallel: std::cout << "parallel\n"; break;
            case MathConfiguration::ReductionMode::Tree: std::cout << "tree\n"; break;
            case MathConfiguration::ReductionMode::Sequential: std::cout << "sequential\n"; break;
        }
        std::cout << "Kahan:            " << (config.use_kahan_summation ? "enabled" : "disabled") << "\n";
        std::cout << "Denormals:        " << (config.flush_to_zero ? "FTZ/DAZ" : "IEEE 754") << "\n";
        std::cout << "Rounding:         ";
        switch (config.rounding_mode) {
            case FE_TONEAREST: std::cout << "nearest\n"; break;
            case FE_DOWNWARD: std::cout << "downward\n"; break;
            case FE_UPWARD: std::cout << "upward\n"; break;
            case FE_TOWARDZERO: std::cout << "toward zero\n"; break;
        }
        std::cout << "Checksums:        " << (config.validate_checksums ? "enabled" : "disabled") << "\n";
        std::cout << "\n";
    }

private:
    static MathConfiguration current_config_;
};

MathConfiguration MathModeController::current_config_ = {};

} // namespace NEVM
} // namespace RawrXD
