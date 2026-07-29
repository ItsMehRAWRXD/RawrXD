//============================================================================
// nevm_performance_profiles.hpp
// RawrXD N-EVM - Performance vs Memory Trade-off Profiles
// Pre-configured settings for different optimization targets
//============================================================================

#pragma once

#include "nevm_v2.hpp"
#include "nevm_precision_controller.hpp"
#include <string>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Performance Profile Types
//============================================================================

enum class OptimizationTarget {
    MAX_THROUGHPUT,      // Prioritize tok/s above all else
    MIN_MEMORY,          // Minimize RAM/VRAM usage
    BALANCED,            // Reasonable trade-off
    LOW_LATENCY,         // Minimize TTFT and inter-token latency
    DETERMINISTIC,       // Reproducible results
    CUSTOM               // User-defined
};

struct PerformanceProfile {
    const char* name;
    OptimizationTarget target;
    
    // Memory budgets (as fraction of available)
    float ram_budget_fraction;
    float vram_budget_fraction;
    
    // Precision settings
    PrecisionMode default_precision;
    bool enable_adaptive_precision;
    float precision_error_threshold;
    float min_precision_bits;  // Minimum acceptable precision
    
    // Residency settings
    bool aggressive_prefetch;
    int prefetch_lookahead;
    float residency_hot_threshold;
    
    // Scheduling
    bool prioritize_prefetch_over_compute;
    int max_concurrent_migrations;
    
    // Kernel selection
    bool prefer_throughput_over_latency;
    bool allow_fallback_kernels;
    
    // KV cache
    bool use_kv_cache;
    float kv_cache_quantization;  // 0.0 = FP16, 1.0 = Q8, etc.
    
    // Flash attention
    bool use_flash_attention;
    int attention_tile_size;
};

//============================================================================
// Pre-defined Profiles
//============================================================================

class ProfileRegistry {
public:
    // Maximum throughput profile
    // Uses maximum precision, aggressive prefetching, prioritizes compute
    static PerformanceProfile MaxThroughput() {
        return {
            "Maximum Throughput",
            OptimizationTarget::MAX_THROUGHPUT,
            0.95f,      // Use 95% of RAM
            0.95f,      // Use 95% of VRAM
            PrecisionMode::Q4,  // Start with Q4
            true,       // Adaptive precision on
            0.05f,      // 5% error tolerance
            2.0f,       // Min 2 bits
            true,       // Aggressive prefetch
            5,          // Lookahead 5 layers
            0.8f,       // Hot threshold
            false,      // Compute over prefetch
            8,          // Max 8 concurrent migrations
            true,       // Prefer throughput
            true,       // Allow fallbacks
            true,       // Use KV cache
            0.5f,       // Q8 KV cache
            true,       // Flash attention
            128         // Large tiles
        };
    }
    
    // Minimum memory profile
    // Uses lowest precision, minimal prefetching, quantizes aggressively
    static PerformanceProfile MinMemory() {
        return {
            "Minimum Memory",
            OptimizationTarget::MIN_MEMORY,
            0.50f,      // Use only 50% of RAM
            0.50f,      // Use only 50% of VRAM
            PrecisionMode::BINARY,  // Start with binary
            true,       // Adaptive precision on
            0.15f,      // 15% error tolerance (higher)
            0.8f,       // Min 0.8 bits (binary)
            false,      // Conservative prefetch
            2,          // Lookahead 2 layers
            0.5f,       // Lower hot threshold
            true,       // Prefetch over compute
            2,          // Max 2 concurrent migrations
            false,      // Prefer latency (smaller batches)
            false,      // No fallbacks (save memory)
            true,       // Use KV cache
            1.0f,       // Q4 KV cache (more compressed)
            false,      // No flash attention (saves memory)
            64          // Small tiles
        };
    }
    
    // Balanced profile
    // Reasonable trade-off for general use
    static PerformanceProfile Balanced() {
        return {
            "Balanced",
            OptimizationTarget::BALANCED,
            0.75f,      // Use 75% of RAM
            0.75f,      // Use 75% of VRAM
            PrecisionMode::Q4,
            true,
            0.08f,      // 8% error tolerance
            1.6f,       // Min 1.6 bits
            true,
            3,
            0.7f,
            false,
            4,
            true,
            true,
            true,
            0.5f,
            true,
            96
        };
    }
    
    // Low latency profile
    // Minimizes time to first token and inter-token latency
    static PerformanceProfile LowLatency() {
        return {
            "Low Latency",
            OptimizationTarget::LOW_LATENCY,
            0.85f,
            0.85f,
            PrecisionMode::Q8,  // Higher precision = faster per token
            false,      // Fixed precision (no switching overhead)
            0.05f,
            4.0f,       // Min 4 bits
            true,       // Prefetch everything
            10,         // Aggressive lookahead
            0.9f,       // Very hot threshold
            false,
            16,         // Many concurrent migrations
            false,      // Latency focused
            true,
            true,
            0.0f,       // FP16 KV cache (fastest)
            true,
            64          // Small tiles for parallelism
        };
    }
    
    // Deterministic profile
    // Reproducible results for benchmarking
    static PerformanceProfile Deterministic() {
        return {
            "Deterministic",
            OptimizationTarget::DETERMINISTIC,
            0.80f,
            0.80f,
            PrecisionMode::Q4,
            false,      // Fixed precision
            0.0f,
            4.0f,
            false,      // No prefetch (non-deterministic timing)
            0,
            0.5f,
            false,
            1,          // Sequential only
            false,
            true,
            true,
            0.5f,
            true,
            128
        };
    }
    
    // Apply profile to VM config
    static void ApplyProfile(NEVM_v2::Config& config, 
                          TransformerEngine::Config& engine_config,
                          const PerformanceProfile& profile) {
        // Apply memory budgets
        // (These would be set based on system detection)
        // config.ram_budget = total_ram * profile.ram_budget_fraction;
        // config.vram_budget = total_vram * profile.vram_budget_fraction;
        
        // Apply precision settings
        engine_config.default_precision = profile.default_precision;
        config.enable_adaptive_precision = profile.enable_adaptive_precision;
        
        // Apply residency settings
        config.enable_prefetch = profile.aggressive_prefetch;
        config.max_prefetch_threads = profile.max_concurrent_migrations;
        
        // Apply engine settings
        engine_config.use_flash_attention = profile.use_flash_attention;
        engine_config.use_kv_cache = profile.use_kv_cache;
    }
    
    // Get profile by name
    static PerformanceProfile GetProfile(const std::string& name) {
        if (name == "throughput" || name == "max") return MaxThroughput();
        if (name == "memory" || name == "min") return MinMemory();
        if (name == "latency" || name == "low") return LowLatency();
        if (name == "deterministic" || name == "det") return Deterministic();
        return Balanced();  // Default
    }
    
    // List available profiles
    static std::vector<std::string> ListProfiles() {
        return {
            "throughput",
            "memory",
            "balanced",
            "latency",
            "deterministic"
        };
    }
};

//============================================================================
// Profile Toggle Interface
//============================================================================

class ProfileToggle {
public:
    // Toggle between two profiles
    static void Toggle(NEVM_v2* vm, 
                      const PerformanceProfile& profile_a,
                      const PerformanceProfile& profile_b) {
        // This would dynamically reconfigure a running VM
        // For now, just log the toggle
        (void)vm;
        (void)profile_a;
        (void)profile_b;
    }
    
    // Get current profile metrics
    struct ProfileMetrics {
        float actual_throughput;
        float actual_memory_usage;
        float actual_latency;
        float efficiency_score;  // throughput / memory
    };
    
    static ProfileMetrics EvaluateProfile(const PerformanceProfile& profile) {
        // Would run benchmark and return metrics
        (void)profile;
        return {};
    }
};

} // namespace NEVM
} // namespace RawrXD
