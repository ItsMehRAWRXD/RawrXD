//=============================================================================
// Memory Architecture Analysis - Hardware Reality Check
// Dual 800B Model Feasibility Study
//=============================================================================
#pragma once

#include <cstdint>
#include <cstddef>

namespace RawrXD {
namespace Hardware {

//=============================================================================
// Hardware Constraints - The "Wall"
//=============================================================================

struct HardwareLimits {
    // System Configuration
    static constexpr size_t kSystemRAM = 64ULL * 1024 * 1024 * 1024;  // 64 GB
    static constexpr size_t kUsableRAM = 48ULL * 1024 * 1024 * 1024; // ~48 GB (OS overhead)
    
    // PCIe 5.0 x16 Bandwidth
    static constexpr double kPCIe5Bandwidth = 63.0;  // GB/s theoretical
    static constexpr double kPCIe5Effective = 12.0; // GB/s effective (protocol overhead)
    
    // NVMe Gen5
    static constexpr double kNVMeSeqRead = 14.0;   // GB/s sequential
    static constexpr double kNVMeRandomRead = 0.5;   // GB/s random (kills performance)
    
    // Memory Bandwidth (DDR5-5600)
    static constexpr double kDDR5Bandwidth = 89.0;  // GB/s theoretical
    static constexpr double kDDREffective = 70.0;    // GB/s effective
    
    // L3 Cache (Ryzen 7800X3D)
    static constexpr size_t kL3CacheSize = 96ULL * 1024 * 1024;  // 96 MB
    static constexpr double kL3Bandwidth = 300.0;     // GB/s
    
    // Required for 800B Model Inference
    static constexpr double kRequiredMemBW = 500.0;  // GB/s (for real-time)
};

//=============================================================================
// Model Size Calculations
//=============================================================================

struct ModelRequirements {
    // 800B Parameter Model @ Various Quantizations
    
    // FP16: 800B × 2 bytes = 1.6 TB (impossible)
    static constexpr size_t k800B_FP16 = 1600ULL * 1024 * 1024 * 1024;
    
    // Q4_0: 800B × 0.5 bytes = 400 GB (impossible)
    static constexpr size_t k800B_Q4 = 400ULL * 1024 * 1024 * 1024;
    
    // Q2_K: 800B × 0.25 bytes = 200 GB (impossible)
    static constexpr size_t k800B_Q2 = 200ULL * 1024 * 1024 * 1024;
    
    // 0.8-bit (extreme): 800B × 0.1 bytes = 80 GB (theoretical minimum)
    static constexpr size_t k800B_08bit = 80ULL * 1024 * 1024 * 1024;
    
    // Dual Model Requirement
    static constexpr size_t kDual800B_08bit = 160ULL * 1024 * 1024 * 1024;
};

//=============================================================================
// Feasibility Analysis
//=============================================================================

class FeasibilityAnalyzer {
public:
    // Check if configuration is physically possible
    static bool IsPhysicallyPossible(size_t model_size_gb, int num_models);
    
    // Calculate expected tokens per second given constraints
    static double CalculateExpectedTPS(
        size_t model_size,
        double memory_bandwidth,
        double pcie_bandwidth,
        bool is_streaming
    );
    
    // Memory pressure analysis
    struct MemoryPressure {
        double ram_utilization;      // 0.0 - 1.0
        double cache_hit_rate;      // Estimated
        double page_fault_rate;     // faults/second
        bool will_thrash;           // true if catastrophic
    };
    static MemoryPressure AnalyzeMemoryPressure(
        size_t total_model_size,
        size_t active_context_size,
        size_t available_ram
    );
    
    // The "Wall" - when physics stops you
    static bool HitsMemoryWall(
        size_t model_size,
        size_t kv_cache_size,
        size_t available_ram
    ) {
        return (model_size + kv_cache_size) > available_ram;
    }
};

//=============================================================================
// Optimization Strategies
//=============================================================================

enum class ExecutionStrategy {
    // Single model, full resident
    SINGLE_RESIDENT,
    
    // Single model, streaming layers
    SINGLE_STREAMING,
    
    // Two models, expert partitioning (MoE)
    DUAL_MoE_PARTITION,
    
    // Two models, agent split (planner/implementer)
    DUAL_AGENT_SPLIT,
    
    // Two models, time-sliced (not simultaneous)
    DUAL_TIME_SLICED,
    
    // Impossible - would hit wall
    IMPOSSIBLE
};

struct StrategyRecommendation {
    ExecutionStrategy strategy;
    double expected_tps;
    size_t max_context_length;
    bool is_feasible;
    const char* rationale;
};

class StrategySelector {
public:
    // Recommend execution strategy based on hardware
    static StrategyRecommendation RecommendStrategy(
        size_t model_size,
        size_t system_ram,
        size_t vram,
        int num_models_desired
    );
    
    // Calculate optimal batch size for given constraints
    static int CalculateOptimalBatchSize(
        size_t model_size,
        size_t available_memory,
        int target_tps
    );
};

} // namespace Hardware
} // namespace RawrXD
