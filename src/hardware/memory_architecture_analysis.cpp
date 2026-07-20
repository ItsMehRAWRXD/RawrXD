//=============================================================================
// Memory Architecture Analysis - Hardware Reality Implementation
// Dual 800B Model Feasibility Study
//=============================================================================

#include "memory_architecture_analysis.hpp"
#include <cstdio>
#include <cmath>

namespace RawrXD {
namespace Hardware {

//=============================================================================
// Feasibility Analysis Implementation
//=============================================================================

bool FeasibilityAnalyzer::IsPhysicallyPossible(size_t model_size_gb, int num_models) {
    size_t total_required = model_size_gb * num_models * 1024ULL * 1024 * 1024;
    return total_required <= HardwareLimits::kUsableRAM;
}

double FeasibilityAnalyzer::CalculateExpectedTPS(
    size_t model_size,
    double memory_bandwidth,
    double pcie_bandwidth,
    bool is_streaming
) {
    if (is_streaming) {
        // Streaming is limited by PCIe/NVMe, not compute
        double pcie_limited_tps = pcie_bandwidth / (model_size / 1e9) * 1000; // rough estimate
        return pcie_limited_tps; // Will be very low (<< 1 TPS for 800B model)
    } else {
        // Resident in RAM - limited by memory bandwidth
        // Rough formula: TPS = Memory_BW / (Model_Size * Operations_Per_Token)
        double ops_per_token = 2.0; // FLOPs per parameter (simplified)
        double tps = memory_bandwidth / ((model_size / 1e9) * ops_per_token);
        return tps;
    }
}

FeasibilityAnalyzer::MemoryPressure FeasibilityAnalyzer::AnalyzeMemoryPressure(
    size_t total_model_size,
    size_t active_context_size,
    size_t available_ram
) {
    MemoryPressure pressure = {};
    
    size_t total_required = total_model_size + active_context_size;
    pressure.ram_utilization = static_cast<double>(total_required) / available_ram;
    
    // Cache hit rate estimation (simplified)
    if (pressure.ram_utilization > 0.9) {
        pressure.cache_hit_rate = 0.1;  // Catastrophic
        pressure.page_fault_rate = 10000; // faults/sec
        pressure.will_thrash = true;
    } else if (pressure.ram_utilization > 0.7) {
        pressure.cache_hit_rate = 0.5;
        pressure.page_fault_rate = 1000;
        pressure.will_thrash = false;
    } else {
        pressure.cache_hit_rate = 0.9;
        pressure.page_fault_rate = 10;
        pressure.will_thrash = false;
    }
    
    return pressure;
}

//=============================================================================
// Strategy Selection
//=============================================================================

StrategyRecommendation StrategySelector::RecommendStrategy(
    size_t model_size,
    size_t system_ram,
    size_t vram,
    int num_models_desired
) {
    StrategyRecommendation rec = {};
    
    size_t total_required = model_size * num_models_desired;
    
    // Check if physically possible
    if (total_required > system_ram) {
        if (num_models_desired == 1) {
            // Single model too big - must stream
            rec.strategy = ExecutionStrategy::SINGLE_STREAMING;
            rec.expected_tps = 0.1; // Very low - PCIe limited
            rec.max_context_length = 1024; // Limited by streaming
            rec.is_feasible = true; // Technically possible but painful
            rec.rationale = "Model exceeds RAM. Streaming from NVMe at 12GB/s. Expect < 1 TPS.";
        } else {
            // Multiple models impossible
            rec.strategy = ExecutionStrategy::IMPOSSIBLE;
            rec.expected_tps = 0.0;
            rec.max_context_length = 0;
            rec.is_feasible = false;
            rec.rationale = "Dual models require 160GB+. Only 48GB usable. Physically impossible.";
        }
    } else if (num_models_desired == 2) {
        // Two models fit in RAM
        rec.strategy = ExecutionStrategy::DUAL_AGENT_SPLIT;
        rec.expected_tps = 5.0; // Time-sliced
        rec.max_context_length = 4096;
        rec.is_feasible = true;
        rec.rationale = "Agent split: Planner + Implementer. Not simultaneous execution.";
    } else {
        // Single model resident
        rec.strategy = ExecutionStrategy::SINGLE_RESIDENT;
        rec.expected_tps = 50.0; // Reasonable for resident model
        rec.max_context_length = 8192;
        rec.is_feasible = true;
        rec.rationale = "Single model resident in RAM. Optimal path.";
    }
    
    return rec;
}

int StrategySelector::CalculateOptimalBatchSize(
    size_t model_size,
    size_t available_memory,
    int target_tps
) {
    // Simplified calculation
    size_t memory_per_token = model_size / 100000; // Rough estimate
    size_t max_tokens = available_memory / memory_per_token;
    
    // Batch size that fits in L3 cache for attention
    int l3_friendly_batch = 32; // tokens
    
    return std::min(l3_friendly_batch, static_cast<int>(max_tokens));
}

} // namespace Hardware
} // namespace RawrXD
