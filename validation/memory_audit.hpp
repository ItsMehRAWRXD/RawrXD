/**
 * @file memory_audit.hpp
 * @brief Memory Usage Audit Tool for RawrXD
 *
 * Identifies unnecessary tensor materialization and memory bloat.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <iostream>

namespace rawrxd {
namespace validation {

// ============================================================================
// Memory Audit Structures
// ============================================================================

struct TensorAllocation {
    std::string name;
    std::vector<size_t> shape;
    uint32_t dtype;  // GGML type
    size_t bytes_allocated;
    size_t bytes_theoretical;  // What it should be
    bool is_quantized;
    bool is_materialized;  // FP32 copy exists
    std::string allocation_source;  // File:line
};

struct MemoryAuditReport {
    size_t total_allocated_bytes = 0;
    size_t total_theoretical_bytes = 0;
    size_t waste_bytes = 0;
    double waste_percentage = 0.0;
    
    // Breakdown by category
    size_t weights_bytes = 0;
    size_t activations_bytes = 0;
    size_t kv_cache_bytes = 0;
    size_t temporary_bytes = 0;
    
    // Problem areas
    std::vector<TensorAllocation> materialized_tensors;  // Quant -> FP32 copies
    std::vector<TensorAllocation> oversized_tensors;     // Allocated > theoretical
    std::vector<TensorAllocation> duplicate_tensors;     // Multiple copies
    
    // Recommendations
    std::vector<std::string> recommendations;
    
    bool passed = false;
};

// ============================================================================
// Memory Auditor
// ============================================================================

class MemoryAuditor {
public:
    MemoryAuditor();
    ~MemoryAuditor();
    
    // Start tracking allocations
    void BeginAudit();
    
    // Track a tensor allocation
    void TrackAllocation(
        const std::string& name,
        const std::vector<size_t>& shape,
        uint32_t dtype,
        size_t bytes,
        const std::string& source = "");
    
    // Track tensor access pattern
    void TrackAccess(const std::string& name, bool is_write);
    
    // End audit and generate report
    MemoryAuditReport EndAudit();
    
    // Check if a model can fit in memory
    bool CanFitInMemory(
        const std::string& model_path,
        size_t available_memory_bytes);
    
    // Estimate memory for model
    size_t EstimateModelMemory(const std::string& model_path);
    
    // Print live report
    void PrintLiveReport();

private:
    std::map<std::string, TensorAllocation> allocations_;
    bool auditing_ = false;
    
    size_t CalculateTheoreticalSize(
        const std::vector<size_t>& shape,
        uint32_t dtype);
    
    void GenerateRecommendations(MemoryAuditReport& report);
};

// ============================================================================
// Model Memory Profiler
// ============================================================================

class ModelMemoryProfiler {
public:
    // Profile a GGUF model's memory usage
    struct ProfileResult {
        std::string model_path;
        size_t file_size;
        size_t theoretical_memory;
        size_t current_memory_usage;
        size_t peak_memory_usage;
        
        // Per-tensor breakdown
        std::vector<TensorAllocation> tensors;
        
        // Quantization stats
        size_t quantized_tensors = 0;
        size_t fp32_tensors = 0;
        size_t fp16_tensors = 0;
        
        // Memory efficiency
        double efficiency = 0.0;  // theoretical / actual
    };
    
    static ProfileResult ProfileGGUF(const std::string& path);
    static void PrintProfile(const ProfileResult& result);
    static std::string GenerateReport(const ProfileResult& result);
};

// ============================================================================
// Memory Optimization Recommendations
// ============================================================================

struct MemoryOptimization {
    std::string issue;
    std::string location;
    size_t bytes_saved;
    std::string fix_suggestion;
    int priority;  // 1 = critical, 2 = high, 3 = medium
};

std::vector<MemoryOptimization> AnalyzeMemoryReport(const MemoryAuditReport& report);

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick memory audit of current process
MemoryAuditReport QuickMemoryAudit();

// Check specific model for memory issues
MemoryAuditReport AuditModelLoading(const std::string& model_path);

// Estimate if model will cause std::bad_alloc
bool WillModelCauseBadAlloc(
    const std::string& model_path,
    size_t available_ram_bytes);

// Print human-readable memory size
std::string FormatBytes(size_t bytes);

} // namespace validation
} // namespace rawrxd
