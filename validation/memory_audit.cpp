/**
 * @file memory_audit.cpp
 * @brief Memory Audit Implementation
 *
 * Identifies the std::bad_alloc root cause: materializing FP32 copies
 * of quantized weights.
 *
 * @copyright RawrXD 2026
 */

#include "memory_audit.hpp"
#include "../rawrxd/src/model/model_context.h"
#include <fstream>
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace rawrxd {
namespace validation {

// ============================================================================
// GGML Type Helpers
// ============================================================================

static size_t GetGGMLTypeSize(uint32_t type) {
    // GGML type sizes in bytes per block
    switch (type) {
        case 0: return 4;      // F32
        case 1: return 2;      // F16
        case 2: return 18;     // Q4_0 (16 weights + 2 bytes scale/min)
        case 3: return 20;     // Q4_1
        case 6: return 22;     // Q5_0
        case 7: return 24;     // Q5_1
        case 8: return 34;     // Q8_0
        case 9: return 36;     // Q8_1
        case 10: return 16;    // Q2_K
        case 11: return 24;    // Q3_K
        case 12: return 72;    // Q4_K
        case 13: return 88;    // Q5_K
        case 14: return 108;   // Q6_K
        case 15: return 128;   // Q8_K
        default: return 4;     // Unknown, assume FP32
    }
}

static size_t GetGGMLBlockSize(uint32_t type) {
    // Number of elements per block
    switch (type) {
        case 0: return 1;      // F32
        case 1: return 1;      // F16
        case 2: return 32;     // Q4_0
        case 3: return 32;     // Q4_1
        case 6: return 32;     // Q5_0
        case 7: return 32;     // Q5_1
        case 8: return 32;     // Q8_0
        case 9: return 32;     // Q8_1
        case 10: return 256;   // Q2_K
        case 11: return 256;   // Q3_K
        case 12: return 256;   // Q4_K
        case 13: return 256;   // Q5_K
        case 14: return 256;   // Q6_K
        case 15: return 256;   // Q8_K
        default: return 1;
    }
}

static std::string GetGGMLTypeName(uint32_t type) {
    switch (type) {
        case 0: return "F32";
        case 1: return "F16";
        case 2: return "Q4_0";
        case 3: return "Q4_1";
        case 6: return "Q5_0";
        case 7: return "Q5_1";
        case 8: return "Q8_0";
        case 9: return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K";
        case 12: return "Q4_K";
        case 13: return "Q5_K";
        case 14: return "Q6_K";
        case 15: return "Q8_K";
        default: return "UNKNOWN(" + std::to_string(type) + ")";
    }
}

// ============================================================================
// Memory Auditor Implementation
// ============================================================================

MemoryAuditor::MemoryAuditor() = default;
MemoryAuditor::~MemoryAuditor() = default;

void MemoryAuditor::BeginAudit() {
    allocations_.clear();
    auditing_ = true;
    std::cout << "[MemoryAudit] Started tracking allocations...\n";
}

void MemoryAuditor::TrackAllocation(
    const std::string& name,
    const std::vector<size_t>& shape,
    uint32_t dtype,
    size_t bytes,
    const std::string& source) {
    
    if (!auditing_) return;
    
    TensorAllocation alloc;
    alloc.name = name;
    alloc.shape = shape;
    alloc.dtype = dtype;
    alloc.bytes_allocated = bytes;
    alloc.bytes_theoretical = CalculateTheoreticalSize(shape, dtype);
    alloc.is_quantized = (dtype >= 2);  // Q4_0 and above
    alloc.is_materialized = (dtype >= 2 && bytes > alloc.bytes_theoretical * 2);
    alloc.allocation_source = source;
    
    allocations_[name] = alloc;
}

void MemoryAuditor::TrackAccess(const std::string& name, bool is_write) {
    // Track access patterns for optimization hints
}

MemoryAuditReport MemoryAuditor::EndAudit() {
    auditing_ = false;
    
    MemoryAuditReport report;
    
    for (const auto& [name, alloc] : allocations_) {
        report.total_allocated_bytes += alloc.bytes_allocated;
        report.total_theoretical_bytes += alloc.bytes_theoretical;
        
        // Categorize
        if (name.find("weight") != std::string::npos ||
            name.find("proj") != std::string::npos ||
            name.find("embed") != std::string::npos) {
            report.weights_bytes += alloc.bytes_allocated;
        } else if (name.find("kv") != std::string::npos ||
                   name.find("cache") != std::string::npos) {
            report.kv_cache_bytes += alloc.bytes_allocated;
        } else if (name.find("temp") != std::string::npos ||
                   name.find("buffer") != std::string::npos) {
            report.temporary_bytes += alloc.bytes_allocated;
        } else {
            report.activations_bytes += alloc.bytes_allocated;
        }
        
        // Check for materialized quantized tensors
        if (alloc.is_materialized) {
            report.materialized_tensors.push_back(alloc);
        }
        
        // Check for oversized allocations
        if (alloc.bytes_allocated > alloc.bytes_theoretical * 1.5) {
            report.oversized_tensors.push_back(alloc);
        }
    }
    
    report.waste_bytes = report.total_allocated_bytes - report.total_theoretical_bytes;
    if (report.total_allocated_bytes > 0) {
        report.waste_percentage = (double)report.waste_bytes / report.total_allocated_bytes * 100.0;
    }
    
    GenerateRecommendations(report);
    
    // Pass if waste is under 20%
    report.passed = (report.waste_percentage < 20.0);
    
    return report;
}

size_t MemoryAuditor::CalculateTheoreticalSize(
    const std::vector<size_t>& shape,
    uint32_t dtype) {
    
    size_t num_elements = 1;
    for (auto dim : shape) {
        num_elements *= dim;
    }
    
    if (dtype == 0) {  // F32
        return num_elements * 4;
    } else if (dtype == 1) {  // F16
        return num_elements * 2;
    } else {
        // Quantized types
        size_t block_size = GetGGMLBlockSize(dtype);
        size_t num_blocks = (num_elements + block_size - 1) / block_size;
        return num_blocks * GetGGMLTypeSize(dtype);
    }
}

void MemoryAuditor::GenerateRecommendations(MemoryAuditReport& report) {
    report.recommendations.clear();
    
    if (!report.materialized_tensors.empty()) {
        report.recommendations.push_back(
            "CRITICAL: " + std::to_string(report.materialized_tensors.size()) + 
            " quantized tensors are materialized as FP32. Use in-place dequantization.");
    }
    
    if (report.waste_percentage > 50.0) {
        report.recommendations.push_back(
            "Memory waste is " + std::to_string((int)report.waste_percentage) + 
            "%. Consider memory mapping instead of loading full tensors.");
    }
    
    if (report.weights_bytes > 10ULL * 1024 * 1024 * 1024) {  // > 10GB
        report.recommendations.push_back(
            "Weight memory usage is " + FormatBytes(report.weights_bytes) + 
            ". Ensure quantized weights are not expanded to FP32.");
    }
}

bool MemoryAuditor::CanFitInMemory(
    const std::string& model_path,
    size_t available_memory_bytes) {
    
    size_t estimated = EstimateModelMemory(model_path);
    return estimated <= available_memory_bytes;
}

size_t MemoryAuditor::EstimateModelMemory(const std::string& model_path) {
    // Parse GGUF and estimate memory
    model::ModelContext ctx;
    if (!ctx.LoadFromFile(model_path)) {
        return 0;
    }
    
    size_t total = 0;
    for (const auto& [name, info] : ctx.GetTensorMap()) {
        total += info.GetSizeBytes();
    }
    
    // Add overhead for activations and KV cache (rough estimate)
    total = static_cast<size_t>(total * 1.5);
    
    return total;
}

void MemoryAuditor::PrintLiveReport() {
    std::cout << "\n=== Memory Audit (Live) ===\n";
    std::cout << "Tracked allocations: " << allocations_.size() << "\n";
    
    size_t total = 0;
    for (const auto& [name, alloc] : allocations_) {
        total += alloc.bytes_allocated;
    }
    
    std::cout << "Total tracked: " << FormatBytes(total) << "\n";
    std::cout << "===========================\n\n";
}

// ============================================================================
// Model Memory Profiler Implementation
// ============================================================================

ModelMemoryProfiler::ProfileResult ModelMemoryProfiler::ProfileGGUF(
    const std::string& path) {
    
    ProfileResult result;
    result.model_path = path;
    
    // Get file size
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        return result;
    }
    result.file_size = file.tellg();
    file.close();
    
    // Load model context
    model::ModelContext ctx;
    if (!ctx.LoadFromFile(path)) {
        return result;
    }
    
    // Analyze tensors
    size_t theoretical = 0;
    for (const auto& [name, info] : ctx.GetTensorMap()) {
        TensorAllocation alloc;
        alloc.name = name;
        alloc.shape = info.shape;
        alloc.dtype = info.type;
        alloc.bytes_theoretical = info.GetSizeBytes();
        alloc.bytes_allocated = alloc.bytes_theoretical;  // Assume 1:1 for file
        alloc.is_quantized = (info.type >= 2);
        
        result.tensors.push_back(alloc);
        theoretical += alloc.bytes_theoretical;
        
        // Count by type
        if (info.type == 0) result.fp32_tensors++;
        else if (info.type == 1) result.fp16_tensors++;
        else result.quantized_tensors++;
    }
    
    result.theoretical_memory = theoretical;
    result.current_memory_usage = theoretical;  // Baseline
    result.peak_memory_usage = theoretical * 2;  // Estimate with activations
    
    // Calculate efficiency
    if (result.file_size > 0) {
        result.efficiency = (double)theoretical / result.file_size;
    }
    
    return result;
}

void ModelMemoryProfiler::PrintProfile(const ProfileResult& result) {
    std::cout << "\n========================================\n";
    std::cout << "Model Memory Profile\n";
    std::cout << "========================================\n";
    std::cout << "Model: " << result.model_path << "\n";
    std::cout << "File size: " << FormatBytes(result.file_size) << "\n";
    std::cout << "Theoretical memory: " << FormatBytes(result.theoretical_memory) << "\n";
    std::cout << "Peak estimate: " << FormatBytes(result.peak_memory_usage) << "\n";
    std::cout << "\nTensor types:\n";
    std::cout << "  Quantized: " << result.quantized_tensors << "\n";
    std::cout << "  FP16: " << result.fp16_tensors << "\n";
    std::cout << "  FP32: " << result.fp32_tensors << "\n";
    std::cout << "\nEfficiency: " << std::fixed << std::setprecision(1) 
              << (result.efficiency * 100.0) << "%\n";
    
    // Warning for large models
    if (result.theoretical_memory > 20ULL * 1024 * 1024 * 1024) {
        std::cout << "\nWARNING: Model requires " << FormatBytes(result.theoretical_memory)
                  << " which may cause std::bad_alloc if materialized as FP32!\n";
        std::cout << "FP32 materialization would require: " 
                  << FormatBytes(result.theoretical_memory * 4) << "\n";
    }
    
    std::cout << "========================================\n";
}

std::string ModelMemoryProfiler::GenerateReport(const ProfileResult& result) {
    std::ostringstream oss;
    oss << "# Memory Profile Report\n\n";
    oss << "## Model Information\n";
    oss << "- Path: " << result.model_path << "\n";
    oss << "- File size: " << FormatBytes(result.file_size) << "\n";
    oss << "- Theoretical memory: " << FormatBytes(result.theoretical_memory) << "\n";
    oss << "- Peak estimate: " << FormatBytes(result.peak_memory_usage) << "\n\n";
    
    oss << "## Tensor Breakdown\n";
    oss << "| Name | Shape | Type | Size |\n";
    oss << "|------|-------|------|------|\n";
    
    for (const auto& tensor : result.tensors) {
        oss << "| " << tensor.name << " | ";
        for (size_t i = 0; i < tensor.shape.size(); ++i) {
            if (i > 0) oss << "x";
            oss << tensor.shape[i];
        }
        oss << " | " << GetGGMLTypeName(tensor.dtype) << " | ";
        oss << FormatBytes(tensor.bytes_theoretical) << " |\n";
    }
    
    return oss.str();
}

// ============================================================================
// Convenience Functions
// ============================================================================

MemoryAuditReport QuickMemoryAudit() {
    MemoryAuditor auditor;
    auditor.BeginAudit();
    // Would need to instrument actual allocations
    return auditor.EndAudit();
}

MemoryAuditReport AuditModelLoading(const std::string& model_path) {
    MemoryAuditor auditor;
    auditor.BeginAudit();
    
    // Simulate loading and track what would be allocated
    auto profile = ModelMemoryProfiler::ProfileGGUF(model_path);
    
    for (const auto& tensor : profile.tensors) {
        // Check if this would be materialized as FP32
        size_t allocated = tensor.bytes_theoretical;
        if (tensor.is_quantized) {
            // Current implementation materializes as FP32
            // This is the bug!
            size_t num_elements = 1;
            for (auto dim : tensor.shape) num_elements *= dim;
            allocated = num_elements * 4;  // FP32
        }
        
        auditor.TrackAllocation(
            tensor.name, tensor.shape, tensor.dtype, allocated,
            "transformer_layer.cpp:LoadWeights");
    }
    
    return auditor.EndAudit();
}

bool WillModelCauseBadAlloc(const std::string& model_path,
                           size_t available_ram_bytes) {
    auto profile = ModelMemoryProfiler::ProfileGGUF(model_path);
    
    // Check if FP32 materialization would exceed memory
    size_t fp32_size = 0;
    for (const auto& tensor : profile.tensors) {
        if (tensor.is_quantized) {
            // Materialized size
            size_t num_elements = 1;
            for (auto dim : tensor.shape) num_elements *= dim;
            fp32_size += num_elements * 4;
        } else {
            fp32_size += tensor.bytes_theoretical;
        }
    }
    
    return fp32_size > available_ram_bytes;
}

std::string FormatBytes(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_idx = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit_idx < 4) {
        size /= 1024.0;
        unit_idx++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit_idx];
    return oss.str();
}

} // namespace validation
} // namespace rawrxd
