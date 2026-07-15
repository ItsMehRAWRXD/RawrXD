/**
 * @file diagnose_badalloc.cpp
 * @brief Diagnose why 22B model causes std::bad_alloc
 *
 * This tool analyzes the GGUF file and shows exactly how much memory
 * would be consumed if quantized weights are materialized as FP32.
 *
 * @copyright RawrXD 2026
 */

#include "memory_audit.hpp"
#include <iostream>
#include <iomanip>
#include <cstdlib>

using namespace rawrxd::validation;

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Memory Diagnostic Tool\n";
    std::cout << "========================================\n\n";
    
    // Default to the 22B model that causes issues
    std::string model_path = (argc > 1) ? argv[1] : "d:\\rawrxd\\src\\codestral22b.gguf";
    
    std::cout << "Analyzing model: " << model_path << "\n\n";
    
    // Profile the model
    auto profile = ModelMemoryProfiler::ProfileGGUF(model_path);
    
    if (profile.tensors.empty()) {
        std::cerr << "ERROR: Could not load model!\n";
        return 1;
    }
    
    // Calculate memory scenarios
    size_t file_size = profile.file_size;
    size_t quantized_size = 0;
    size_t fp32_materialized = 0;
    size_t fp16_materialized = 0;
    
    for (const auto& tensor : profile.tensors) {
        quantized_size += tensor.bytes_theoretical;
        
        // Calculate FP32 materialization
        size_t num_elements = 1;
        for (auto dim : tensor.shape) num_elements *= dim;
        
        fp32_materialized += num_elements * 4;  // 4 bytes per FP32
        fp16_materialized += num_elements * 2;  // 2 bytes per FP16
    }
    
    // Get system memory
    size_t system_memory = 0;
    #ifdef _WIN32
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        system_memory = mem_status.ullTotalPhys;
    }
    #endif
    
    // Print analysis
    std::cout << "=== Memory Analysis ===\n\n";
    
    std::cout << "File size (on disk):\n";
    std::cout << "  " << FormatBytes(file_size) << "\n\n";
    
    std::cout << "Quantized tensor data (theoretical):\n";
    std::cout << "  " << FormatBytes(quantized_size) << "\n\n";
    
    std::cout << "=== SCENARIO ANALYSIS ===\n\n";
    
    std::cout << "1. CURRENT (FP32 materialization):\n";
    std::cout << "   Memory required: " << FormatBytes(fp32_materialized) << "\n";
    if (system_memory > 0) {
        double pct = (double)fp32_materialized / system_memory * 100.0;
        std::cout << "   % of system RAM: " << std::fixed << std::setprecision(1) << pct << "%\n";
    }
    std::cout << "   Status: ";
    if (fp32_materialized > system_memory * 0.8) {
        std::cout << "WILL CAUSE std::bad_alloc\n";
    } else {
        std::cout << "May work\n";
    }
    std::cout << "\n";
    
    std::cout << "2. WITH FP16 MATERIALIZATION:\n";
    std::cout << "   Memory required: " << FormatBytes(fp16_materialized) << "\n";
    if (system_memory > 0) {
        double pct = (double)fp16_materialized / system_memory * 100.0;
        std::cout << "   % of system RAM: " << std::fixed << std::setprecision(1) << pct << "%\n";
    }
    std::cout << "   Status: ";
    if (fp16_materialized > system_memory * 0.8) {
        std::cout << "WILL CAUSE std::bad_alloc\n";
    } else {
        std::cout << "RECOMMENDED\n";
    }
    std::cout << "\n";
    
    std::cout << "3. IN-PLACE QUANTIZED (no materialization):\n";
    std::cout << "   Memory required: " << FormatBytes(quantized_size) << "\n";
    if (system_memory > 0) {
        double pct = (double)quantized_size / system_memory * 100.0;
        std::cout << "   % of system RAM: " << std::fixed << std::setprecision(1) << pct << "%\n";
    }
    std::cout << "   Status: OPTIMAL\n\n";
    
    // Show tensor breakdown
    std::cout << "=== LARGEST TENSORS (Top 10) ===\n\n";
    std::vector<TensorAllocation> sorted_tensors = profile.tensors;
    std::sort(sorted_tensors.begin(), sorted_tensors.end(),
              [](const auto& a, const auto& b) {
                  size_t a_fp32 = 1;
                  size_t b_fp32 = 1;
                  for (auto dim : a.shape) a_fp32 *= dim;
                  for (auto dim : b.shape) b_fp32 *= dim;
                  a_fp32 *= 4; b_fp32 *= 4;
                  return a_fp32 > b_fp32;
              });
    
    std::cout << std::left << std::setw(40) << "Name"
              << std::setw(15) << "Quantized"
              << std::setw(15) << "FP32"
              << std::setw(10) << "Type"
              << "\n";
    std::cout << std::string(80, '-') << "\n";
    
    for (size_t i = 0; i < std::min(size_t(10), sorted_tensors.size()); ++i) {
        const auto& t = sorted_tensors[i];
        size_t num_elements = 1;
        for (auto dim : t.shape) num_elements *= dim;
        size_t fp32_size = num_elements * 4;
        
        std::cout << std::left << std::setw(40) << t.name.substr(0, 39)
                  << std::setw(15) << FormatBytes(t.bytes_theoretical)
                  << std::setw(15) << FormatBytes(fp32_size)
                  << std::setw(10) << GetGGMLTypeName(t.dtype)
                  << "\n";
    }
    
    std::cout << "\n=== ROOT CAUSE ===\n\n";
    std::cout << "The std::bad_alloc occurs because:\n\n";
    std::cout << "1. The model file contains " << FormatBytes(file_size) << " of quantized weights\n";
    std::cout << "2. Current implementation materializes ALL weights as FP32\n";
    std::cout << "3. This requires " << FormatBytes(fp32_materialized) << " of RAM\n";
    std::cout << "4. System has " << FormatBytes(system_memory) << " RAM\n\n";
    
    std::cout << "=== FIX REQUIRED ===\n\n";
    std::cout << "Modify transformer_layer.cpp:LoadWeights() to:\n";
    std::cout << "  - Keep weights in quantized format (Q4_K, Q8_0, etc.)\n";
    std::cout << "  - Dequantize on-the-fly during MatMul\n";
    std::cout << "  - Or use memory-mapped file access\n\n";
    
    std::cout << "Expected memory savings: " 
              << std::fixed << std::setprecision(1)
              << ((1.0 - (double)quantized_size / fp32_materialized) * 100.0)
              << "%\n\n";
    
    std::cout << "========================================\n";
    
    return (fp32_materialized > system_memory * 0.8) ? 1 : 0;
}
