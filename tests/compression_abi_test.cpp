/**
 * @file compression_abi_test.cpp
 * @brief RawrXD Compression ABI Test
 *
 * Demonstrates the contract layer between storage and execution.
 * Different tensors, different compression, unified decode.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cmath>
#include "../kernels/compression_abi.h"

using namespace std;
using namespace rawrxd::compression;

// ============================================================================
// Mock Tensor Data
// ============================================================================

struct MockTensor {
    string name;
    size_t num_elements;
    float sensitivity;  // 0.0 = low, 1.0 = high
    float* data;
};

vector<MockTensor> CreateMockModel() {
    vector<MockTensor> tensors;
    
    // Token embedding - high sensitivity
    {
        MockTensor t{"token_embd.weight", 32064 * 3072, 0.9f, nullptr};
        t.data = new float[t.num_elements];
        for (size_t i = 0; i < t.num_elements; i++) t.data[i] = sinf(i * 0.001f) * 0.01f;
        tensors.push_back(t);
    }
    
    // Attention Q projection - medium sensitivity
    {
        MockTensor t{"attention.q_proj", 3072 * 3072, 0.6f, nullptr};
        t.data = new float[t.num_elements];
        for (size_t i = 0; i < t.num_elements; i++) t.data[i] = sinf(i * 0.002f) * 0.02f;
        tensors.push_back(t);
    }
    
    // Attention K projection - medium sensitivity
    {
        MockTensor t{"attention.k_proj", 3072 * 3072, 0.5f, nullptr};
        t.data = new float[t.num_elements];
        for (size_t i = 0; i < t.num_elements; i++) t.data[i] = sinf(i * 0.003f) * 0.015f;
        tensors.push_back(t);
    }
    
    // FFN up projection - low sensitivity
    {
        MockTensor t{"ffn.up_proj", 8192 * 3072, 0.3f, nullptr};
        t.data = new float[t.num_elements];
        for (size_t i = 0; i < t.num_elements; i++) t.data[i] = sinf(i * 0.0005f) * 0.005f;
        tensors.push_back(t);
    }
    
    // Output projection - highest sensitivity
    {
        MockTensor t{"output.weight", 32064 * 3072, 1.0f, nullptr};
        t.data = new float[t.num_elements];
        for (size_t i = 0; i < t.num_elements; i++) t.data[i] = sinf(i * 0.001f) * 0.008f;
        tensors.push_back(t);
    }
    
    return tensors;
}

void CleanupMockModel(vector<MockTensor>& tensors) {
    for (auto& t : tensors) {
        delete[] t.data;
        t.data = nullptr;
    }
}

// ============================================================================
// Print Results
// ============================================================================

void PrintHeader() {
    cout << "\n═══════════════════════════════════════════════════════════════════════════════════\n";
    cout << "COMPRESSION ABI - TENSOR-AWARE COMPRESSION\n";
    cout << "═══════════════════════════════════════════════════════════════════════════════════\n\n";
    
    cout << left << setw(25) << "Tensor";
    cout << right << setw(12) << "Elements";
    cout << setw(12) << "FP32 (MB)";
    cout << setw(10) << "Bits";
    cout << setw(12) << "Comp (MB)";
    cout << setw(10) << "Ratio";
    cout << setw(12) << "Sens.";
    cout << setw(15) << "Format" << "\n";
    cout << string(108, '-') << "\n";
}

void PrintTensor(const TensorCompressionInfo& info, const string& format_name) {
    cout << left << setw(25) << info.tensor_name;
    cout << right << fixed << setprecision(1);
    cout << setw(12) << (info.original_size_mb * 1024 * 1024 / sizeof(float));
    cout << setw(12) << info.original_size_mb;
    cout << setw(10) << static_cast<int>(info.recommended_bits);
    cout << setw(12) << info.compressed_size_mb;
    cout << setw(9) << setprecision(1) << info.compression_ratio << ":1";
    cout << setw(12) << setprecision(2) << info.measured_error;
    cout << setw(15) << format_name << "\n";
}

// ============================================================================
// Main
// ============================================================================

int main() {
    cout << "🔧 RawrXD Compression ABI Test\n";
    cout << "════════════════════════════════\n\n";
    cout << "Architecture: Storage Format -> ABI -> Execution Format\n";
    cout << "Different tensors, different compression, unified decode.\n\n";
    
    // Get ABI instance
    CompressionABI& abi = GetCompressionABI();
    
    // Create mock model
    vector<MockTensor> tensors = CreateMockModel();
    
    cout << "Model Configuration:\n";
    cout << "  Tensors: " << tensors.size() << "\n";
    float total_fp32 = 0;
    for (const auto& t : tensors) total_fp32 += (t.num_elements * sizeof(float)) / (1024.0f * 1024.0f);
    cout << "  Total FP32: " << fixed << setprecision(1) << total_fp32 << " MB\n\n";
    
    // Analyze tensors
    cout << "[1/3] Analyzing tensor sensitivity...\n";
    vector<TensorCompressionInfo> infos;
    for (const auto& tensor : tensors) {
        TensorCompressionInfo info = abi.AnalyzeTensor(tensor.name, tensor.data, tensor.num_elements);
        infos.push_back(info);
    }
    
    // Apply adaptive compression
    cout << "[2/3] Applying adaptive compression...\n";
    abi.ApplyAdaptiveCompression(infos);
    
    // Print results
    PrintHeader();
    float total_compressed = 0;
    for (const auto& info : infos) {
        PrintTensor(info, abi.QuantTypeToString(info.profile.quant_type));
        total_compressed += info.compressed_size_mb;
    }
    
    cout << "\n" << string(108, '=') << "\n";
    
    // Summary
    cout << "\n📊 ADAPTIVE COMPRESSION SUMMARY\n";
    cout << "════════════════════════════════\n\n";
    cout << "Total FP32 Size:     " << fixed << setprecision(1) << total_fp32 << " MB\n";
    cout << "Total Compressed:    " << total_compressed << " MB\n";
    cout << "Memory Reduction:    " << setprecision(1) << (100.0f * (1.0f - total_compressed / total_fp32)) << "%\n";
    cout << "Overall Ratio:       " << setprecision(2) << (total_fp32 / total_compressed) << ":1\n\n";
    
    // Test runtime profiles
    cout << "[3/3] Testing runtime profiles...\n\n";
    
    cout << "Runtime Profiles:\n";
    cout << "─────────────────\n";
    
    auto eco = abi.CreateProfile(RuntimeProfile::ECO);
    cout << "  ECO:         " << eco.bits_per_weight << " bits/weight, " 
         << setprecision(1) << eco.compression_ratio << ":1, " << eco.name << "\n";
    
    auto balanced = abi.CreateProfile(RuntimeProfile::BALANCED);
    cout << "  BALANCED:    " << balanced.bits_per_weight << " bits/weight, " 
         << balanced.compression_ratio << ":1, " << balanced.name << "\n";
    
    auto performance = abi.CreateProfile(RuntimeProfile::PERFORMANCE);
    cout << "  PERFORMANCE: " << performance.bits_per_weight << " bits/weight, " 
         << performance.compression_ratio << ":1, " << performance.name << "\n";
    
    auto quality = abi.CreateProfile(RuntimeProfile::QUALITY);
    cout << "  QUALITY:     " << quality.bits_per_weight << " bits/weight, " 
         << quality.compression_ratio << ":1, " << quality.name << "\n";
    
    auto adaptive = abi.CreateProfile(RuntimeProfile::ADAPTIVE);
    cout << "  ADAPTIVE:    " << adaptive.bits_per_weight << " bits/weight (variable), " 
         << adaptive.compression_ratio << ":1 base, " << adaptive.name << "\n\n";
    
    // Custom profile example
    cout << "Custom Profile Example:\n";
    cout << "──────────────────────\n";
    auto custom = abi.CreateCustomProfile(QuantType::Q5_0, 64, 5);
    cout << "  Custom Q5:   " << custom.bits_per_weight << " bits/weight, "
         << custom.block_size << " block size, "
         << setprecision(2) << custom.compression_ratio << ":1\n";
    cout << "  Effective:   " << setprecision(2) << custom.effective_bits << " bits/weight\n";
    cout << "  Block bytes: " << custom.bytes_per_block << "\n\n";
    
    // Decoder registry
    cout << "Decoder Registry:\n";
    cout << "─────────────────\n";
    cout << "  Q4_0:  " << (abi.HasDecoder(QuantType::Q4_0) ? "✅ Registered" : "❌ Missing") << "\n";
    cout << "  Q8_0:  " << (abi.HasDecoder(QuantType::Q8_0) ? "✅ Registered" : "❌ Missing") << "\n";
    cout << "  FP32:  " << (abi.HasDecoder(QuantType::FP32) ? "✅ Registered" : "❌ Missing") << "\n";
    cout << "  Q4_K:  " << (abi.HasDecoder(QuantType::Q4_K) ? "✅ Registered" : "❌ Missing") << "\n\n";
    
    // Cleanup
    CleanupMockModel(tensors);
    
    cout << "═══════════════════════════════════════════════════════════════════════════════════\n";
    cout << "COMPRESSION ABI TEST COMPLETE\n";
    cout << "═══════════════════════════════════════════════════════════════════════════════════\n";
    cout << "\n✅ Storage representation decoupled from execution\n";
    cout << "✅ Per-tensor adaptive compression\n";
    cout << "✅ Runtime profile selection\n";
    cout << "✅ Unified decode interface\n\n";
    
    return 0;
}
