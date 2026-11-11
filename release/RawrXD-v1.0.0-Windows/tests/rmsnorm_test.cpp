/**
 * @file rmsnorm_test.cpp
 * @brief Phase 7: RMSNorm Implementation
 * 
 * Root Mean Square Layer Normalization:
 *   output = input * weight / sqrt(mean(input²) + epsilon)
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <cfloat>
#include <cstdint>

using namespace std;

// Helper: Read little-endian
template<typename T>
T read_le(ifstream& f) {
    T val;
    f.read(reinterpret_cast<char*>(&val), sizeof(T));
    return val;
}

// Helper: Read string
string read_str(ifstream& f) {
    uint64_t len = read_le<uint64_t>(f);
    string s(len, '\0');
    f.read(&s[0], len);
    return s;
}

// Skip GGUF value based on type
void skip_value(ifstream& f, int type) {
    switch (type) {
        case 0: case 1: case 7: f.seekg(1, ios::cur); break;
        case 2: case 3: f.seekg(2, ios::cur); break;
        case 4: case 5: case 6: f.seekg(4, ios::cur); break;
        case 10: case 11: case 12: f.seekg(8, ios::cur); break;
        case 8: read_str(f); break;
        case 9: {
            int arr_type = read_le<uint32_t>(f);
            uint64_t arr_len = read_le<uint64_t>(f);
            for (uint64_t i = 0; i < arr_len; i++) skip_value(f, arr_type);
            break;
        }
        default: f.seekg(8, ios::cur);
    }
}

// FP16 to FP32 conversion
float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        return (sign ? -1.0f : 1.0f) * (mant / 1024.0f) * powf(2.0f, -14);
    } else if (exp == 31) {
        return (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    }
    
    float value = (1.0f + mant / 1024.0f) * powf(2.0f, (int)exp - 15);
    return sign ? -value : value;
}

// RMSNorm implementation
// output = input * weight / sqrt(mean(input²) + epsilon)
void rmsnorm(const float* input, const float* weight, float* output, int size, float epsilon = 1e-5f) {
    // Calculate mean of squares
    float sum_sq = 0.0f;
    for (int i = 0; i < size; i++) {
        sum_sq += input[i] * input[i];
    }
    float mean_sq = sum_sq / size;
    
    // Calculate normalization factor
    float norm_factor = 1.0f / sqrtf(mean_sq + epsilon);
    
    // Apply normalization and weight
    for (int i = 0; i < size; i++) {
        output[i] = input[i] * norm_factor * weight[i];
    }
}

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔬 RawrXD Phase 7: RMSNorm Test\n";
    cout << "===============================\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open: " << MODEL_PATH << "\n";
        return 1;
    }
    
    auto start = chrono::high_resolution_clock::now();
    
    // Read header
    uint32_t magic = read_le<uint32_t>(file);
    uint32_t version = read_le<uint32_t>(file);
    uint64_t n_tensors = read_le<uint64_t>(file);
    uint64_t n_kv = read_le<uint64_t>(file);
    
    cout << "[1/5] Parsing GGUF header...\n";
    cout << "  ✓ GGUF v" << version << ", " << n_tensors << " tensors\n\n";
    
    // Skip metadata
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_str(file);
        uint32_t type = read_le<uint32_t>(file);
        skip_value(file, type);
    }
    
    // Find input_norm.weight tensor (first layer normalization)
    cout << "[2/5] Finding input_norm.weight tensor...\n";
    
    struct TensorInfo {
        string name;
        uint64_t offset;
        uint32_t type;
        uint64_t size;
    };
    
    TensorInfo norm_tensor;
    bool found = false;
    
    for (uint64_t i = 0; i < n_tensors && !found; i++) {
        string name = read_str(file);
        uint32_t n_dims = read_le<uint32_t>(file);
        
        vector<uint64_t> dims(n_dims);
        for (uint32_t d = 0; d < n_dims; d++) {
            dims[d] = read_le<uint64_t>(file);
        }
        
        uint32_t type = read_le<uint32_t>(file);
        uint64_t offset = read_le<uint64_t>(file);
        
        if (name == "blk.0.attn_norm.weight") {
            norm_tensor = {name, offset, type, dims[0]};
            found = true;
        }
    }
    
    if (!found) {
        cerr << "❌ blk.0.attn_norm.weight not found\n";
        return 1;
    }
    
    cout << "  ✓ Found: " << norm_tensor.name << "\n";
    cout << "    Size: " << norm_tensor.size << "\n";
    cout << "    Type: " << (norm_tensor.type == 0 ? "F32" : "other") << "\n\n";
    
    // Load the normalization weights
    cout << "[3/5] Loading normalization weights...\n";
    
    // Tensor data starts at 738400
    uint64_t tensor_data_start = 738400;
    uint64_t weight_offset = tensor_data_start + norm_tensor.offset;
    
    file.seekg(weight_offset, ios::beg);
    
    vector<float> norm_weights(norm_tensor.size);
    if (norm_tensor.type == 0) { // F32
        file.read(reinterpret_cast<char*>(norm_weights.data()), norm_tensor.size * sizeof(float));
    } else {
        cerr << "❌ Unsupported type: " << norm_tensor.type << "\n";
        return 1;
    }
    
    cout << "  ✓ Loaded " << norm_weights.size() << " weights\n";
    cout << "    First 10: ";
    for (int i = 0; i < min(10, (int)norm_weights.size()); i++) {
        cout << fixed << setprecision(4) << norm_weights[i] << " ";
    }
    cout << "\n\n";
    
    // Create test input (simulated embedding output)
    cout << "[4/5] Creating test input...\n";
    
    vector<float> input(norm_tensor.size);
    
    // Fill with some test values (simulating embedding output)
    // Use a mix of positive and negative values
    for (int i = 0; i < norm_tensor.size; i++) {
        // Create a pattern: sine wave with some noise
        input[i] = sinf(i * 0.01f) * 0.1f + (i % 7 - 3) * 0.01f;
    }
    
    // Calculate input statistics
    float input_mean = 0.0f, input_var = 0.0f;
    for (float v : input) {
        input_mean += v;
        input_var += v * v;
    }
    input_mean /= input.size();
    input_var = input_var / input.size() - input_mean * input_mean;
    
    cout << "  ✓ Test input created\n";
    cout << "    Size: " << input.size() << "\n";
    cout << "    Mean: " << fixed << setprecision(6) << input_mean << "\n";
    cout << "    Variance: " << input_var << "\n";
    cout << "    First 10: ";
    for (int i = 0; i < min(10, (int)input.size()); i++) {
        cout << fixed << setprecision(4) << input[i] << " ";
    }
    cout << "\n\n";
    
    // Apply RMSNorm
    cout << "[5/5] Applying RMSNorm...\n";
    
    vector<float> output(norm_tensor.size);
    
    auto compute_start = chrono::high_resolution_clock::now();
    rmsnorm(input.data(), norm_weights.data(), output.data(), norm_tensor.size);
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    // Calculate output statistics
    float output_mean = 0.0f, output_var = 0.0f;
    float output_min = FLT_MAX, output_max = -FLT_MAX;
    for (float v : output) {
        output_mean += v;
        output_var += v * v;
        output_min = min(output_min, v);
        output_max = max(output_max, v);
    }
    output_mean /= output.size();
    output_var = output_var / output.size() - output_mean * output_mean;
    
    cout << "  ✓ RMSNorm applied\n";
    cout << "    Compute time: " << compute_us << " μs\n";
    cout << "    Output mean: " << fixed << setprecision(6) << output_mean << "\n";
    cout << "    Output variance: " << output_var << "\n";
    cout << "    Output range: [" << output_min << ", " << output_max << "]\n";
    cout << "    First 20 output values:\n";
    for (int i = 0; i < min(20, (int)output.size()); i++) {
        cout << "      [" << setw(4) << i << "] " << setw(10) << fixed << setprecision(6) << output[i] << "\n";
    }
    
    // Verify RMSNorm properties
    // The learned weights scale the normalized output
    // Check: no NaN/Inf, reasonable value range
    bool no_nan_inf = true;
    for (float v : output) {
        if (isnan(v) || isinf(v)) {
            no_nan_inf = false;
            break;
        }
    }
    
    // Check that output is in reasonable range for embeddings
    bool range_ok = (output_min > -10.0f && output_max < 10.0f);
    
    cout << "\n  Verification:\n";
    cout << "    No NaN/Inf: " << (no_nan_inf ? "✓" : "✗") << "\n";
    cout << "    Value range: [" << output_min << ", " << output_max << "]\n";
    cout << "    Range check: " << (range_ok ? "✓" : "✗") << " (should be in [-10, 10])\n";
    
    if (no_nan_inf && range_ok) {
        cout << "    ✓ RMSNorm output is valid\n";
    } else {
        cout << "    ✗ RMSNorm output has issues\n";
    }
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: RMSNorm\n";
    cout << "  Input size: " << input.size() << "\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Throughput: " << fixed << setprecision(2) 
         << (input.size() * sizeof(float) / 1024.0 / 1024.0) / (compute_us / 1000000.0)
         << " MB/s\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (no_nan_inf && range_ok) {
        cout << "  Status: ✅ RMSNORM TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ RMSNorm test failed\n";
        return 1;
    }
}
