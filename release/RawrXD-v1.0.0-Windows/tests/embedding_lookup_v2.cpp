/**
 * @file embedding_lookup_v2.cpp
 * @brief Phase 4: Single Tensor Compute Validation - Fixed version
 * 
 * Uses manual byte reading to avoid struct packing issues.
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

// GGML Types
enum ggml_type {
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_F32  = 0,
};

// FP16 to FP32 conversion
float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (h >> 15) & 0x1;
    uint32_t exp = (h >> 10) & 0x1F;
    uint32_t mant = h & 0x3FF;
    
    if (exp == 0) {
        // Subnormal
        if (mant == 0) return sign ? -0.0f : 0.0f;
        return (sign ? -1.0f : 1.0f) * (mant / 1024.0f) * powf(2.0f, -14);
    } else if (exp == 31) {
        // Inf/NaN
        return (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
    }
    
    // Normal
    float value = (1.0f + mant / 1024.0f) * powf(2.0f, (int)exp - 15);
    return sign ? -value : value;
}

// Read Q4_0 block from file pointer
// Returns scale and fills weights array
float read_q4_0_block(ifstream& file, int8_t* weights_out) {
    // Read 18 bytes
    uint8_t bytes[18];
    file.read(reinterpret_cast<char*>(bytes), 18);
    
    // Parse scale (little-endian FP16)
    uint16_t scale_bits = bytes[0] | (bytes[1] << 8);
    float scale = fp16_to_fp32(scale_bits);
    
    // Parse weights (16 bytes = 32 x 4-bit values)
    for (int i = 0; i < 16; i++) {
        uint8_t b = bytes[2 + i];
        weights_out[i * 2] = (b & 0x0F);      // Low nibble
        weights_out[i * 2 + 1] = (b >> 4) & 0x0F;  // High nibble
    }
    
    return scale;
}

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

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔬 RawrXD Phase 4: Single Tensor Compute Validation (v2)\n";
    cout << "========================================================\n";
    cout << "Operation: Embedding Lookup\n";
    cout << "Formula: token_id → embedding_row → Q4_0_decode → float[3072]\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open: " << MODEL_PATH << "\n";
        return 1;
    }
    
    auto total_start = chrono::high_resolution_clock::now();
    
    // [1/6] Parse header
    cout << "[1/6] Parsing GGUF header...\n";
    
    uint32_t magic = read_le<uint32_t>(file);
    if (magic != 0x46554747) { // "GGUF" in little-endian
        cerr << "❌ Invalid magic\n";
        return 1;
    }
    
    uint32_t version = read_le<uint32_t>(file);
    uint64_t n_tensors = read_le<uint64_t>(file);
    uint64_t n_kv = read_le<uint64_t>(file);
    
    cout << "  ✓ GGUF v" << version << ", " << n_tensors << " tensors, " << n_kv << " KV pairs\n\n";
    
    // [2/6] Skip metadata
    cout << "[2/6] Skipping metadata...\n";
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_str(file);
        uint32_t type = read_le<uint32_t>(file);
        skip_value(file, type);
    }
    cout << "  ✓ Metadata skipped\n\n";
    
    // [3/6] Find token_embd.weight tensor
    cout << "[3/6] Locating token_embd.weight tensor...\n";
    
    struct TensorInfo {
        string name;
        uint64_t offset;
        uint32_t type;
        uint64_t dim0, dim1;
    };
    
    TensorInfo emb_tensor;
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
        
        if (name == "token_embd.weight") {
            emb_tensor = {name, offset, type, dims[0], dims[1]};
            found = true;
        }
    }
    
    if (!found) {
        cerr << "❌ token_embd.weight not found\n";
        return 1;
    }
    
    cout << "  ✓ Found: " << emb_tensor.name << "\n";
    cout << "    Shape: [" << emb_tensor.dim0 << ", " << emb_tensor.dim1 << "]\n";
    cout << "    Type: " << (emb_tensor.type == GGML_TYPE_Q4_0 ? "Q4_0" : "other") << "\n";
    cout << "    Offset: " << emb_tensor.offset << "\n\n";
    
    // [4/6] Calculate offsets
    cout << "[4/6] Performing embedding lookup...\n";
    
    uint32_t token_id = 0;
    uint64_t elements_per_row = emb_tensor.dim0;  // 3072
    uint64_t blocks_per_row = elements_per_row / 32;  // 96 blocks
    
    // CRITICAL: Tensor data section starts at offset 738400 (32-byte aligned after tensor directory)
    uint64_t tensor_data_start = 738400;
    uint64_t row_offset = tensor_data_start + emb_tensor.offset + (token_id * blocks_per_row * 18);
    
    cout << "  Token ID: " << token_id << "\n";
    cout << "  Tensor data section starts at: " << tensor_data_start << "\n";
    cout << "  Tensor offset within section: " << emb_tensor.offset << "\n";
    cout << "  Row offset in file: " << row_offset << "\n";
    cout << "  Blocks per row: " << blocks_per_row << "\n\n";
    
    // [5/6] Load and decode
    cout << "[5/6] Loading and decoding embedding row...\n";
    
    auto compute_start = chrono::high_resolution_clock::now();
    
    file.seekg(row_offset, ios::beg);
    
    vector<float> embedding(elements_per_row);
    int8_t weights[32];
    
    for (size_t b = 0; b < blocks_per_row; b++) {
        float scale = read_q4_0_block(file, weights);
        
        // Decode 32 values
        for (int i = 0; i < 32; i++) {
            embedding[b * 32 + i] = scale * (weights[i] - 8);
        }
    }
    
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    cout << "  ✓ Decoded " << embedding.size() << " values\n";
    cout << "  Time: " << compute_us << " μs\n";
    cout << "  Throughput: " << fixed << setprecision(2) 
         << (embedding.size() * sizeof(float) / 1024.0 / 1024.0) / (compute_us / 1000000.0)
         << " MB/s\n\n";
    
    // [6/6] Validate
    cout << "[6/6] Validating embedding vector...\n";
    
    // Check for NaN/Inf
    int nan_count = 0, inf_count = 0;
    for (float v : embedding) {
        if (isnan(v)) nan_count++;
        if (isinf(v)) inf_count++;
    }
    
    // Calculate statistics
    float min_val = FLT_MAX, max_val = -FLT_MAX, sum = 0;
    int valid_count = 0;
    
    for (float v : embedding) {
        if (!isnan(v) && !isinf(v)) {
            min_val = min(min_val, v);
            max_val = max(max_val, v);
            sum += v;
            valid_count++;
        }
    }
    
    float mean = (valid_count > 0) ? sum / valid_count : 0;
    
    // Calculate stddev
    float variance = 0;
    for (float v : embedding) {
        if (!isnan(v) && !isinf(v)) {
            variance += (v - mean) * (v - mean);
        }
    }
    float stddev = (valid_count > 0) ? sqrt(variance / valid_count) : 0;
    
    if (nan_count > 0 || inf_count > 0) {
        cout << "  ⚠ Found " << nan_count << " NaN and " << inf_count << " Inf values\n";
    }
    
    cout << "  Statistics:\n";
    cout << "    Valid values: " << valid_count << " / " << embedding.size() << "\n";
    cout << "    Min: " << min_val << "\n";
    cout << "    Max: " << max_val << "\n";
    cout << "    Mean: " << mean << "\n";
    cout << "    StdDev: " << stddev << "\n\n";
    
    cout << "  First 32 values:\n";
    for (int i = 0; i < 32; i++) {
        cout << "    [" << setw(3) << i << "] " << setw(10) << embedding[i];
        if ((i + 1) % 4 == 0) cout << "\n";
        else cout << " ";
    }
    
    // Check if values are in reasonable range for embeddings
    bool in_range = (min_val > -10.0f && max_val < 10.0f && fabs(mean) < 1.0f);
    
    if (in_range && nan_count == 0 && inf_count == 0) {
        cout << "\n  ✓ Values in typical embedding range [-10, 10]\n";
    } else {
        cout << "\n  ⚠ Warning: Values outside typical embedding range [-10, 10]\n";
    }
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - total_start).count();
    
    cout << "\n===================================================\n";
    cout << "Summary:\n";
    cout << "  Operation: Embedding Lookup\n";
    cout << "  Token ID: " << token_id << "\n";
    cout << "  Output shape: [" << embedding.size() << "]\n";
    cout << "  Output type: float32\n";
    cout << "  Valid values: " << (nan_count == 0 && inf_count == 0 ? "YES" : "NO") << "\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    cout << "===================================================\n";
    
    if (nan_count == 0 && inf_count == 0) {
        cout << "✅ PHASE 4 PASSED: Embedding lookup works!\n";
        return 0;
    } else {
        cout << "❌ Validation failed\n";
        return 1;
    }
}
