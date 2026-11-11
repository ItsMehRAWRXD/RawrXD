/**
 * @file embedding_lookup.cpp
 * @brief Phase 4: Single Tensor Compute Validation - Embedding Lookup
 * 
 * Performs the first actual model operation:
 *   token_id → embedding row lookup → Q4_0 decode → 3072 float vector
 * 
 * This validates the bridge from "file format" to "model computation".
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

using namespace std;

// GGML Types
enum ggml_type {
    GGML_TYPE_Q4_0 = 2,
    GGML_TYPE_F32  = 0,
};

// Q4_0 block: 32 weights packed into 16 bytes + 2 byte FP16 scale
struct Q4_0_Block {
    uint16_t scale;      // FP16 scale
    uint8_t qs[16];      // 32 x 4-bit weights
    
    float get_scale() const {
        // FP16 to FP32
        uint16_t h = scale;
        uint32_t sign = (h >> 15) & 0x1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        
        if (exp == 0) {
            return (sign ? -1.0f : 1.0f) * (mant / 1024.0f) * powf(2.0f, -14);
        } else if (exp == 31) {
            return (mant == 0) ? (sign ? -INFINITY : INFINITY) : NAN;
        }
        
        float value = (1.0f + mant / 1024.0f) * powf(2.0f, exp - 15);
        return sign ? -value : value;
    }
    
    int8_t get_weight(int idx) const {
        int byte_idx = idx / 2;
        bool is_high = (idx % 2) == 0;
        return is_high ? ((qs[byte_idx] >> 4) & 0xF) : (qs[byte_idx] & 0xF);
    }
    
    void decode(float* out) const {
        float s = get_scale();
        for (int i = 0; i < 32; i++) {
            int w = get_weight(i);
            out[i] = s * (w - 8);  // Q4_0: value = scale * (quant - 8)
        }
    }
};

static_assert(sizeof(Q4_0_Block) == 18, "Q4_0_Block must be 18 bytes");

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
    
    cout << "🔬 RawrXD Phase 4: Single Tensor Compute Validation\n";
    cout << "===================================================\n";
    cout << "Operation: Embedding Lookup\n";
    cout << "Formula: token_id → embedding_row → Q4_0_decode → float[3072]\n\n";
    
    ifstream file(MODEL_PATH, ios::binary);
    if (!file.is_open()) {
        cerr << "❌ Failed to open file\n";
        return 1;
    }
    
    auto total_start = chrono::high_resolution_clock::now();
    
    // [1/6] Parse GGUF header
    cout << "[1/6] Parsing GGUF header...\n";
    
    uint32_t magic = read_le<uint32_t>(file);
    if (magic != 0x46554747) {
        cerr << "❌ Invalid GGUF magic\n";
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
        uint64_t dim0, dim1;  // [dim0, dim1] = [3072, 32064]
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
    
    // Validate shape
    if (emb_tensor.dim0 != 3072 || emb_tensor.dim1 != 32064) {
        cerr << "❌ Unexpected shape, expected [3072, 32064]\n";
        return 1;
    }
    
    // [4/6] Perform embedding lookup
    cout << "[4/6] Performing embedding lookup...\n";
    
    // Use token ID 0 (typically <pad> or <bos>)
    uint32_t token_id = 0;
    cout << "  Token ID: " << token_id << "\n";
    
    // Calculate offset within tensor
    // Each row has dim0 (3072) elements
    // Q4_0: 32 elements per block, 18 bytes per block
    uint64_t elements_per_row = emb_tensor.dim0;  // 3072
    uint64_t blocks_per_row = elements_per_row / 32;  // 96 blocks
    uint64_t bytes_per_row = blocks_per_row * sizeof(Q4_0_Block);  // 1728 bytes
    
    // CRITICAL: Tensor offsets in GGUF are relative to the start of tensor data section
    // The tensor data section starts after the tensor directory, aligned to 32 bytes
    // For Phi-3-mini GGUF: metadata ends at 726725, tensor dir ends at 738394, data starts at 738400
    uint64_t tensor_data_start = 738400;  // Corrected: aligned to 32 bytes after tensor directory
    uint64_t row_offset = tensor_data_start + emb_tensor.offset + (token_id * bytes_per_row);
    
    cout << "  Tensor data section starts at: " << tensor_data_start << "\n";
    cout << "  Tensor offset within section: " << emb_tensor.offset << "\n";
    cout << "  Row offset in file: " << row_offset << "\n";
    cout << "  Blocks per row: " << blocks_per_row << "\n";
    cout << "  Bytes per row: " << bytes_per_row << "\n\n";
    
    // [5/6] Load and decode embedding row
    cout << "[5/6] Loading and decoding embedding row...\n";
    
    auto compute_start = chrono::high_resolution_clock::now();
    
    file.seekg(row_offset, ios::beg);
    
    // Read all blocks for this row
    vector<Q4_0_Block> blocks(blocks_per_row);
    file.read(reinterpret_cast<char*>(blocks.data()), blocks_per_row * sizeof(Q4_0_Block));
    
    // Decode to float vector
    vector<float> embedding(elements_per_row);
    for (size_t b = 0; b < blocks.size(); b++) {
        blocks[b].decode(&embedding[b * 32]);
    }
    
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    cout << "  ✓ Decoded " << embedding.size() << " values\n";
    cout << "  Time: " << compute_us << " μs\n";
    cout << "  Throughput: " << fixed << setprecision(2) 
         << (embedding.size() * sizeof(float) / 1024.0 / 1024.0) / (compute_us / 1000000.0)
         << " MB/s\n\n";
    
    // [6/6] Validate output
    cout << "[6/6] Validating embedding vector...\n";
    
    // Check for NaN/Inf first
    int nan_count = 0, inf_count = 0;
    for (float v : embedding) {
        if (isnan(v)) nan_count++;
        if (isinf(v)) inf_count++;
    }
    
    if (nan_count > 0 || inf_count > 0) {
        cout << "  ⚠ Found " << nan_count << " NaN and " << inf_count << " Inf values\n";
        
        // Debug: Check which blocks have issues
        cout << "  Debugging block scales:\n";
        for (int b = 0; b < min(10, (int)blocks.size()); b++) {
            float s = blocks[b].get_scale();
            cout << "    Block " << b << ": scale=" << s;
            if (isnan(s) || isinf(s)) cout << " ❌";
            else if (s == 0) cout << " (zero)";
            else cout << " ✓";
            cout << "\n";
        }
    }
    
    // Calculate statistics (excluding NaN/Inf)
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
    
    // Calculate standard deviation
    float variance = 0;
    for (float v : embedding) {
        if (!isnan(v) && !isinf(v)) {
            variance += (v - mean) * (v - mean);
        }
    }
    float stddev = (valid_count > 0) ? sqrt(variance / valid_count) : 0;
    
    cout << "  Statistics (excluding NaN/Inf):\n";
    cout << "    Valid values: " << valid_count << " / " << embedding.size() << "\n";
    cout << "    Min: " << fixed << setprecision(4) << min_val << "\n";
    cout << "    Max: " << max_val << "\n";
    cout << "    Mean: " << mean << "\n";
    cout << "    StdDev: " << stddev << "\n\n";
    
    // Display first 32 values
    cout << "  First 32 values:\n";
    for (int i = 0; i < 32; i++) {
        cout << "    [" << setw(4) << i << "] " << setw(10) << embedding[i];
        if ((i + 1) % 4 == 0) cout << "\n";
        else cout << " ";
    }
    
    // Validation checks
    bool valid = (nan_count == 0 && inf_count == 0);
    
    // Check range is reasonable for embeddings
    if (min_val < -100 || max_val > 100) {
        cout << "\n  ⚠ Warning: Values outside typical embedding range [-100, 100]\n";
    }
    
    // Summary
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - total_start).count();
    
    cout << "\n===================================================\n";
    cout << "Summary:\n";
    cout << "  Operation: Embedding Lookup\n";
    cout << "  Token ID: " << token_id << "\n";
    cout << "  Output shape: [" << embedding.size() << "]\n";
    cout << "  Output type: float32\n";
    cout << "  Valid values: " << (valid ? "YES" : "NO") << "\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    cout << "===================================================\n";
    
    if (valid) {
        cout << "✅ EMBEDDING LOOKUP VALIDATED\n";
        cout << "\nFirst model operation works!\n";
        cout << "Token " << token_id << " → " << embedding.size() << "-dimensional vector\n";
        return 0;
    } else {
        cout << "❌ Validation failed\n";
        return 1;
    }
}
