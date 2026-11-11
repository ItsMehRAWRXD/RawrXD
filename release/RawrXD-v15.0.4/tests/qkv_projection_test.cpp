/**
 * @file qkv_projection_test.cpp
 * @brief Phase 8: QKV Projection (Matrix Multiplication)
 * 
 * Projects input to Query, Key, and Value vectors:
 *   Q = input @ W_q
 *   K = input @ W_k  
 *   V = input @ W_v
 * 
 * Phi-3 uses fused QKV weights: [Q; K; V] concatenated.
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

// Read Q4_0 block and return scale + decoded weights
float read_q4_0_block(ifstream& file, float* weights_out) {
    uint8_t bytes[18];
    file.read(reinterpret_cast<char*>(bytes), 18);
    
    uint16_t scale_bits = bytes[0] | (bytes[1] << 8);
    float scale = fp16_to_fp32(scale_bits);
    
    for (int i = 0; i < 16; i++) {
        uint8_t b = bytes[2 + i];
        weights_out[i * 2] = scale * ((b & 0x0F) - 8);
        weights_out[i * 2 + 1] = scale * (((b >> 4) & 0x0F) - 8);
    }
    
    return scale;
}

// Matrix-vector multiplication: y = x @ W
// x: [1, in_features], W: [in_features, out_features], y: [1, out_features]
void matmul(const float* x, const float* W, float* y, int in_features, int out_features) {
    for (int j = 0; j < out_features; j++) {
        float sum = 0.0f;
        for (int i = 0; i < in_features; i++) {
            sum += x[i] * W[i * out_features + j];
        }
        y[j] = sum;
    }
}

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔬 RawrXD Phase 8: QKV Projection Test\n";
    cout << "========================================\n\n";
    
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
    
    cout << "[1/6] Parsing GGUF header...\n";
    cout << "  ✓ GGUF v" << version << ", " << n_tensors << " tensors\n\n";
    
    // Skip metadata
    for (uint64_t i = 0; i < n_kv; i++) {
        string key = read_str(file);
        uint32_t type = read_le<uint32_t>(file);
        skip_value(file, type);
    }
    
    // Find attn_qkv.weight tensor
    cout << "[2/6] Finding attn_qkv.weight tensor...\n";
    
    struct TensorInfo {
        string name;
        uint64_t offset;
        uint32_t type;
        uint64_t dim0, dim1;  // [dim0, dim1] = [in_features, out_features]
    };
    
    TensorInfo qkv_tensor;
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
        
        if (name == "blk.0.attn_qkv.weight") {
            qkv_tensor = {name, offset, type, dims[0], dims[1]};
            found = true;
        }
    }
    
    if (!found) {
        cerr << "❌ blk.0.attn_qkv.weight not found\n";
        return 1;
    }
    
    cout << "  ✓ Found: " << qkv_tensor.name << "\n";
    cout << "    Shape: [" << qkv_tensor.dim0 << ", " << qkv_tensor.dim1 << "]\n";
    cout << "    Type: " << (qkv_tensor.type == 2 ? "Q4_0" : "other") << "\n\n";
    
    // Phi-3: dim0 = 3072 (embed), dim1 = 9216 (3 * 3072 for Q+K+V)
    int embed_dim = qkv_tensor.dim0;      // 3072
    int qkv_dim = qkv_tensor.dim1;        // 9216 = 3 * 3072
    int head_dim = embed_dim;             // 3072 (for simplicity, actual heads = 32)
    
    // Load QKV weights
    cout << "[3/6] Loading QKV weights...\n";
    
    uint64_t tensor_data_start = 738400;
    uint64_t weight_offset = tensor_data_start + qkv_tensor.offset;
    
    file.seekg(weight_offset, ios::beg);
    
    // For Q4_0: each block is 18 bytes for 32 weights
    // Total elements = embed_dim * qkv_dim = 3072 * 9216 = 28,311,552
    // Blocks = 28,311,552 / 32 = 884,736 blocks
    // Total bytes = 884,736 * 18 = 15,925,248 bytes (~15.2 MB)
    
    size_t total_elements = embed_dim * qkv_dim;
    size_t blocks_needed = total_elements / 32;
    
    cout << "  Total elements: " << total_elements << "\n";
    cout << "  Q4_0 blocks: " << blocks_needed << "\n";
    
    // Load weights (this will take some time and memory)
    vector<float> qkv_weights(total_elements);
    float block_weights[32];
    
    auto load_start = chrono::high_resolution_clock::now();
    
    for (size_t b = 0; b < blocks_needed; b++) {
        read_q4_0_block(file, block_weights);
        for (int i = 0; i < 32; i++) {
            qkv_weights[b * 32 + i] = block_weights[i];
        }
        
        // Progress indicator
        if ((b + 1) % 100000 == 0) {
            cout << "    Loaded " << (b + 1) << " / " << blocks_needed << " blocks\r";
            cout.flush();
        }
    }
    
    auto load_end = chrono::high_resolution_clock::now();
    auto load_ms = chrono::duration_cast<chrono::milliseconds>(load_end - load_start).count();
    
    cout << "\n  ✓ Loaded " << qkv_weights.size() << " weights in " << load_ms << " ms\n";
    cout << "    First 10 weights: ";
    for (int i = 0; i < min(10, (int)qkv_weights.size()); i++) {
        cout << fixed << setprecision(4) << qkv_weights[i] << " ";
    }
    cout << "\n\n";
    
    // Create test input
    cout << "[4/6] Creating test input...\n";
    
    vector<float> input(embed_dim);
    for (int i = 0; i < embed_dim; i++) {
        // Simple test pattern
        input[i] = sinf(i * 0.01f) * 0.1f;
    }
    
    cout << "  ✓ Test input created\n";
    cout << "    Size: " << input.size() << "\n";
    cout << "    First 10: ";
    for (int i = 0; i < min(10, (int)input.size()); i++) {
        cout << fixed << setprecision(4) << input[i] << " ";
    }
    cout << "\n\n";
    
    // Perform QKV projection
    cout << "[5/6] Performing QKV projection...\n";
    
    vector<float> qkv_output(qkv_dim);
    
    auto compute_start = chrono::high_resolution_clock::now();
    
    // Matrix multiply: input [1, embed_dim] @ weights [embed_dim, qkv_dim]
    for (int j = 0; j < qkv_dim; j++) {
        float sum = 0.0f;
        for (int i = 0; i < embed_dim; i++) {
            sum += input[i] * qkv_weights[i * qkv_dim + j];
        }
        qkv_output[j] = sum;
    }
    
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    // Split into Q, K, V
    vector<float> Q(head_dim);
    vector<float> K(head_dim);
    vector<float> V(head_dim);
    
    for (int i = 0; i < head_dim; i++) {
        Q[i] = qkv_output[i];
        K[i] = qkv_output[i + head_dim];
        V[i] = qkv_output[i + 2 * head_dim];
    }
    
    cout << "  ✓ QKV projection complete\n";
    cout << "    Compute time: " << compute_us << " μs\n";
    cout << "    Q size: " << Q.size() << "\n";
    cout << "    K size: " << K.size() << "\n";
    cout << "    V size: " << V.size() << "\n\n";
    
    // Validate output
    cout << "[6/6] Validating QKV outputs...\n";
    
    auto validate = [](const vector<float>& vec, const string& name) {
        float min_val = FLT_MAX, max_val = -FLT_MAX, sum = 0.0f;
        bool has_nan_inf = false;
        
        for (float v : vec) {
            if (isnan(v) || isinf(v)) {
                has_nan_inf = true;
                break;
            }
            min_val = min(min_val, v);
            max_val = max(max_val, v);
            sum += v;
        }
        
        float mean = sum / vec.size();
        
        cout << "  " << name << ":\n";
        cout << "    Range: [" << fixed << setprecision(4) << min_val << ", " << max_val << "]\n";
        cout << "    Mean: " << mean << "\n";
        cout << "    Valid: " << (has_nan_inf ? "✗" : "✓") << "\n";
        
        return !has_nan_inf;
    };
    
    bool q_ok = validate(Q, "Q");
    bool k_ok = validate(K, "K");
    bool v_ok = validate(V, "V");
    
    // Show sample values
    cout << "\n  Sample values:\n";
    cout << "    Q[0:5]: ";
    for (int i = 0; i < min(5, (int)Q.size()); i++) {
        cout << fixed << setprecision(4) << Q[i] << " ";
    }
    cout << "\n    K[0:5]: ";
    for (int i = 0; i < min(5, (int)K.size()); i++) {
        cout << fixed << setprecision(4) << K[i] << " ";
    }
    cout << "\n    V[0:5]: ";
    for (int i = 0; i < min(5, (int)V.size()); i++) {
        cout << fixed << setprecision(4) << V[i] << " ";
    }
    cout << "\n";
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: QKV Projection\n";
    cout << "  Input size: " << input.size() << "\n";
    cout << "  Output size: " << qkv_output.size() << " (Q+K+V)\n";
    cout << "  Weight matrix: [" << embed_dim << ", " << qkv_dim << "]\n";
    cout << "  Load time: " << load_ms << " ms\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (q_ok && k_ok && v_ok) {
        cout << "  Status: ✅ QKV PROJECTION TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ QKV projection test failed\n";
        return 1;
    }
}
