/**
 * @file rope_test.cpp
 * @brief Phase 9: RoPE (Rotary Position Embedding)
 * 
 * Applies rotary embeddings to Q and K vectors:
 *   For each pair of dimensions (2i, 2i+1):
 *     [Q_2i, Q_2i+1] = [Q_2i * cos(m*θ) - Q_2i+1 * sin(m*θ), 
 *                       Q_2i * sin(m*θ) + Q_2i+1 * cos(m*θ)]
 *   where m = position, θ = base^(−2i/d)
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

// RoPE (Rotary Position Embedding)
// Applies rotary embeddings to Q and K vectors
void apply_rope(float* vec, int dim, int position, float base = 10000.0f) {
    // Process pairs of dimensions
    for (int i = 0; i < dim; i += 2) {
        // Calculate rotation angle
        // θ_i = position * base^(-2i/dim)
        float theta = position * powf(base, -2.0f * i / dim);
        
        float cos_theta = cosf(theta);
        float sin_theta = sinf(theta);
        
        // Apply rotation to pair
        float v0 = vec[i];
        float v1 = vec[i + 1];
        
        vec[i] = v0 * cos_theta - v1 * sin_theta;
        vec[i + 1] = v0 * sin_theta + v1 * cos_theta;
    }
}

int main() {
    const char* MODEL_PATH = "F:\\ollamamodels\\Phi-3-mini-4k-instruct-q8_0.gguf";
    
    cout << "🔬 RawrXD Phase 9: RoPE Test\n";
    cout << "=============================\n\n";
    
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
        uint64_t dim0, dim1;
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
    
    int embed_dim = qkv_tensor.dim0;      // 3072
    int qkv_dim = qkv_tensor.dim1;        // 9216 = 3 * 3072
    int head_dim = embed_dim;             // 3072
    
    cout << "  ✓ Found: " << qkv_tensor.name << "\n";
    cout << "    Shape: [" << embed_dim << ", " << qkv_dim << "]\n\n";
    
    // Load QKV weights (simplified - just load first few blocks for testing)
    cout << "[3/6] Loading QKV weights...\n";
    
    uint64_t tensor_data_start = 738400;
    uint64_t weight_offset = tensor_data_start + qkv_tensor.offset;
    
    file.seekg(weight_offset, ios::beg);
    
    // For this test, we'll just load enough weights for one projection
    // Full matrix: 3072 * 9216 = 28,311,552 elements
    // We'll load just the first row (3072 elements) for testing
    size_t elements_to_load = embed_dim * 3;  // Just Q, K, V for first position
    size_t blocks_to_load = (elements_to_load + 31) / 32;
    
    vector<float> qkv_weights(elements_to_load);
    float block_weights[32];
    
    for (size_t b = 0; b < blocks_to_load; b++) {
        read_q4_0_block(file, block_weights);
        for (int i = 0; i < 32 && (b * 32 + i) < elements_to_load; i++) {
            qkv_weights[b * 32 + i] = block_weights[i];
        }
    }
    
    cout << "  ✓ Loaded " << qkv_weights.size() << " weights\n\n";
    
    // Create test input and perform QKV projection
    cout << "[4/6] Creating Q, K, V vectors...\n";
    
    // For simplicity, use the loaded weights as our Q, K, V
    // In reality, this would be: Q = input @ W_q, etc.
    vector<float> Q(head_dim);
    vector<float> K(head_dim);
    vector<float> V(head_dim);
    
    // Fill with test values (first elements from weights)
    for (int i = 0; i < head_dim && i < qkv_weights.size(); i++) {
        Q[i] = qkv_weights[i % qkv_weights.size()] * 10.0f;  // Scale up for visibility
        K[i] = qkv_weights[(i + head_dim) % qkv_weights.size()] * 10.0f;
        V[i] = qkv_weights[(i + 2 * head_dim) % qkv_weights.size()] * 10.0f;
    }
    
    cout << "  ✓ Q, K, V created\n";
    cout << "    Q size: " << Q.size() << "\n";
    cout << "    K size: " << K.size() << "\n";
    cout << "    V size: " << V.size() << "\n";
    cout << "    Q[0:5] before RoPE: ";
    for (int i = 0; i < min(5, (int)Q.size()); i++) {
        cout << fixed << setprecision(4) << Q[i] << " ";
    }
    cout << "\n\n";
    
    // Apply RoPE
    cout << "[5/6] Applying RoPE...\n";
    
    int position = 5;  // Test position
    float rope_base = 10000.0f;  // Standard base
    
    auto compute_start = chrono::high_resolution_clock::now();
    
    // Apply RoPE to Q and K (not V)
    apply_rope(Q.data(), Q.size(), position, rope_base);
    apply_rope(K.data(), K.size(), position, rope_base);
    // V is not rotated
    
    auto compute_end = chrono::high_resolution_clock::now();
    auto compute_us = chrono::duration_cast<chrono::microseconds>(compute_end - compute_start).count();
    
    cout << "  ✓ RoPE applied at position " << position << "\n";
    cout << "    Compute time: " << compute_us << " μs\n";
    cout << "    Q[0:5] after RoPE: ";
    for (int i = 0; i < min(5, (int)Q.size()); i++) {
        cout << fixed << setprecision(4) << Q[i] << " ";
    }
    cout << "\n    K[0:5] after RoPE: ";
    for (int i = 0; i < min(5, (int)K.size()); i++) {
        cout << fixed << setprecision(4) << K[i] << " ";
    }
    cout << "\n    V[0:5] (unchanged): ";
    for (int i = 0; i < min(5, (int)V.size()); i++) {
        cout << fixed << setprecision(4) << V[i] << " ";
    }
    cout << "\n\n";
    
    // Validate
    cout << "[6/6] Validating RoPE outputs...\n";
    
    auto validate = [](const vector<float>& vec, const string& name) {
        float min_val = FLT_MAX, max_val = -FLT_MAX;
        bool has_nan_inf = false;
        
        for (float v : vec) {
            if (isnan(v) || isinf(v)) {
                has_nan_inf = true;
                break;
            }
            min_val = min(min_val, v);
            max_val = max(max_val, v);
        }
        
        cout << "  " << name << ":\n";
        cout << "    Range: [" << fixed << setprecision(4) << min_val << ", " << max_val << "]\n";
        cout << "    Valid: " << (has_nan_inf ? "✗" : "✓") << "\n";
        
        return !has_nan_inf;
    };
    
    bool q_ok = validate(Q, "Q (with RoPE)");
    bool k_ok = validate(K, "K (with RoPE)");
    bool v_ok = validate(V, "V (no RoPE)");
    
    // Test that different positions produce different rotations
    cout << "\n  Position sensitivity test:\n";
    vector<float> Q_pos0 = Q;
    vector<float> Q_pos10 = Q;
    
    // Reset to original
    for (int i = 0; i < head_dim && i < qkv_weights.size(); i++) {
        Q_pos0[i] = qkv_weights[i % qkv_weights.size()] * 10.0f;
        Q_pos10[i] = qkv_weights[i % qkv_weights.size()] * 10.0f;
    }
    
    apply_rope(Q_pos0.data(), Q_pos0.size(), 0, rope_base);
    apply_rope(Q_pos10.data(), Q_pos10.size(), 10, rope_base);
    
    float diff = 0.0f;
    for (int i = 0; i < min(10, (int)Q.size()); i++) {
        diff += fabs(Q_pos0[i] - Q_pos10[i]);
    }
    
    cout << "    Q at pos 0 vs pos 10 difference: " << fixed << setprecision(4) << diff << "\n";
    cout << "    Position encoding: " << (diff > 0.01f ? "✓ Working" : "✗ Not working") << "\n";
    
    auto total_end = chrono::high_resolution_clock::now();
    auto total_ms = chrono::duration_cast<chrono::milliseconds>(total_end - start).count();
    
    cout << "\n" << string(60, '=') << "\n";
    cout << "Summary:\n";
    cout << "  Operation: RoPE (Rotary Position Embedding)\n";
    cout << "  Position: " << position << "\n";
    cout << "  Base: " << rope_base << "\n";
    cout << "  Compute time: " << compute_us << " μs\n";
    cout << "  Total time: " << total_ms << " ms\n";
    
    if (q_ok && k_ok && v_ok && diff > 0.01f) {
        cout << "  Status: ✅ ROPE TEST PASSED\n";
        return 0;
    } else {
        cout << "  Status: ❌ RoPE test failed\n";
        return 1;
    }
}
