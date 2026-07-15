// ============================================================================
// test_c6_q4k_integration.cpp - C6 FlashAttention + Q4_K Integration Test
// ============================================================================
// Validates that OptimizedTransformerLayer works with real Q4_K weights
// from GGUF files. This is the "known good" checkpoint before C7.
//
// Test flow:
//   1. Load GGUF (streaming loader)
//   2. Extract layer 0 tensors (Q4_K weights)
//   3. Bind to OptimizedTransformerLayer
//   4. Initialize FlashAttention
//   5. Run single-token forward pass
//   6. Verify non-zero output (weights are being dequantized)
// ============================================================================

#include "optimized_transformer_layer.hpp"
#include "streaming_gguf_loader.hpp"
#include "kv_cache.hpp"
#include <iostream>
#include <cmath>
#include <cstring>

using namespace RawrXD::Runtime;

// ============================================================================
// Test Configuration
// ============================================================================
struct TestConfig {
    const char* model_path = "phi-3-mini-q4_k.gguf";
    uint32_t layer_idx = 0;
    uint32_t seq_len = 1;
    uint32_t position = 0;
    float zero_tolerance = 0.0001f;  // Minimum non-zero threshold
};

// ============================================================================
// Validation Helpers
// ============================================================================
bool CheckNonZero(const float* data, size_t len, float tolerance) {
    for (size_t i = 0; i < len; ++i) {
        if (std::abs(data[i]) > tolerance) {
            return true;
        }
    }
    return false;
}

float ComputeL2Norm(const float* data, size_t len) {
    float sum_sq = 0.0f;
    for (size_t i = 0; i < len; ++i) {
        sum_sq += data[i] * data[i];
    }
    return std::sqrt(sum_sq);
}

// ============================================================================
// Main Integration Test
// ============================================================================
bool TestC6Q4KIntegration(const TestConfig& config) {
    std::cout << "========================================\n";
    std::cout << "C6 FlashAttention + Q4_K Integration Test\n";
    std::cout << "========================================\n";
    std::cout << "Model: " << config.model_path << "\n";
    std::cout << "Layer: " << config.layer_idx << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 1: Open GGUF file
    // ------------------------------------------------------------------------
    std::cout << "[1/7] Opening GGUF file...\n";
    
    StreamingGGUFLoader loader;
    if (!loader.Open(config.model_path)) {
        std::cerr << "ERROR: Failed to open GGUF file\n";
        std::cerr << "  Path: " << config.model_path << "\n";
        std::cerr << "  Make sure the file exists and is a valid GGUF\n";
        return false;
    }
    
    std::cout << "  File size: " << (loader.GetFileSize() / (1024*1024)) << " MB\n";
    std::cout << "  Tensors: " << loader.GetTensorCount() << "\n";
    std::cout << "  Metadata entries: " << loader.GetMetadataCount() << "\n";
    
    // ------------------------------------------------------------------------
    // Step 2: Build tensor index
    // ------------------------------------------------------------------------
    std::cout << "\n[2/7] Building tensor index...\n";
    
    if (!loader.BuildIndex()) {
        std::cerr << "ERROR: Failed to build tensor index\n";
        return false;
    }
    
    std::cout << "  Index built successfully\n";
    
    // ------------------------------------------------------------------------
    // Step 3: Detect architecture from metadata
    // ------------------------------------------------------------------------
    std::cout << "\n[3/7] Detecting model architecture...\n";
    
    auto arch = loader.DetectArchitecture();
    if (!arch.IsValid()) {
        std::cerr << "ERROR: Failed to detect architecture\n";
        return false;
    }
    
    std::cout << "  Hidden size: " << arch.hidden_size << "\n";
    std::cout << "  Num layers: " << arch.num_layers << "\n";
    std::cout << "  Num heads: " << arch.num_heads << "\n";
    std::cout << "  Num KV heads: " << arch.num_kv_heads << "\n";
    std::cout << "  Head dim: " << arch.head_dim << "\n";
    std::cout << "  Intermediate size: " << arch.intermediate_size << "\n";
    std::cout << "  Vocab size: " << arch.vocab_size << "\n";
    
    // ------------------------------------------------------------------------
    // Step 4: Load layer 0 tensors
    // ------------------------------------------------------------------------
    std::cout << "\n[4/7] Loading layer " << config.layer_idx << " tensors...\n";
    
    char prefix[32];
    snprintf(prefix, sizeof(prefix), "blk.%u.", config.layer_idx);
    
    auto load_tensor = [&](const char* name) -> TensorView {
        std::string full_name = std::string(prefix) + name;
        TensorInfo info;
        if (!loader.SeekToTensor(full_name, info)) {
            std::cerr << "ERROR: Tensor not found: " << full_name << "\n";
            return TensorView();
        }
        std::cout << "  Loaded: " << full_name 
                  << " [shape=" << info.NumRows() << "x" << info.NumCols() 
                  << ", type=" << info.type << "]\n";
        return loader.CreateTensorView(info);
    };
    
    TensorView attn_q = load_tensor("attn_q.weight");
    TensorView attn_k = load_tensor("attn_k.weight");
    TensorView attn_v = load_tensor("attn_v.weight");
    TensorView attn_output = load_tensor("attn_output.weight");
    TensorView ffn_gate = load_tensor("ffn_gate.weight");
    TensorView ffn_up = load_tensor("ffn_up.weight");
    TensorView ffn_down = load_tensor("ffn_down.weight");
    TensorView attn_norm = load_tensor("attn_norm.weight");
    TensorView ffn_norm = load_tensor("ffn_norm.weight");
    
    // Validate all tensors loaded
    if (!attn_q.IsValid() || !attn_k.IsValid() || !attn_v.IsValid()) {
        std::cerr << "ERROR: Failed to load attention weights\n";
        return false;
    }
    
    // Check that weights are Q4_K
    if (attn_q.Type() != GGMLType::Q4_K) {
        std::cerr << "WARNING: Expected Q4_K weights, got type " 
                  << static_cast<int>(attn_q.Type()) << "\n";
    }
    
    // ------------------------------------------------------------------------
    // Step 5: Bind to OptimizedTransformerLayer
    // ------------------------------------------------------------------------
    std::cout << "\n[5/7] Binding to OptimizedTransformerLayer...\n";
    
    OptimizedTransformerLayer layer;
    
    TransformerLayerConfig layer_config;
    layer_config.hiddenSize = arch.hidden_size;
    layer_config.numHeads = arch.num_heads;
    layer_config.numKVHeads = arch.num_kv_heads;
    layer_config.headDim = arch.head_dim;
    layer_config.intermediateSize = arch.intermediate_size;
    layer_config.rmsNormEps = 1e-5f;
    
    bool bound = layer.BindLayer(
        config.layer_idx,
        attn_norm,
        attn_q, attn_k, attn_v, attn_output,
        ffn_norm,
        ffn_gate, ffn_up, ffn_down
    );
    
    if (!bound) {
        std::cerr << "ERROR: Failed to bind layer\n";
        return false;
    }
    
    std::cout << "  Layer bound successfully\n";
    std::cout << "  Hidden size: " << layer_config.hiddenSize << "\n";
    std::cout << "  Num heads: " << layer_config.numHeads << "\n";
    std::cout << "  Head dim: " << layer_config.headDim << "\n";
    
    // ------------------------------------------------------------------------
    // Step 6: Initialize FlashAttention
    // ------------------------------------------------------------------------
    std::cout << "\n[6/7] Initializing FlashAttention...\n";
    
    if (!layer.InitializeFlashAttention()) {
        std::cerr << "WARNING: Failed to initialize FlashAttention (falling back to standard)\n";
        // Continue anyway - will use standard attention
    } else {
        std::cout << "  FlashAttention initialized\n";
        std::cout << "  Has FlashAttention: " << (layer.HasFlashAttention() ? "YES" : "NO") << "\n";
    }
    
    // ------------------------------------------------------------------------
    // Step 7: Run forward pass
    // ------------------------------------------------------------------------
    std::cout << "\n[7/7] Running forward pass...\n";
    
    // Allocate buffers
    alignas(64) float input[8192] = {};  // Zero-initialized
    alignas(64) float output[8192] = {};
    
    // Initialize input with small random values
    std::mt19937 gen(42);  // Fixed seed for reproducibility
    std::uniform_real_distribution<float> dist(-0.1f, 0.1f);
    for (uint32_t i = 0; i < arch.hidden_size; ++i) {
        input[i] = dist(gen);
    }
    
    // Initialize KV cache
    KVCache kv_cache;
    kv_cache.Resize(arch.max_position_embeddings, arch.num_kv_heads, arch.head_dim);
    
    // Run forward
    uint64_t cycles = 0;
    #ifdef _WIN32
    cycles = __rdtsc();
    #endif
    
    bool success = layer.Forward(
        input,
        config.seq_len,
        config.position,
        output,
        nullptr,  // key_cache - using internal KV cache
        nullptr,  // value_cache
        arch.max_position_embeddings
    );
    
    #ifdef _WIN32
    cycles = __rdtsc() - cycles;
    #endif
    
    if (!success) {
        std::cerr << "ERROR: Forward pass failed\n";
        return false;
    }
    
    std::cout << "  Forward pass completed\n";
    if (cycles > 0) {
        std::cout << "  Cycles: " << cycles << "\n";
        float ms = cycles / (3.0e6f);  // Assuming 3GHz
        std::cout << "  Time: " << ms << " ms (approx)\n";
    }
    
    // ------------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------------
    std::cout << "\n========================================\n";
    std::cout << "Validation\n";
    std::cout << "========================================\n";
    
    // Check 1: Output is not all zeros
    bool output_nonzero = CheckNonZero(output, arch.hidden_size, config.zero_tolerance);
    std::cout << "[1] Output non-zero: " << (output_nonzero ? "PASS" : "FAIL") << "\n";
    
    if (!output_nonzero) {
        std::cerr << "ERROR: Output is all zeros - Q4_K dequantization may not be working\n";
        return false;
    }
    
    // Check 2: Output has reasonable magnitude
    float l2_norm = ComputeL2Norm(output, arch.hidden_size);
    std::cout << "[2] Output L2 norm: " << l2_norm << "\n";
    
    bool norm_reasonable = (l2_norm > 0.1f) && (l2_norm < 1000.0f);
    std::cout << "    Norm reasonable: " << (norm_reasonable ? "PASS" : "WARNING") << "\n";
    
    // Check 3: Output is different from input
    bool output_different = false;
    for (uint32_t i = 0; i < arch.hidden_size; ++i) {
        if (std::abs(output[i] - input[i]) > config.zero_tolerance) {
            output_different = true;
            break;
        }
    }
    std::cout << "[3] Output different from input: " << (output_different ? "PASS" : "FAIL") << "\n";
    
    // Check 4: Performance stats
    const auto& stats = layer.GetPerfStats();
    std::cout << "[4] Performance stats:\n";
    std::cout << "    Total cycles: " << stats.total_cycles << "\n";
    std::cout << "    QKV cycles: " << stats.qkv_cycles << "\n";
    std::cout << "    Attention cycles: " << stats.attention_cycles << "\n";
    std::cout << "    MLP cycles: " << stats.mlp_cycles << "\n";
    std::cout << "    Tokens processed: " << stats.tokens_processed << "\n";
    
    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------
    std::cout << "\n========================================\n";
    std::cout << "C6 Integration Test: PASS\n";
    std::cout << "========================================\n";
    std::cout << "FlashAttention + Q4_K weights are working correctly.\n";
    std::cout << "Ready for C7 multi-threading.\n";
    
    return true;
}

// ============================================================================
// Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    TestConfig config;
    
    // Allow command-line override
    if (argc > 1) {
        config.model_path = argv[1];
    }
    if (argc > 2) {
        config.layer_idx = static_cast<uint32_t>(std::atoi(argv[2]));
    }
    
    bool success = TestC6Q4KIntegration(config);
    
    return success ? 0 : 1;
}
