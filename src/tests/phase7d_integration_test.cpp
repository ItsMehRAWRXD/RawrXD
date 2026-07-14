// ============================================================================
// RawrXD Phase 7D Integration Test
// Tests checkpoint hooks with synthetic data before real model integration
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cstring>
#include "../integration/gguf_checkpoint_hooks.hpp"

using namespace RawrXD::Integration;
using namespace RawrXD::Core;

// Synthetic transformer simulation
void SimulateTransformerLayer(
    GGUFCheckpointContext* ctx,
    float* input,
    float* output,
    size_t seq_len,
    size_t hidden_dim,
    uint32_t layer_idx) {
    
    // Simulate RMSNorm
    for (size_t i = 0; i < seq_len * hidden_dim; i++) {
        output[i] = input[i] * 0.95f;  // Simplified
    }
    
    RAWRXD_CHECKPOINT_RMSNORM(ctx, output, seq_len, hidden_dim, layer_idx);
    
    // Simulate attention
    float* attn_out = new float[seq_len * hidden_dim];
    for (size_t i = 0; i < seq_len * hidden_dim; i++) {
        attn_out[i] = output[i] * 0.9f;
    }
    
    RAWRXD_CHECKPOINT_ATTENTION(ctx, attn_out, seq_len, hidden_dim, layer_idx);
    
    // Simulate KV cache
    size_t kv_len = seq_len;
    size_t head_dim = hidden_dim / 32;
    float* k_cache = new float[kv_len * 32 * head_dim];
    float* v_cache = new float[kv_len * 32 * head_dim];
    
    for (size_t i = 0; i < kv_len * 32 * head_dim; i++) {
        k_cache[i] = attn_out[i % (seq_len * hidden_dim)] * 0.8f;
        v_cache[i] = attn_out[i % (seq_len * hidden_dim)] * 0.7f;
    }
    
    RAWRXD_CHECKPOINT_KV_CACHE(ctx, k_cache, v_cache, kv_len, head_dim, layer_idx);
    
    // Simulate FFN
    for (size_t i = 0; i < seq_len * hidden_dim; i++) {
        output[i] = attn_out[i] * 1.1f;
    }
    
    RAWRXD_CHECKPOINT_FFN(ctx, output, seq_len, hidden_dim, layer_idx);
    
    delete[] attn_out;
    delete[] k_cache;
    delete[] v_cache;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("Phase 7D Integration Test\n");
    printf("Testing checkpoint hooks with synthetic data\n");
    printf("========================================\n\n");
    
    // Test configuration
    const uint32_t NUM_LAYERS = 4;  // Small for testing
    const uint32_t SEQ_LEN = 8;
    const uint32_t HIDDEN_DIM = 128;
    const uint32_t VOCAB_SIZE = 1000;
    
    // Initialize checkpoint context
    printf("Initializing checkpoint context...\n");
    GGUFCheckpointContext* ctx = new GGUFCheckpointContext();
    
    // Create a dummy model file for hash computation
    const char* dummy_model = "test_model.gguf";
    FILE* f = fopen(dummy_model, "wb");
    if (f) {
        // Write dummy GGUF header
        const char header[] = "GGUF";
        fwrite(header, 1, 4, f);
        uint32_t version = 3;
        fwrite(&version, 4, 1, f);
        uint64_t n_tensors = 10;
        fwrite(&n_tensors, 8, 1, f);
        uint64_t n_kv = 5;
        fwrite(&n_kv, 8, 1, f);
        fclose(f);
    }
    
    bool init_ok = GGUFCheckpoint_Init(ctx, 
        dummy_model, 
        "test-model-v1", 
        "tiered_memory");
    
    if (!init_ok) {
        fprintf(stderr, "Failed to initialize checkpoint context\n");
        return 1;
    }
    
    printf("  Model hash: 0x%016llX\n", ctx->model_hash);
    printf("  Checkpoints enabled: %s\n\n", ctx->enabled ? "YES" : "NO");
    
    // Simulate inference
    printf("Simulating %d transformer layers...\n", NUM_LAYERS);
    
    std::vector<float> embeddings(SEQ_LEN * HIDDEN_DIM);
    std::vector<float> layer_input(SEQ_LEN * HIDDEN_DIM);
    std::vector<float> layer_output(SEQ_LEN * HIDDEN_DIM);
    std::vector<float> logits(VOCAB_SIZE);
    
    // Initialize with deterministic values
    for (size_t i = 0; i < embeddings.size(); i++) {
        embeddings[i] = static_cast<float>(i % 100) / 100.0f;
    }
    
    // Checkpoint embeddings
    RAWRXD_CHECKPOINT_EMBEDDING(ctx, embeddings.data(), SEQ_LEN, HIDDEN_DIM);
    printf("  [Layer 0] Embeddings checkpointed\n");
    
    // Copy to layer input
    memcpy(layer_input.data(), embeddings.data(), embeddings.size() * sizeof(float));
    
    // Run transformer layers
    for (uint32_t layer = 0; layer < NUM_LAYERS; layer++) {
        printf("  [Layer %d] Processing...\n", layer + 1);
        
        SimulateTransformerLayer(ctx,
            layer_input.data(),
            layer_output.data(),
            SEQ_LEN,
            HIDDEN_DIM,
            layer);
        
        // Swap buffers
        std::swap(layer_input, layer_output);
    }
    
    // Simulate logits computation
    for (size_t i = 0; i < VOCAB_SIZE; i++) {
        logits[i] = static_cast<float>(i % 100) / 100.0f;
    }
    
    RAWRXD_CHECKPOINT_LOGITS(ctx, logits.data(), VOCAB_SIZE, 0);
    printf("  [Output] Logits checkpointed\n");
    
    // Simulate sampling
    int32_t selected_token = 42;
    float temperature = 0.8f;
    float top_p = 0.9f;
    int32_t top_k = 40;
    
    RAWRXD_CHECKPOINT_SAMPLER(ctx, selected_token, temperature, top_p, top_k, 0);
    printf("  [Sampler] Token %d selected\n", selected_token);
    
    // Get statistics
    uint32_t tensors_hashed = 0;
    uint64_t bytes_hashed = 0;
    double hash_time_ms = 0.0;
    
    GGUFCheckpoint_GetStats(ctx, &tensors_hashed, &bytes_hashed, &hash_time_ms);
    
    printf("\nCheckpoint Statistics:\n");
    printf("  Tensors hashed: %u\n", tensors_hashed);
    printf("  Bytes hashed: %llu\n", bytes_hashed);
    printf("  Hash time: %.2f ms\n", hash_time_ms);
    
    // Export proof
    printf("\nExporting proof...\n");
    const char* proof_path = "test_integration.rawrproof";
    
    if (GGUFCheckpoint_ExportProof(ctx, proof_path)) {
        printf("  Proof exported to: %s\n", proof_path);
        
        // Verify file exists
        FILE* proof_file = fopen(proof_path, "rb");
        if (proof_file) {
            fseek(proof_file, 0, SEEK_END);
            size_t proof_size = ftell(proof_file);
            fclose(proof_file);
            printf("  Proof file size: %zu bytes\n", proof_size);
        }
    } else {
        printf("  ERROR: Failed to export proof\n");
    }
    
    // Cleanup
    remove(dummy_model);
    
    printf("\n========================================\n");
    printf("Integration Test Complete\n");
    printf("========================================\n");
    printf("\nNext steps:\n");
    printf("  1. Build real model: build_realmodel.bat\n");
    printf("  2. Run audit: scripts\\audit_run_realmodel.bat model.gguf quick\n");
    printf("  3. Compare: scripts\\compare_llamacpp_rawrxd.ps1\n");
    
    return 0;
}
