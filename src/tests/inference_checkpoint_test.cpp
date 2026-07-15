// ============================================================================
// RawrXD Inference Checkpoint Integration Test
// Phase 7C: Immutable Execution Fabric Integration
// ============================================================================

#include <cstdio>
#include <cstring>
#include <windows.h>
#include "../core/hash_chain.hpp"

using namespace RawrXD::Core;

int main() {
    printf("========================================\n");
    printf("Inference Checkpoint Integration Test\n");
    printf("Phase 7C: Immutable Execution Fabric\n");
    printf("========================================\n\n");
    
    // Test 1: Initialize inference session
    printf("Test 1: Initialize Inference Session\n");
    printf("--------------------------------------\n");
    
    InferenceCheckpointManager checkpoint_mgr;
    checkpoint_mgr.Initialize(
        0x123456789ABCDEF0ULL,  // model hash
        0xFEDCBA9876543210ULL,  // inference id
        "1.0.0",                // model version
        "performance"           // fabric policy
    );
    
    printf("  Model hash: ");
    char hash_str[32];
    HashChainManager::FormatHash(checkpoint_mgr.GetModelHash(), hash_str, sizeof(hash_str));
    printf("%s\n", hash_str);
    printf("  Inference ID: ");
    HashChainManager::FormatHash(checkpoint_mgr.GetInferenceId(), hash_str, sizeof(hash_str));
    printf("%s\n\n", hash_str);
    
    // Test 2: Simulate embedding checkpoint
    printf("Test 2: Embedding Checkpoint\n");
    printf("------------------------------\n");
    
    float embeddings[4096 * 10];  // 10 tokens x 4096 dim
    for (int i = 0; i < 40960; ++i) {
        embeddings[i] = static_cast<float>(i % 100) / 100.0f;
    }
    
    checkpoint_mgr.CheckpointEmbedding(embeddings, 10, 4096);
    printf("  Submitted embedding checkpoint\n");
    printf("  Pending tickets: %zu\n\n", checkpoint_mgr.GetCurrentChainHash() != 0 ? 1 : 0);
    
    // Test 3: Simulate attention checkpoints
    printf("Test 3: Attention Checkpoints (32 layers)\n");
    printf("-------------------------------------------\n");
    
    float attn_output[4096];  // Single token x 4096 dim
    float k_cache[1024 * 128];  // 1024 tokens x 128 head_dim
    float v_cache[1024 * 128];
    
    for (int i = 0; i < 4096; ++i) attn_output[i] = static_cast<float>(i) / 1000.0f;
    for (int i = 0; i < 1024 * 128; ++i) {
        k_cache[i] = static_cast<float>(i % 50) / 50.0f;
        v_cache[i] = static_cast<float>(i % 50) / 50.0f;
    }
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (uint32_t layer = 0; layer < 32; ++layer) {
        checkpoint_mgr.CheckpointAttentionOutput(attn_output, 1, 4096, layer);
        checkpoint_mgr.CheckpointKVAppend(k_cache, v_cache, 1024, 128, layer);
    }
    
    QueryPerformanceCounter(&end);
    double elapsed = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    
    printf("  Submitted %d attention checkpoints\n", 32);
    printf("  Time: %.2f ms\n", elapsed);
    printf("  Avg per layer: %.2f ms\n\n", elapsed / 32.0);
    
    // Test 4: MLP checkpoints
    printf("Test 4: MLP Checkpoints\n");
    printf("------------------------\n");
    
    float mlp_output[4096];
    for (int i = 0; i < 4096; ++i) mlp_output[i] = static_cast<float>(i) / 1000.0f;
    
    QueryPerformanceCounter(&start);
    for (uint32_t layer = 0; layer < 32; ++layer) {
        checkpoint_mgr.CheckpointPostMLP(mlp_output, 1, 4096, layer);
    }
    QueryPerformanceCounter(&end);
    elapsed = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    
    printf("  Submitted %d MLP checkpoints\n", 32);
    printf("  Time: %.2f ms\n\n", elapsed);
    
    // Test 5: Logits and sampler
    printf("Test 5: Logits and Sampler\n");
    printf("---------------------------\n");
    
    float logits[32000];  // Vocab size
    for (int i = 0; i < 32000; ++i) logits[i] = static_cast<float>(i % 100) / 100.0f;
    
    checkpoint_mgr.CheckpointLogits(logits, 32000, 0);
    checkpoint_mgr.CheckpointSampler(42, 0.8f, 0.9f, 40, 0);
    
    printf("  Submitted logits checkpoint\n");
    printf("  Submitted sampler checkpoint\n\n");
    
    // Test 6: Flush and get chain hash
    printf("Test 6: Flush Checkpoints\n");
    printf("--------------------------\n");
    
    QueryPerformanceCounter(&start);
    checkpoint_mgr.FlushCheckpoints(5000);
    QueryPerformanceCounter(&end);
    elapsed = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
    
    printf("  Flush time: %.2f ms\n", elapsed);
    printf("  Chain hash: ");
    HashChainManager::FormatHash(checkpoint_mgr.GetCurrentChainHash(), hash_str, sizeof(hash_str));
    printf("%s\n\n", hash_str);
    
    // Test 7: Export proof
    printf("Test 7: Export Proof\n");
    printf("---------------------\n");
    
    const char* proof_path = "d:/rawrxd/build_cli/test_proof.rawrproof";
    if (checkpoint_mgr.ExportProof(proof_path)) {
        printf("  Proof exported to: %s\n", proof_path);
        
        // Get file size
        WIN32_FILE_ATTRIBUTE_DATA attrs;
        if (GetFileAttributesExA(proof_path, GetFileExInfoStandard, &attrs)) {
            LARGE_INTEGER size;
            size.HighPart = attrs.nFileSizeHigh;
            size.LowPart = attrs.nFileSizeLow;
            printf("  Proof size: %lld bytes\n\n", size.QuadPart);
        }
    } else {
        printf("  ERROR: Failed to export proof\n\n");
    }
    
    // Test 8: Verify proof
    printf("Test 8: Verify Proof\n");
    printf("---------------------\n");
    
    HashChainManager verify_chain;
    if (verify_chain.ImportChain(proof_path)) {
        printf("  Proof imported successfully\n");
        printf("  Checkpoints: %zu\n", verify_chain.GetCheckpointCount());
        printf("  Chain valid: %s\n", verify_chain.VerifyChain() ? "YES" : "NO");
        printf("  Chain hash:  ");
        HashChainManager::FormatHash(verify_chain.GetCurrentHash(), hash_str, sizeof(hash_str));
        printf("%s\n", hash_str);
        
        // Compare chains
        if (verify_chain.GetCurrentHash() == checkpoint_mgr.GetCurrentChainHash()) {
            printf("  Chain match: YES\n\n");
        } else {
            printf("  Chain match: NO (mismatch!)\n\n");
        }
    } else {
        printf("  ERROR: Failed to import proof\n\n");
    }
    
    printf("========================================\n");
    printf("Integration Test Complete\n");
    printf("========================================\n");
    
    return 0;
}
