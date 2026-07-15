// ============================================================================
// RawrXD Phase 7D: Real Model Smoke Test
// ============================================================================
// Tests checkpoint hooks with a real GGUF model file
// This is the first real-model test before full integration
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include "../integration/gguf_checkpoint_hooks.hpp"
#include "../inference/InferenceEngine.h"

using namespace RawrXD;

// ============================================================================
// Simple SHA256 computation for model verification
// ============================================================================

std::string ComputeFileSHA256(const char* filepath) {
    FILE* f = fopen(filepath, "rb");
    if (!f) return "";
    
    // Simple hash - in production use proper SHA256
    uint64_t hash = 0x9E3779B97F4A7C15ULL;
    uint8_t buffer[4096];
    size_t read;
    
    while ((read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        for (size_t i = 0; i < read; i++) {
            hash = hash * 31 + buffer[i];
        }
    }
    
    fclose(f);
    
    char result[32];
    snprintf(result, sizeof(result), "%016llX", hash);
    return std::string(result);
}

// ============================================================================
// Main Test
// ============================================================================

int main(int argc, char* argv[]) {
    printf("=====================================================================\n");
    printf("RawrXD Phase 7D: Real Model Smoke Test\n");
    printf("=====================================================================\n\n");
    
    // Parse arguments
    const char* model_path = (argc > 1) ? argv[1] : "models/tinyllama.gguf";
    const char* prompt = (argc > 2) ? argv[2] : "Hello world";
    int max_tokens = (argc > 3) ? atoi(argv[3]) : 10;
    int seed = 42;
    
    printf("Configuration:\n");
    printf("  Model: %s\n", model_path);
    printf("  Prompt: \"%s\"\n", prompt);
    printf("  Max tokens: %d\n", max_tokens);
    printf("  Seed: %d\n\n", seed);
    
    // Check model file exists
    FILE* f = fopen(model_path, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Model file not found: %s\n", model_path);
        fprintf(stderr, "Please provide a valid GGUF model file path.\n");
        return 1;
    }
    fclose(f);
    
    // Compute model hash
    printf("Computing model hash...\n");
    std::string model_hash = ComputeFileSHA256(model_path);
    printf("  Model hash: %s\n\n", model_hash.c_str());
    
    // Initialize checkpoint context
    printf("Initializing checkpoint context...\n");
    Integration::GGUFCheckpointContext* ctx = new Integration::GGUFCheckpointContext();
    
    if (!Integration::GGUFCheckpoint_Init(ctx, model_path, "phase7d-smoke", "tiered_memory")) {
        fprintf(stderr, "ERROR: Failed to initialize checkpoint context\n");
        return 1;
    }
    
    printf("  Checkpoint context initialized\n");
    printf("  Model hash: 0x%016llX\n", ctx->model_hash);
    printf("  Enabled: %s\n\n", ctx->enabled ? "YES" : "NO");
    
    // Initialize inference engine
    printf("Initializing inference engine...\n");
    
    Inference::EngineConfig config;
    config.modelPath = model_path;
    config.useGPU = false;  // CPU-only for determinism
    config.numThreads = 1;
    config.validateTensors = true;
    
    auto engine = Inference::InferenceEngine::Create(config);
    if (!engine) {
        fprintf(stderr, "ERROR: Failed to create inference engine\n");
        return 1;
    }
    
    if (!engine->LoadModel(model_path)) {
        fprintf(stderr, "ERROR: Failed to load model\n");
        return 1;
    }
    
    printf("  Engine initialized successfully\n\n");
    
    // Set up generation parameters
    Inference::GenerationParams params;
    params.maxTokens = max_tokens;
    params.seed = seed;
    params.temperature = 0.8f;
    params.topP = 0.9f;
    params.topK = 40;
    
    // Hash the prompt
    uint64_t prompt_hash = 0;
    for (const char* p = prompt; *p; p++) {
        prompt_hash = prompt_hash * 31 + static_cast<uint64_t>(*p);
    }
    ctx->prompt_hash = prompt_hash;
    
    // Generate
    printf("Generating...\n");
    printf("---------------------------------------------------------------------\n");
    
    auto start = std::chrono::high_resolution_clock::now();
    auto result = engine->Generate(prompt, params);
    auto end = std::chrono::high_resolution_clock::now();
    
    printf("---------------------------------------------------------------------\n\n");
    
    if (!result.success) {
        fprintf(stderr, "ERROR: Generation failed: %s\n", result.errorMessage.c_str());
        return 1;
    }
    
    // Print results
    printf("Generated text:\n");
    printf("  %s\n\n", result.text.c_str());
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    float tps = result.tokens.size() * 1000.0f / duration.count();
    
    printf("Statistics:\n");
    printf("  Tokens generated: %zu\n", result.tokens.size());
    printf("  Time: %lld ms\n", duration.count());
    printf("  TPS: %.2f\n", tps);
    
    // Export proof
    printf("\nExporting proof...\n");
    std::string proof_path = "phase7d_smoke_" + model_hash + ".rawrproof";
    
    if (Integration::GGUFCheckpoint_ExportProof(ctx, proof_path.c_str())) {
        printf("  Proof exported to: %s\n", proof_path.c_str());
        
        // Get file size
        FILE* pf = fopen(proof_path.c_str(), "rb");
        if (pf) {
            fseek(pf, 0, SEEK_END);
            size_t size = ftell(pf);
            fclose(pf);
            printf("  Proof size: %zu bytes\n", size);
        }
    } else {
        printf("  WARNING: Failed to export proof\n");
    }
    
    // Get checkpoint stats
    uint32_t tensors = 0;
    uint64_t bytes = 0;
    double hash_time = 0.0;
    Integration::GGUFCheckpoint_GetStats(ctx, &tensors, &bytes, &hash_time);
    
    printf("\nCheckpoint statistics:\n");
    printf("  Tensors hashed: %u\n", tensors);
    printf("  Bytes hashed: %llu\n", bytes);
    printf("  Hash time: %.2f ms\n", hash_time);
    
    // Cleanup
    delete ctx;
    
    printf("\n=====================================================================\n");
    printf("Smoke Test Complete\n");
    printf("=====================================================================\n");
    printf("\nNext steps:\n");
    printf("  1. Verify proof: .\\build_cli\\verify_proof.exe %s %s\n", model_path, proof_path.c_str());
    printf("  2. Run determinism test (3x with same seed)\n");
    printf("  3. Compare with llama.cpp reference\n");
    
    return 0;
}
