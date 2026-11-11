// ============================================================================
// RawrXD Phase 7D: GGUF Load Test with Checkpoints
// ============================================================================
// Tests loading a real GGUF file and computing hashes with checkpoint hooks
// This is a standalone test that doesn't require the full inference engine
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "../integration/gguf_checkpoint_hooks.hpp"
#include "../gguf/gguf_loader_minimal.cpp"

using namespace RawrXD;

// Simple SHA256 computation for model verification
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

int main(int argc, char* argv[]) {
    printf("=====================================================================\n");
    printf("RawrXD Phase 7D: GGUF Load Test with Checkpoints\n");
    printf("=====================================================================\n\n");
    
    // Parse arguments
    const char* model_path = (argc > 1) ? argv[1] : "models/tinyllama.gguf";
    
    printf("Configuration:\n");
    printf("  Model: %s\n\n", model_path);
    
    // Check model file exists
    FILE* f = fopen(model_path, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: Model file not found: %s\n", model_path);
        fprintf(stderr, "Please provide a valid GGUF model file path.\n");
        fprintf(stderr, "\nUsage: %s <model.gguf>\n", argv[0]);
        return 1;
    }
    fclose(f);
    
    // Compute model hash
    printf("Step 1: Computing model hash...\n");
    std::string model_hash = ComputeFileSHA256(model_path);
    printf("  Model hash: %s\n\n", model_hash.c_str());
    
    // Initialize checkpoint context
    printf("Step 2: Initializing checkpoint context...\n");
    Integration::GGUFCheckpointContext* ctx = new Integration::GGUFCheckpointContext();
    
    if (!Integration::GGUFCheckpoint_Init(ctx, model_path, "phase7d-gguf-test", "tiered_memory")) {
        fprintf(stderr, "ERROR: Failed to initialize checkpoint context\n");
        return 1;
    }
    
    printf("  Checkpoint context initialized\n");
    printf("  Model hash: 0x%016llX\n", ctx->model_hash);
    printf("  Enabled: %s\n\n", ctx->enabled ? "YES" : "NO");
    
    // Load GGUF file
    printf("Step 3: Loading GGUF file...\n");
    GGUF::GGUFContext* gguf = GGUF::LoadGGUF(model_path);
    
    if (!gguf) {
        fprintf(stderr, "ERROR: Failed to load GGUF file\n");
        return 1;
    }
    
    if (!gguf->valid) {
        fprintf(stderr, "ERROR: GGUF file invalid: %s\n", gguf->error_msg);
        GGUF::FreeGGUF(gguf);
        return 1;
    }
    
    printf("  GGUF loaded successfully\n");
    printf("  Version: %u\n", gguf->version);
    printf("  Tensors: %zu\n", gguf->tensors.size());
    printf("  KV pairs: %llu\n\n", (unsigned long long)gguf->kv_count);
    
    // Print tensor info
    printf("Step 4: Tensor information (first 10 tensors):\n");
    size_t tensors_to_show = (gguf->tensors.size() < 10) ? gguf->tensors.size() : 10;
    for (size_t i = 0; i < tensors_to_show; i++) {
        const auto& tensor = gguf->tensors[i];
        printf("  [%zu] %s: [", i, tensor.name.c_str());
        for (size_t d = 0; d < tensor.dimensions.size(); d++) {
            if (d > 0) printf(", ");
            printf("%llu", (unsigned long long)tensor.dimensions[d]);
        }
        printf("] type=%u, size=%zu bytes\n", 
               static_cast<uint32_t>(tensor.type), tensor.data.size());
    }
    printf("\n");
    
    // Hash some tensors
    printf("Step 5: Hashing tensors...\n");
    for (size_t i = 0; i < tensors_to_show; i++) {
        const auto& tensor = gguf->tensors[i];
        uint64_t tensor_hash = Integration::GGUFCheckpoint_HashTensor(
            tensor.data.data(), tensor.data.size(), 
            static_cast<uint32_t>(tensor.type), static_cast<uint32_t>(i));
        printf("  [%zu] %s hash: 0x%016llX\n", i, tensor.name.c_str(), tensor_hash);
    }
    printf("\n");
    
    // Export proof
    printf("Step 6: Exporting proof...\n");
    std::string proof_path = "phase7d_gguf_" + model_hash + ".rawrproof";
    
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
    GGUF::FreeGGUF(gguf);
    
    printf("\n=====================================================================\n");
    printf("GGUF Load Test Complete\n");
    printf("=====================================================================\n");
    printf("\nNext steps:\n");
    printf("  1. Run determinism test: scripts\\test_determinism.bat\n");
    printf("  2. Compare with llama.cpp: scripts\\compare_llamacpp_rawrxd.ps1\n");
    printf("  3. Full audit: scripts\\audit_run_realmodel.bat\n");
    
    return 0;
}
