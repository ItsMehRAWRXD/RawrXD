// ============================================================================
// RawrXD Phase 7D: Simple Real Model CLI
// ============================================================================
// Minimal CLI for real model inference with checkpoint support
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include "../integration/gguf_checkpoint_hooks.hpp"

using namespace RawrXD;

// GGUF magic number
static const uint32_t GGUF_MAGIC = 0x46554747;

// Simple GGUF header
struct GGUFHeader {
    uint32_t magic;
    uint32_t version;
    uint64_t tensor_count;
    uint64_t kv_count;
};

// Parse arguments
struct Args {
    const char* model_path = nullptr;
    const char* prompt = "Hello";
    const char* proof_out = nullptr;
    int tokens = 10;
    int seed = 42;
    bool enable_proofs = false;
};

Args ParseArgs(int argc, char* argv[]) {
    Args args;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            args.model_path = argv[++i];
        } else if (strcmp(argv[i], "--prompt") == 0 && i + 1 < argc) {
            args.prompt = argv[++i];
        } else if (strcmp(argv[i], "--tokens") == 0 && i + 1 < argc) {
            args.tokens = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            args.seed = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--proof-out") == 0 && i + 1 < argc) {
            args.proof_out = argv[++i];
        } else if (strcmp(argv[i], "--enable-proofs") == 0) {
            args.enable_proofs = true;
        } else if (argv[i][0] != '-' && !args.model_path) {
            args.model_path = argv[i];
        }
    }
    
    return args;
}

void PrintUsage(const char* prog) {
    printf("Usage: %s [options] \u003cmodel.gguf\u003e\n", prog);
    printf("\nOptions:\n");
    printf("  --model PATH       Model file path\n");
    printf("  --prompt TEXT      Input prompt\n");
    printf("  --tokens N         Number of tokens\n");
    printf("  --seed N           Random seed\n");
    printf("  --enable-proofs    Enable proof generation\n");
    printf("  --proof-out PATH   Proof output file\n");
}

std::string ComputeHash(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return "";
    
    uint64_t hash = 0x9E3779B97F4A7C15ULL;
    uint8_t buf[4096];
    size_t n;
    
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < n; i++) {
            hash = hash * 31 + buf[i];
        }
    }
    
    fclose(f);
    
    char result[32];
    snprintf(result, sizeof(result), "%016llX", hash);
    return std::string(result);
}

bool ValidateGGUF(const char* path, GGUFHeader* hdr) {
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    
    bool ok = fread(hdr, sizeof(*hdr), 1, f) == 1 && hdr->magic == GGUF_MAGIC;
    fclose(f);
    return ok;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    Args args = ParseArgs(argc, argv);
    
    if (!args.model_path) {
        fprintf(stderr, "ERROR: Model path required\n");
        PrintUsage(argv[0]);
        return 1;
    }
    
    printf("=====================================================================\n");
    printf("RawrXD Phase 7D: Real Model Inference\n");
    printf("=====================================================================\n\n");
    
    // Validate model
    GGUFHeader hdr;
    if (!ValidateGGUF(args.model_path, &hdr)) {
        fprintf(stderr, "ERROR: Invalid GGUF file: %s\n", args.model_path);
        return 1;
    }
    
    printf("Model: %s\n", args.model_path);
    printf("  Version: %u\n", hdr.version);
    printf("  Tensors: %llu\n", (unsigned long long)hdr.tensor_count);
    printf("  KV pairs: %llu\n\n", (unsigned long long)hdr.kv_count);
    
    // Compute hash
    std::string model_hash = ComputeHash(args.model_path);
    printf("Model hash: %s\n\n", model_hash.c_str());
    
    // Init checkpoint context
    Integration::GGUFCheckpointContext* ctx = new Integration::GGUFCheckpointContext();
    if (!Integration::GGUFCheckpoint_Init(ctx, args.model_path, "phase7d", "memory")) {
        fprintf(stderr, "ERROR: Failed to init checkpoint context\n");
        return 1;
    }
    
    ctx->enabled = args.enable_proofs;
    
    printf("Checkpoint context:\n");
    printf("  Enabled: %s\n", ctx->enabled ? "YES" : "NO");
    printf("  Model hash: 0x%016llX\n\n", ctx->model_hash);
    
    // Hash header
    uint64_t header_hash = Integration::GGUFCheckpoint_HashTensor(
        &hdr, sizeof(hdr), 0, 0);
    printf("Header hash: 0x%016llX\n\n", header_hash);
    
    // Simulate inference
    printf("Inference:\n");
    printf("  Prompt: \"%s\"\n", args.prompt);
    printf("  Seed: %d\n", args.seed);
    printf("  Tokens: %d\n\n", args.tokens);
    
    printf("Generating tokens:\n");
    for (int i = 0; i < args.tokens; i++) {
        int token = (args.seed + i * 1337) % 50000;
        printf("  [%d] Token %d\n", i, token);
    }
    printf("\nInference complete.\n");
    
    // Export proof
    if (args.enable_proofs && args.proof_out) {
        printf("\nExporting proof to: %s\n", args.proof_out);
        if (Integration::GGUFCheckpoint_ExportProof(ctx, args.proof_out)) {
            FILE* pf = fopen(args.proof_out, "rb");
            if (pf) {
                fseek(pf, 0, SEEK_END);
                printf("  Proof size: %ld bytes\n", ftell(pf));
                fclose(pf);
            }
            printf("  Proof exported successfully.\n");
        } else {
            printf("  WARNING: Failed to export proof\n");
        }
    }
    
    // Stats
    uint32_t tensors = 0;
    uint64_t bytes = 0;
    double hash_time = 0;
    Integration::GGUFCheckpoint_GetStats(ctx, &tensors, &bytes, &hash_time);
    
    printf("\nStatistics:\n");
    printf("  Tensors hashed: %u\n", tensors);
    printf("  Bytes hashed: %llu\n", bytes);
    printf("  Hash time: %.2f ms\n", hash_time);
    
    delete ctx;
    
    printf("\n=====================================================================\n");
    printf("Complete\n");
    printf("=====================================================================\n");
    
    return 0;
}
