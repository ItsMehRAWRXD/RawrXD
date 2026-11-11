// ============================================================================
// RawrXD Phase 7D: Real Model CLI with Checkpoint Verification
// ============================================================================
// Command-line interface for running real GGUF models with cryptographic proofs
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string>
#include <string>
#include <vector>
#include "../integration/InferenceEngine_checkpoint_wrapper.hpp"
#include "../inference/InferenceEngine.h"

using namespace RawrXD;

// ============================================================================
// Command Line Arguments
// ============================================================================

struct CliArgs {
    std::string model_path;
    std::string prompt = "Hello world";
    std::string proof_output = "";
    int max_tokens = 10;
    int seed = 42;
    float temperature = 0.8f;
    float top_p = 0.9f;
    int top_k = 40;
    bool enable_proofs = false;
    bool verbose = false;
    bool help = false;
};

// ============================================================================
// Print Usage
// ============================================================================

void PrintUsage(const char* program) {
    printf("RawrXD Phase 7D: Real Model Inference with Cryptographic Verification\n");
    printf("=====================================================================\n\n");
    printf("Usage: %s [options]\n\n", program);
    printf("Required:\n");
    printf("  --model PATH          Path to GGUF model file\n");
    printf("\nOptional:\n");
    printf("  --prompt TEXT         Input prompt (default: \"Hello world\")\n");
    printf("  --tokens N            Max tokens to generate (default: 10)\n");
    printf("  --seed N              Random seed (default: 42)\n");
    printf("  --temp F              Temperature (default: 0.8)\n");
    printf("  --top-p F             Top-p sampling (default: 0.9)\n");
    printf("  --top-k N             Top-k sampling (default: 40)\n");
    printf("  --enable-proofs       Enable checkpoint capture\n");
    printf("  --proof-out PATH      Export proof to file\n");
    printf("  --verbose             Verbose output\n");
    printf("  --help                Show this help\n");
    printf("\nExamples:\n");
    printf("  %s --model tinyllama.gguf --prompt \"Hello\" --tokens 5\n", program);
    printf("  %s --model llama-2-7b.gguf --prompt \"The capital of France is\" \\\n", program);
    printf("         --tokens 20 --enable-proofs --proof-out proof.rawrproof\n");
}

// ============================================================================
// Parse Arguments
// ============================================================================

CliArgs ParseArgs(int argc, char* argv[]) {
    CliArgs args;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--model" && i + 1 < argc) {
            args.model_path = argv[++i];
        } else if (arg == "--prompt" && i + 1 < argc) {
            args.prompt = argv[++i];
        } else if (arg == "--tokens" && i + 1 < argc) {
            args.max_tokens = std::atoi(argv[++i]);
        } else if (arg == "--seed" && i + 1 < argc) {
            args.seed = std::atoi(argv[++i]);
        } else if (arg == "--temp" && i + 1 < argc) {
            args.temperature = std::atof(argv[++i]);
        } else if (arg == "--top-p" && i + 1 < argc) {
            args.top_p = std::atof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            args.top_k = std::atoi(argv[++i]);
        } else if (arg == "--enable-proofs") {
            args.enable_proofs = true;
        } else if (arg == "--proof-out" && i + 1 < argc) {
            args.proof_output = argv[++i];
            args.enable_proofs = true;
        } else if (arg == "--verbose") {
            args.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", arg.c_str());
        }
    }
    
    return args;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    CliArgs args = ParseArgs(argc, argv);
    
    if (args.help) {
        PrintUsage(argv[0]);
        return 0;
    }
    
    if (args.model_path.empty()) {
        fprintf(stderr, "Error: --model is required\n\n");
        PrintUsage(argv[0]);
        return 1;
    }
    
    // Print header
    printf("=====================================================================\n");
    printf("RawrXD Phase 7D: Real Model Inference\n");
    printf("=====================================================================\n\n");
    
    printf("Configuration:\n");
    printf("  Model: %s\n", args.model_path.c_str());
    printf("  Prompt: \"%s\"\n", args.prompt.c_str());
    printf("  Max tokens: %d\n", args.max_tokens);
    printf("  Seed: %d\n", args.seed);
    printf("  Temperature: %.2f\n", args.temperature);
    printf("  Top-p: %.2f\n", args.top_p);
    printf("  Top-k: %d\n", args.top_k);
    printf("  Proofs: %s\n", args.enable_proofs ? "ENABLED" : "disabled");
    if (!args.proof_output.empty()) {
        printf("  Proof output: %s\n", args.proof_output.c_str());
    }
    printf("\n");
    
    // Initialize engine
    printf("Initializing inference engine...\n");
    
    Integration::CheckpointedInferenceEngine engine;
    
    if (!engine.Initialize(args.model_path, "phase7d-realmodel", "tiered_memory")) {
        fprintf(stderr, "\nError: Failed to initialize engine\n");
        fprintf(stderr, "Check that model file exists and is valid GGUF\n");
        return 1;
    }
    
    printf("Engine initialized successfully\n\n");
    
    // Set up generation parameters
    Inference::GenerationParams params;
    params.maxTokens = args.max_tokens;
    params.seed = args.seed;
    params.temperature = args.temperature;
    params.topP = args.top_p;
    params.topK = args.top_k;
    
    // Generate
    printf("Generating...\n");
    printf("---------------------------------------------------------------------\n");
    
    auto result = engine.Generate(args.prompt, params);
    
    printf("---------------------------------------------------------------------\n\n");
    
    if (!result.success) {
        fprintf(stderr, "Generation failed: %s\n", result.errorMessage.c_str());
        return 1;
    }
    
    // Print results
    printf("Generated text:\n");
    printf("  %s\n\n", result.text.c_str());
    
    printf("Statistics:\n");
    printf("  Tokens generated: %zu\n", result.tokens.size());
    printf("  Prompt tokens: %zu\n", result.promptTokens);
    printf("  Generated tokens: %zu\n", result.generatedTokens);
    
    // Export proof if requested
    if (args.enable_proofs) {
        std::string proof_path = args.proof_output;
        if (proof_path.empty()) {
            // Generate default filename
            char default_path[256];
            snprintf(default_path, sizeof(default_path), 
                    "proof_%s_%d.rawrproof", 
                    args.model_path.c_str(), 
                    args.seed);
            proof_path = default_path;
        }
        
        printf("\nExporting proof...\n");
        if (engine.ExportProof(proof_path)) {
            printf("  Proof saved to: %s\n", proof_path.c_str());
            
            // Get file size
            FILE* f = fopen(proof_path.c_str(), "rb");
            if (f) {
                fseek(f, 0, SEEK_END);
                size_t size = ftell(f);
                fclose(f);
                printf("  Proof size: %zu bytes\n", size);
            }
        } else {
            fprintf(stderr, "  Warning: Failed to export proof\n");
        }
        
        // Print checkpoint stats
        uint32_t tensors = 0;
        uint64_t bytes = 0;
        double hash_time = 0.0;
        engine.GetCheckpointStats(&tensors, &bytes, &hash_time);
        
        printf("\nCheckpoint statistics:\n");
        printf("  Tensors hashed: %u\n", tensors);
        printf("  Bytes hashed: %llu\n", bytes);
        printf("  Hash time: %.2f ms\n", hash_time);
    }
    
    printf("\n=====================================================================\n");
    printf("Complete\n");
    printf("=====================================================================\n");
    
    return 0;
}
