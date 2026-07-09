// ============================================================================
// C4.4 Validation Test - Verify Transformer Execution Correctness
// ============================================================================
// Compares RawrXD output against llama.cpp reference
// Usage: test_c4_4_validation --model <gguf> --prompt "Hello world"
// ============================================================================

#include "streaming_multi_layer_backend.hpp"
#include "streaming_gguf_loader.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <cmath>

using namespace RawrXD::Runtime;

// Simple tokenizer stub - in real test, use actual tokenizer
std::vector<uint32_t> SimpleTokenize(const std::string& text) {
    // Stub: just return ASCII codes for testing
    // In real implementation, use SentencePiece or TikToken
    std::vector<uint32_t> tokens;
    for (char c : text) {
        tokens.push_back(static_cast<uint32_t>(c));
    }
    return tokens;
}

struct LogitEntry {
    uint32_t token_id;
    float logit;
    float probability;
};

void PrintUsage() {
    std::cout << "C4.4 Validation Test - Verify Transformer Execution\n"
              << "Usage: test_c4_4_validation [options]\n"
              << "\nOptions:\n"
              << "  --model <path>     Path to GGUF model file\n"
              << "  --prompt <text>    Input prompt (default: \"Hello world\")\n"
              << "  --temperature <f>  Sampling temperature (default: 1.0)\n"
              << "  --top-k <n>        Top-k sampling (default: 40)\n"
              << "  --max-tokens <n>   Max tokens to generate (default: 10)\n"
              << "  --dump-logits      Dump top logits for comparison\n"
              << "  --compare-ref      Compare against reference file\n"
              << "\nExample:\n"
              << "  test_c4_4_validation --model phi-3-mini-q4_k.gguf --prompt \"The capital of France is\" --dump-logits\n";
}

void DumpTopLogits(const float* logits, uint32_t vocab_size, int top_k = 10) {
    std::vector<LogitEntry> entries;
    entries.reserve(vocab_size);
    
    for (uint32_t i = 0; i < vocab_size; ++i) {
        entries.push_back({i, logits[i], 0.0f});
    }
    
    // Sort by logit descending
    std::partial_sort(entries.begin(), entries.begin() + top_k, entries.end(),
        [](const LogitEntry& a, const LogitEntry& b) { return a.logit > b.logit; });
    
    // Compute softmax for top entries
    float max_logit = entries[0].logit;
    float sum_exp = 0.0f;
    for (int i = 0; i < top_k; ++i) {
        entries[i].probability = std::exp(entries[i].logit - max_logit);
        sum_exp += entries[i].probability;
    }
    for (int i = 0; i < top_k; ++i) {
        entries[i].probability /= sum_exp;
    }
    
    // Print
    std::cout << "\n=== Top " << top_k << " Logits ===\n";
    std::cout << std::setw(6) << "Rank" << " | "
              << std::setw(10) << "Token ID" << " | "
              << std::setw(15) << "Logit" << " | "
              << std::setw(15) << "Probability" << "\n";
    std::cout << std::string(60, '-') << "\n";
    
    for (int i = 0; i < top_k; ++i) {
        std::cout << std::setw(6) << (i + 1) << " | "
                  << std::setw(10) << entries[i].token_id << " | "
                  << std::setw(15) << std::fixed << std::setprecision(6) << entries[i].logit << " | "
                  << std::setw(15) << std::setprecision(6) << entries[i].probability << "\n";
    }
    std::cout << std::endl;
}

bool CompareWithReference(const float* logits, uint32_t vocab_size, const std::string& ref_file) {
    // TODO: Load reference logits from file and compare
    // For now, just print a message
    std::cout << "[INFO] Reference comparison not yet implemented\n";
    std::cout << "       Expected: " << ref_file << "\n";
    return true;
}

int main(int argc, char* argv[]) {
    // Parse arguments
    std::string model_path;
    std::string prompt = "Hello world";
    float temperature = 1.0f;
    int top_k = 40;
    size_t max_tokens = 10;
    bool dump_logits = false;
    std::string ref_file;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--model" && i + 1 < argc) {
            model_path = argv[++i];
        } else if (arg == "--prompt" && i + 1 < argc) {
            prompt = argv[++i];
        } else if (arg == "--temperature" && i + 1 < argc) {
            temperature = std::stof(argv[++i]);
        } else if (arg == "--top-k" && i + 1 < argc) {
            top_k = std::stoi(argv[++i]);
        } else if (arg == "--max-tokens" && i + 1 < argc) {
            max_tokens = std::stoul(argv[++i]);
        } else if (arg == "--dump-logits") {
            dump_logits = true;
        } else if (arg == "--compare-ref" && i + 1 < argc) {
            ref_file = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            return 0;
        }
    }
    
    if (model_path.empty()) {
        std::cerr << "Error: --model is required\n\n";
        PrintUsage();
        return 1;
    }
    
    std::cout << "=== C4.4 Validation Test ===\n\n";
    std::cout << "Model: " << model_path << "\n";
    std::cout << "Prompt: \"" << prompt << "\"\n";
    std::cout << "Temperature: " << temperature << "\n";
    std::cout << "Top-k: " << top_k << "\n";
    std::cout << "Max tokens: " << max_tokens << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 1: Open model
    // ------------------------------------------------------------------------
    std::cout << "[1/4] Opening model...\n";
    
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        std::cerr << "Failed to open model: " << model_path << "\n";
        return 1;
    }
    
    std::cout << "      ✓ Model opened\n";
    std::cout << "      Tensors: " << loader.GetTensorCount() << "\n";
    std::cout << "      File size: " << (loader.GetFileSize() / (1024.0 * 1024.0 * 1024.0)) << " GB\n\n";
    
    // ------------------------------------------------------------------------
    // Step 2: Initialize backend
    // ------------------------------------------------------------------------
    std::cout << "[2/4] Initializing backend...\n";
    
    StreamingMultiLayerBackend backend;
    if (!backend.Initialize(loader)) {
        std::cerr << "Failed to initialize backend\n";
        return 1;
    }
    
    std::cout << "      ✓ Backend initialized\n";
    std::cout << "      Layers: " << backend.GetNumLayers() << "\n";
    std::cout << "      Hidden size: " << backend.GetHiddenSize() << "\n";
    std::cout << "      Heads: " << backend.GetNumHeads() << "\n";
    std::cout << "      Vocab size: " << backend.GetVocabSize() << "\n\n";
    
    // ------------------------------------------------------------------------
    // Step 3: Tokenize prompt
    // ------------------------------------------------------------------------
    std::cout << "[3/4] Tokenizing prompt...\n";
    
    std::vector<uint32_t> prompt_tokens = SimpleTokenize(prompt);
    std::cout << "      ✓ Tokenized to " << prompt_tokens.size() << " tokens\n";
    std::cout << "      Tokens: [";
    for (size_t i = 0; i < prompt_tokens.size(); ++i {
        if (i > 0) std::cout << ", ";
        std::cout << prompt_tokens[i];
    }
    std::cout << "]\n\n";
    
    // ------------------------------------------------------------------------
    // Step 4: Execute first token to get logits
    // ------------------------------------------------------------------------
    std::cout << "[4/4] Executing first token...\n";
    
    // Execute just the first token to get logits
    alignas(64) float logits[128000];
    bool success = backend.ExecuteToken(prompt_tokens[0], 0, logits);
    
    if (!success) {
        std::cerr << "Failed to execute token\n";
        return 1;
    }
    
    std::cout << "      ✓ First token executed\n\n";
    
    // ------------------------------------------------------------------------
    // Step 5: Dump logits for comparison
    // ------------------------------------------------------------------------
    if (dump_logits) {
        DumpTopLogits(logits, backend.GetVocabSize(), 20);
    }
    
    // ------------------------------------------------------------------------
    // Step 6: Compare with reference (if provided)
    // ------------------------------------------------------------------------
    if (!ref_file.empty()) {
        CompareWithReference(logits, backend.GetVocabSize(), ref_file);
    }
    
    // ------------------------------------------------------------------------
    // Step 7: Generate continuation
    // ------------------------------------------------------------------------
    std::cout << "=== Generation ===\n";
    std::cout << "Prompt: \"" << prompt << "\"\n";
    std::cout << "Output: \"" << prompt;
    
    std::vector<uint32_t> output_tokens;
    success = backend.Generate(prompt_tokens, output_tokens, max_tokens, temperature, top_k);
    
    if (!success) {
        std::cerr << "Generation failed\n";
        return 1;
    }
    
    // Print generated tokens (as characters for simple tokenizer)
    for (auto token : output_tokens) {
        if (token < 128) {
            std::cout << static_cast<char>(token);
        } else {
            std::cout << "<" << token << ">";
        }
    }
    std::cout << "\"\n\n";
    
    // ------------------------------------------------------------------------
    // Summary
    // ------------------------------------------------------------------------
    std::cout << "=== Validation Summary ===\n";
    std::cout << "✓ Model loaded successfully\n";
    std::cout << "✓ Backend initialized\n";
    std::cout << "✓ First token executed\n";
    std::cout << "✓ Generated " << output_tokens.size() << " tokens\n";
    
    if (dump_logits) {
        std::cout << "\nTo validate correctness:\n";
        std::cout << "1. Run the same prompt with llama.cpp:\n";
        std::cout << "   ./main -m " << model_path << " -p \"" << prompt << "\" --logits-all\n";
        std::cout << "2. Compare top logits (should match within tolerance)\n";
    }
    
    return 0;
}
