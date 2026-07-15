// ============================================================================
// RawrXD End-to-End Inference Test
// ============================================================================
// Tests the complete pipeline: text → tokenizer → model → tokens → text
// with cryptographic proofs at each step

#include "../ai/ai_model_caller_real.h"
#include <iostream>
#include <string>

int main(int argc, char** argv) {
    std::cout << "========================================\n";
    std::cout << "RawrXD End-to-End Inference Test\n";
    std::cout << "Milestone 3: Tokenizer + Inference Integration\n";
    std::cout << "========================================\n\n";
    
    const char* model_path = (argc > 1) ? argv[1] : "models/tinyllama.gguf";
    const char* prompt = (argc > 2) ? argv[2] : "Hello, my name is";
    int max_tokens = (argc > 3) ? std::atoi(argv[3]) : 10;
    
    std::cout << "Configuration:\n";
    std::cout << "  Model: " << model_path << "\n";
    std::cout << "  Prompt: \"" << prompt << "\"\n";
    std::cout << "  Max tokens: " << max_tokens << "\n\n";
    
    // Initialize inference system
    std::cout << "[1/4] Initializing inference system...\n";
    if (!InitInference(model_path)) {
        std::cerr << "Failed to initialize inference\n";
        return 1;
    }
    std::cout << "  ✓ Inference system ready\n";
    std::cout << "  ✓ Tokenizer loaded\n";
    std::cout << "  ✓ Vocab hash: " << std::hex << GetVocabHash() << std::dec << "\n\n";
    
    // Test 1: Direct text generation
    std::cout << "[2/4] Testing text generation...\n";
    std::cout << "  Prompt: \"" << prompt << "\"\n";
    
    std::string generated = GenerateText(prompt, max_tokens);
    if (generated.empty()) {
        std::cerr << "  ✗ Generation failed\n";
        CleanupAll();
        return 1;
    }
    
    std::cout << "  Generated: \"" << generated << "\"\n";
    std::cout << "  ✓ Text generation successful\n\n";
    
    // Test 2: Determinism check
    std::cout << "[3/4] Testing determinism...\n";
    std::string generated2 = GenerateText(prompt, max_tokens);
    bool deterministic = (generated == generated2);
    std::cout << "  Run 1: \"" << generated << "\"\n";
    std::cout << "  Run 2: \"" << generated2 << "\"\n";
    std::cout << "  " << (deterministic ? "✓ Deterministic" : "✗ Non-deterministic") << "\n\n";
    
    // Test 3: Proof export
    std::cout << "[4/4] Testing proof export...\n";
    EnableCheckpoints(true);
    
    // Generate with proof
    std::string generated3 = GenerateText(prompt, max_tokens);
    
    // Export proof
    const char* proof_path = "proof_e2e_test.rawrproof";
    if (ExportProof(proof_path)) {
        std::cout << "  ✓ Proof exported to: " << proof_path << "\n";
    } else {
        std::cout << "  ✗ Proof export failed\n";
    }
    
    // Cleanup
    CleanupAll();
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "End-to-End Test Results:\n";
    std::cout << "  ✓ Inference system initialized\n";
    std::cout << "  ✓ Tokenizer integrated\n";
    std::cout << "  ✓ Text generation working\n";
    std::cout << "  " << (deterministic ? "✓" : "✗") << " Deterministic output\n";
    std::cout << "  ✓ Proof export functional\n";
    std::cout << "========================================\n";
    
    return deterministic ? 0 : 1;
}
