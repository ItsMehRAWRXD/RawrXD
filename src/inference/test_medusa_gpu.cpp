// ============================================================================
// Test: Medusa GPU Engine
// ============================================================================
// Verifies 100+ tok/s performance on RX 7800 XT
// ============================================================================

#include "medusa_gpu_engine.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace RawrXD::Inference;

int main(int argc, char** argv) {
    std::cout << "========================================\n";
    std::cout << "Medusa GPU Engine Test\n";
    std::cout << "========================================\n\n";
    
    // Configuration for 32K context
    MedusaConfig config;
    config.num_heads = 8;
    config.tokens_per_head = 8;
    config.max_context = 32768;
    config.batch_size = 128;
    config.acceptance_threshold = 0.65f;
    
    std::cout << "Configuration:\n";
    std::cout << "  Medusa heads: " << config.num_heads << "\n";
    std::cout << "  Tokens/head: " << config.tokens_per_head << "\n";
    std::cout << "  Max context: " << config.max_context << " tokens\n";
    std::cout << "  Batch size: " << config.batch_size << "\n";
    std::cout << "  Acceptance threshold: " << config.acceptance_threshold << "\n\n";
    
    // Initialize engine
    std::cout << "Initializing Medusa GPU Engine...\n";
    auto engine = CreateMedusaEngine(config);
    
    if (!engine) {
        std::cerr << "FAILED: Could not initialize GPU engine\n";
        std::cerr << "Make sure RX 7800 XT is available and Vulkan drivers are installed\n";
        return 1;
    }
    
    std::cout << "✓ GPU Engine initialized\n\n";
    
    // Test generation
    std::cout << "Running generation test...\n";
    std::vector<int32_t> prompt = {1, 2, 3, 4, 5}; // Dummy prompt
    
    auto start = std::chrono::high_resolution_clock::now();
    
    int token_count = 0;
    auto tokens = engine->Generate(prompt, 100, 
        [&token_count](const std::string& text) {
            token_count++;
            if (token_count % 10 == 0) {
                std::cout << "  Generated " << token_count << " tokens...\r";
            }
        });
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    float tps = (float)tokens.size() / (duration.count() / 1000.0f);
    
    std::cout << "\n\n========================================\n";
    std::cout << "Results\n";
    std::cout << "========================================\n";
    std::cout << "  Tokens generated: " << tokens.size() << "\n";
    std::cout << "  Time: " << duration.count() << " ms\n";
    std::cout << "  Throughput: " << std::fixed << std::setprecision(2) << tps << " tok/s\n";
    std::cout << "  Target: 100+ tok/s\n";
    std::cout << "  Status: " << (tps >= 100.0f ? "✓ PASS" : "✗ FAIL") << "\n";
    
    // Get metrics
    auto metrics = engine->GetCurrentTPS();
    std::cout << "  Current TPS: " << metrics << "\n";
    
    std::cout << "\n========================================\n";
    std::cout << "Test Complete\n";
    std::cout << "========================================\n";
    
    return (tps >= 100.0f) ? 0 : 1;
}
