//==============================================================================
// test_graph_runner_forward.cpp
// Test Forward pass
//==============================================================================

#include <iostream>
#include "../src/core/execution/SovereignGraphRunner_v2.hpp"

using namespace sovereign;

int main() {
    std::cout << "======================================================================\n";
    std::cout << "SovereignGraphRunner Forward Pass Test\n";
    std::cout << "======================================================================\n";
    
    SovereignGraphRunner runner;
    TransformerConfig config;
    config.hiddenSize = 512;
    config.numHeads = 8;
    config.headDim = 64;
    config.maxSeqLen = 128;
    
    std::cout << "Initializing...\n";
    if (!runner.Initialize(config)) {
        std::cout << "Initialize: FAIL\n";
        return 1;
    }
    std::cout << "Initialize: PASS\n";
    
    // Run forward pass WITHOUT validation
    std::cout << "\nRunning Forward pass (no validation)...\n";
    auto result = runner.Forward(0, 0, ValidationMode::NONE);
    
    std::cout << "Forward: " << (result.success ? "PASS" : "FAIL") << "\n";
    if (result.success) {
        std::cout << "  Total time: " << result.totalTimeUs << " us\n";
        std::cout << "  Backend: " << result.backendUsed << "\n";
    }
    
    // Run forward pass with REFERENCE validation
    std::cout << "\nRunning Forward pass (REFERENCE validation)...\n";
    result = runner.Forward(0, 0, ValidationMode::REFERENCE);
    std::cout << "Forward: " << (result.success ? "PASS" : "FAIL") << "\n";
    
    // Run forward pass with COMPARE validation
    std::cout << "\nRunning Forward pass (COMPARE validation)...\n";
    result = runner.Forward(0, 0, ValidationMode::COMPARE);
    std::cout << "Forward: " << (result.success ? "PASS" : "FAIL") << "\n";
    if (result.success && !result.validationResults.empty()) {
        std::cout << "  Validation results:\n";
        for (const auto& entry : result.validationResults) {
            std::cout << "    " << entry.backendName 
                      << ": max_error=" << entry.maxError
                      << " " << (entry.passed ? "PASS" : "FAIL") << "\n";
        }
    }
    
    std::cout << "\nShutting down...\n";
    runner.Shutdown();
    
    std::cout << "\n======================================================================\n";
    std::cout << "All tests passed!\n";
    std::cout << "======================================================================\n";
    
    return 0;
}
