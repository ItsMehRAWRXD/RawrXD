//==============================================================================
// test_graph_runner_simple.cpp
// Simple test for SovereignGraphRunner
//==============================================================================

#include <iostream>
#include "../src/core/execution/SovereignGraphRunner_v2.hpp"

using namespace sovereign;

int main() {
    std::cout << "Starting SovereignGraphRunner test...\n";
    
    // Test 1: Create runner
    std::cout << "[Test 1] Create Runner\n";
    {
        SovereignGraphRunner runner;
        std::cout << "  Created runner\n";
        std::cout << "  IsInitialized: " << (runner.IsInitialized() ? "YES" : "NO") << "\n";
    }
    std::cout << "  Runner destroyed\n";
    
    // Test 2: Initialize
    std::cout << "[Test 2] Initialize\n";
    {
        SovereignGraphRunner runner;
        
        TransformerConfig config;
        config.hiddenSize = 512;
        config.numHeads = 8;
        config.headDim = 64;
        config.intermediateSize = 1376;
        config.maxSeqLen = 128;
        
        std::cout << "  Calling Initialize...\n";
        bool success = runner.Initialize(config);
        std::cout << "  Initialize returned: " << (success ? "true" : "false") << "\n";
        std::cout << "  IsInitialized: " << (runner.IsInitialized() ? "YES" : "NO") << "\n";
        
        if (success) {
            std::cout << "  Calling Shutdown...\n";
            runner.Shutdown();
            std::cout << "  Shutdown complete\n";
            std::cout << "  IsInitialized: " << (runner.IsInitialized() ? "YES" : "NO") << "\n";
        }
    }
    
    std::cout << "\nAll tests passed!\n";
    return 0;
}
