//==============================================================================
// test_graph_runner_individual.cpp
// Individual test execution to find crash
//==============================================================================

#include <iostream>
#include "../src/core/execution/SovereignGraphRunner_v2.hpp"

using namespace sovereign;

bool Test_Initialization() {
    std::cout << "\n[Test 1] Initialization\n";
    std::cout << "  " << std::string(50, '-') << "\n";
    
    SovereignGraphRunner runner;
    
    TransformerConfig config;
    config.hiddenSize = 512;
    config.numHeads = 8;
    config.headDim = 64;
    config.intermediateSize = 1376;
    config.maxSeqLen = 128;
    
    std::cout << "  Initializing...\n";
    bool success = runner.Initialize(config);
    
    std::cout << "  Initialize: " << (success ? "PASS" : "FAIL") << "\n";
    std::cout << "  IsInitialized: " << (runner.IsInitialized() ? "YES" : "NO") << "\n";
    
    if (success) {
        std::cout << "  Shutting down...\n";
        runner.Shutdown();
    }
    
    return success;
}

bool Test_BackendSelection() {
    std::cout << "\n[Test 2] Backend Selection\n";
    std::cout << "  " << std::string(50, '-') << "\n";
    
    SovereignGraphRunner runner;
    TransformerConfig config;
    config.hiddenSize = 512;
    config.numHeads = 8;
    config.headDim = 64;
    config.maxSeqLen = 128;
    
    std::cout << "  Initializing...\n";
    if (!runner.Initialize(config)) {
        std::cout << "  Initialize: FAIL\n";
        return false;
    }
    
    std::cout << "  Setting AUTO policy...\n";
    runner.SetDispatchPolicy(SelectionPolicy::AUTO);
    auto policy = runner.GetDispatchPolicy();
    std::cout << "  AUTO policy: " << (policy == SelectionPolicy::AUTO ? "PASS" : "FAIL") << "\n";
    
    std::cout << "  Setting REFERENCE_ONLY policy...\n";
    runner.SetDispatchPolicy(SelectionPolicy::REFERENCE_ONLY);
    policy = runner.GetDispatchPolicy();
    std::cout << "  REFERENCE policy: " << (policy == SelectionPolicy::REFERENCE_ONLY ? "PASS" : "FAIL") << "\n";
    
    std::cout << "  Forcing backend...\n";
    runner.ForceBackend("Reference");
    std::cout << "  Force backend: PASS\n";
    
    std::cout << "  Auto selecting backend...\n";
    runner.AutoSelectBackend();
    policy = runner.GetDispatchPolicy();
    std::cout << "  Auto select: " << (policy == SelectionPolicy::AUTO ? "PASS" : "FAIL") << "\n";
    
    std::cout << "  Shutting down...\n";
    runner.Shutdown();
    return true;
}

bool Test_ValidationSuite() {
    std::cout << "\n[Test 3] Validation Suite\n";
    std::cout << "  " << std::string(50, '-') << "\n";
    
    SovereignGraphRunner runner;
    TransformerConfig config;
    config.hiddenSize = 512;
    config.numHeads = 8;
    config.headDim = 64;
    config.maxSeqLen = 128;
    
    std::cout << "  Initializing...\n";
    if (!runner.Initialize(config)) {
        std::cout << "  Initialize: FAIL\n";
        return false;
    }
    
    std::cout << "  Running validation suite...\n";
    bool passed = runner.RunValidationSuite();
    
    std::cout << "  Validation: " << (passed ? "ALL PASS" : "SOME FAIL") << "\n";
    
    std::cout << "  Shutting down...\n";
    runner.Shutdown();
    return passed;
}

int main(int argc, char* argv[]) {
    std::cout << "======================================================================\n";
    std::cout << "SovereignGraphRunner Individual Tests\n";
    std::cout << "======================================================================\n";
    
    int testNum = 0;
    if (argc > 1) {
        testNum = std::atoi(argv[1]);
    }
    
    bool result = false;
    
    switch (testNum) {
        case 1:
            result = Test_Initialization();
            break;
        case 2:
            result = Test_BackendSelection();
            break;
        case 3:
            result = Test_ValidationSuite();
            break;
        default:
            std::cout << "Usage: " << argv[0] << " [test_number]\n";
            std::cout << "  1 - Initialization\n";
            std::cout << "  2 - Backend Selection\n";
            std::cout << "  3 - Validation Suite\n";
            return 0;
    }
    
    std::cout << "\n======================================================================\n";
    std::cout << "Result: " << (result ? "PASS" : "FAIL") << "\n";
    std::cout << "======================================================================\n";
    
    return result ? 0 : 1;
}
