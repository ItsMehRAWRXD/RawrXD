#include "Deep2Engine.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <xmmintrin.h>
#include <pmmintrin.h>

void runMove10Validation(Deep2Engine& engine) {
    std::vector<uint32_t> inputTokens = { 1 };  // Single token for fast boundary probe test
    std::vector<float> outputLogits, baselineLogits;
    
    std::cout << "\n=== MOVE 10 VALIDATION WITH ORACLE-TRACE PROBES ===\n";
    // Run only first 5 layers to hit the boundary probes quickly
    // Temporarily modify the engine to limit layers
    bool success = engine.executePhi3ROMForwardPass(inputTokens, outputLogits, baselineLogits);
    
    if (success) {
        std::cout << "\n[Move 10] Forward pass completed successfully!\n";
        std::cout << "  Output logits size: " << outputLogits.size() << "\n";
        if (!baselineLogits.empty()) {
            bool parity = engine.validateLogitsParity(outputLogits, baselineLogits, 1e-5f);
            std::cout << "  Logits parity: " << (parity ? "PASSED" : "FAILED") << "\n";
        }
    } else {
        std::cerr << "\n[Move 10] Forward pass FAILED!\n";
    }
}

int main(int argc, char* argv[]) {
    _mm_setcsr(_mm_getcsr() | 0x8040);

    if (argc < 2) {
        std::cout << "Deep2Engine - Native GGUF Execution Layer\n";
        std::cout << "Usage: " << argv[0] << " <path_to_model.gguf> [manifest.json] [--whole-loader]\n";
        std::cout << "       " << argv[0] << " --verify-init-only <path_to_model.gguf> [manifest.json] [--whole-loader]\n";
        std::cout << "       " << argv[0] << " --help\n";
        return 0;
    }

    if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        std::cout << "Deep2Engine - Native GGUF Execution Layer\n";
        std::cout << "Usage: " << argv[0] << " <path_to_model.gguf> [manifest.json] [--whole-loader]\n";
        std::cout << "       " << argv[0] << " --verify-init-only <path_to_model.gguf> [manifest.json] [--whole-loader]\n";
        std::cout << "       " << argv[0] << " --help\n";
        return 0;
    }

    bool verifyOnly = false;
    bool forceWholeLoader = false;
    bool runMove10 = false;
    std::string modelPath;
    std::string manifestPath;

    int argIndex = 1;
    if (std::string(argv[argIndex]) == "--verify-init-only") {
        verifyOnly = true;
        argIndex++;
    }
    if (argIndex < argc && std::string(argv[argIndex]) == "--move10-validate") {
        runMove10 = true;
        argIndex++;
    }
    while (argIndex < argc) {
        std::string a = argv[argIndex];
        if (a == "--whole-loader") { forceWholeLoader = true; argIndex++; continue; }
        if (modelPath.empty()) { modelPath = a; argIndex++; continue; }
        manifestPath = a; argIndex++;
    }

    Deep2Engine engine;
    unsigned int systemThreads = std::thread::hardware_concurrency();
    std::cout << "[ENV_INFO] Active lock-free worker threads deployed: "
              << (systemThreads > 1 ? systemThreads - 1 : 1) << "\n";

    if (!engine.Initialize(modelPath, manifestPath, forceWholeLoader)) {
        std::cerr << "stage=MODEL_LOAD_FAIL msg=Could not initialize execution layer.\n";
        return 1;
    }

    if (verifyOnly) {
        std::cout << "Deep2Engine::initialize SUCCESS\n";
        return 0;
    }

    // Check for Move 10 validation flag (already parsed above)
    if (runMove10) {
        runMove10Validation(engine);
    } else {
        Deep2EngineExecuteInferenceStep(engine);
    }
    engine.Shutdown();
    return 0;
}
