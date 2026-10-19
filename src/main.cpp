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

// Run the forward pass twice, once with the resident multi-GPU path and
// once with the CPU path, and compare the logits.
//
// The forward pass is the real test of the resident path: it exercises the
// device weight buffers across every layer of the model and all the
// projections, not just one matrix.
static void runForwardParity(Deep2Engine& engine) {
    const std::vector<uint32_t> inputTokens = { 1, 100, 200 };

    std::cout << "\n=== FORWARD PASS PARITY: RESIDENT GPU vs CPU ===\n" << std::flush;

    std::vector<float> residentLogits, residentBaseline;
    const bool residentOk = engine.executePhi3ROMForwardPass(inputTokens, residentLogits, residentBaseline, false);
    std::cout << "\n[PARITY] resident path: " << (residentOk ? "OK" : "FAILED") << "\n" << std::flush;

    std::vector<float> cpuLogits, cpuBaseline;
    const bool cpuOk = engine.executePhi3ROMForwardPass(inputTokens, cpuLogits, cpuBaseline, true);
    std::cout << "\n[PARITY] cpu path: " << (cpuOk ? "OK" : "FAILED") << "\n" << std::flush;

    if (!residentOk || !cpuOk) {
        std::cerr << "[PARITY] one of the two paths failed\n";
        return;
    }
    if (residentLogits.size() != cpuLogits.size()) {
        std::cerr << "[PARITY] logits size mismatch: " << residentLogits.size()
                  << " vs " << cpuLogits.size() << "\n";
        return;
    }

    float maxDiff = 0.0f;
    size_t maxIdx = 0;
    double sumSq = 0.0;
    size_t over = 0;
    for (size_t i = 0; i < cpuLogits.size(); ++i) {
        const float d = std::abs(residentLogits[i] - cpuLogits[i]);
        sumSq += static_cast<double>(d) * d;
        if (d > maxDiff) { maxDiff = d; maxIdx = i; }
        if (d > 1e-3f) ++over;
    }
    const double rms = std::sqrt(sumSq / (cpuLogits.size() ? cpuLogits.size() : 1));
    std::cout << "[PARITY] logits compared: " << cpuLogits.size()
              << "  max_diff=" << maxDiff << " at idx " << maxIdx
              << "  rms_diff=" << rms
              << "  rows over 1e-3: " << over << "\n";
    std::cout << "[PARITY] " << (over == 0 ? "PASSED" : "FAILED") << "\n";
}
int main(int argc, char* argv[]) {
    _mm_setcsr(_mm_getcsr() | 0x8040);

    if (argc < 2) {
        std::cout << "Deep2Engine - Native GGUF Execution Layer\n";
        std::cout << "Usage: " << argv[0] << " <path_to_model.gguf> [manifest.json] [--whole-loader]\n";
        std::cout << "       " << argv[0] << " --verify-init-only <path_to_model.gguf> [manifest.json]\n";
        std::cout << "       " << argv[0] << " --move10-validate <path_to_model.gguf> [manifest.json]\n";
    std::cout << "       " << argv[0] << " --forward-parity <path_to_model.gguf> [manifest.json]\n";
        std::cout << "       " << argv[0] << " --help\n";
        return 0;
    }

    if (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h") {
        std::cout << "Deep2Engine - Native GGUF Execution Layer\n";
        std::cout << "Usage: " << argv[0] << " <path_to_model.gguf> [manifest.json] [--whole-loader]\n";
        std::cout << "       " << argv[0] << " --verify-init-only <path_to_model.gguf> [manifest.json]\n";
        std::cout << "       " << argv[0] << " --move10-validate <path_to_model.gguf> [manifest.json]\n";
    std::cout << "       " << argv[0] << " --forward-parity <path_to_model.gguf> [manifest.json]\n";
        std::cout << "       " << argv[0] << " --help\n";
        return 0;
    }

    bool verifyOnly = false;
    bool forceWholeLoader = false;
    bool runMove10 = false;
    bool runParity = false;
    std::string modelPath;
    std::string manifestPath;

    int argIndex = 1;
    while (argIndex < argc) {
        std::string a = argv[argIndex];
        if (a == "--verify-init-only") {
            verifyOnly = true;
            argIndex++;
            continue;
        }
        if (a == "--move10-validate") {
            runMove10 = true;
            argIndex++;
            continue;
        }
        if (a == "--forward-parity") {
            runParity = true;
            argIndex++;
            continue;
        }
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
    if (runParity) {
        runForwardParity(engine);
    } else if (runMove10) {
        runMove10Validation(engine);
    } else {
        Deep2EngineExecuteInferenceStep(engine);
    }
    engine.Shutdown();
    return 0;
}
