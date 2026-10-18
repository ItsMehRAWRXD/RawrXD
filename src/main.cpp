#include "Deep2Engine.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <xmmintrin.h>
#include <pmmintrin.h>

void runMove10Validation(Deep2Engine& engine) {
    std::cout << "[Move 10] Validation disabled - not implemented\n";
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
    std::string modelPath;
    std::string manifestPath;

    int argIndex = 1;
    if (std::string(argv[argIndex]) == "--verify-init-only") {
        verifyOnly = true;
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

    Deep2EngineExecuteInferenceStep(engine);
    engine.Shutdown();
    return 0;
}
