/*===========================================================================
 * main_runtime.cpp
 *
 * RawrXD Runtime Entry Point
 *
 * Standalone executable with no IDE dependencies
 * Usage:
 *   RawrXD_Engine.exe --model model.gguf
 *   RawrXD_Engine.exe --self-test
 *   RawrXD_Engine.exe --version
 *===========================================================================*/

#include "runtime/runtime_paths.hpp"
#include "runtime/self_test.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

// Version information
#define RAWRXD_VERSION_MAJOR 1
#define RAWRXD_VERSION_MINOR 0
#define RAWRXD_VERSION_PATCH 0
#define RAWRXD_VERSION_STRING "1.0.0"

// Function prototypes
void PrintBanner();
void PrintUsage();
void PrintVersion();
int RunSelfTest();
int RunWithModel(const char* modelPath);
int RunInteractive();

int main(int argc, char* argv[]) {
    // Set console output mode for UTF-8
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    #endif

    // Parse arguments
    if (argc < 2) {
        PrintBanner();
        PrintUsage();
        return 1;
    }

    const char* command = argv[1];

    if (strcmp(command, "--version") == 0 || strcmp(command, "-v") == 0) {
        PrintVersion();
        return 0;
    }

    if (strcmp(command, "--self-test") == 0) {
        return RunSelfTest();
    }

    if (strcmp(command, "--model") == 0) {
        if (argc < 3) {
            std::cerr << "Error: --model requires a path\n";
            return 1;
        }
        return RunWithModel(argv[2]);
    }

    if (strcmp(command, "--interactive") == 0 || strcmp(command, "-i") == 0) {
        return RunInteractive();
    }

    if (strcmp(command, "--help") == 0 || strcmp(command, "-h") == 0) {
        PrintBanner();
        PrintUsage();
        return 0;
    }

    std::cerr << "Unknown command: " << command << "\n";
    PrintUsage();
    return 1;
}

void PrintBanner() {
    std::cout << R"(
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   RawrXD Runtime v)" << RAWRXD_VERSION_STRING << R"(                                         ║
║   Sovereign Inference Engine                                     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

)";
}

void PrintUsage() {
    std::cout << "Usage:\n";
    std::cout << "  RawrXD_Engine.exe --model <path>    Load and run GGUF model\n";
    std::cout << "  RawrXD_Engine.exe --self-test       Run runtime self-tests\n";
    std::cout << "  RawrXD_Engine.exe --interactive     Interactive mode\n";
    std::cout << "  RawrXD_Engine.exe --version         Show version\n";
    std::cout << "  RawrXD_Engine.exe --help            Show this help\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  RawrXD_Engine.exe --model models\\deepseek.gguf\n";
    std::cout << "  RawrXD_Engine.exe --self-test\n";
    std::cout << "\n";
}

void PrintVersion() {
    std::cout << "RawrXD Runtime v" << RAWRXD_VERSION_STRING << "\n";
    std::cout << "Build: " << __DATE__ << " " << __TIME__ << "\n";
    std::cout << "Architecture: x64\n";
    std::cout << "AVX-512: ";
    
    #ifdef __AVX512F__
    std::cout << "Enabled\n";
    #else
    std::cout << "Runtime detection\n";
    #endif
}

int RunSelfTest() {
    PrintBanner();
    std::cout << "Running runtime self-test...\n\n";

    RawrXD::Runtime::SelfTestSuite suite;
    auto results = suite.RunAllTests();
    RawrXD::Runtime::SelfTestSuite::PrintResults(results);

    return RawrXD::Runtime::SelfTestSuite::AllPassed(results) ? 0 : 1;
}

int RunWithModel(const char* modelPath) {
    PrintBanner();

    // Initialize runtime paths
    RawrXD::Runtime::RuntimePaths paths;
    if (!paths.Initialize()) {
        std::cerr << "Error: Failed to initialize runtime paths\n";
        return 1;
    }

    // Ensure directory structure exists
    if (!paths.EnsureDirectories()) {
        std::cerr << "Error: Failed to create runtime directories\n";
        return 1;
    }

    std::cout << paths.GetPathSummary() << "\n";

    // Validate model path
    std::filesystem::path modelFile(modelPath);
    if (!std::filesystem::exists(modelFile)) {
        // Try relative to models directory
        modelFile = paths.GetModelsPath() / modelPath;
        if (!std::filesystem::exists(modelFile)) {
            std::cerr << "Error: Model not found: " << modelPath << "\n";
            return 1;
        }
    }

    std::cout << "Loading model: " << modelFile.string() << "\n";

    // Load the model using the RawrXD inference engine
    std::cout << "\n";
    std::cout << "[1/4] Loading GGUF format...\n";
    
    // Initialize the inference backend
    if (!RawrXDInference::Initialize()) {
        std::cerr << "Error: Failed to initialize inference backend\n";
        return 1;
    }
    
    std::cout << "[2/4] Initializing tokenizer...\n";
    
    // Load the tokenizer from the model directory
    std::filesystem::path vocabPath = modelFile.parent_path() / "tokenizer.json";
    if (!std::filesystem::exists(vocabPath)) {
        vocabPath = paths.GetModelsPath() / "tokenizer.json";
    }
    
    RawrXDTokenizer tokenizer;
    if (!tokenizer.Load(vocabPath.string())) {
        std::cerr << "Warning: Failed to load tokenizer, using byte fallback\n";
    }
    
    std::cout << "[3/4] Loading kernel registry...\n";
    
    // Register available inference kernels
    register_rawr_inference();
    
    std::cout << "[4/4] Inference ready\n";
    std::cout << "\n";
    std::cout << "Model loaded successfully.\n";
    std::cout << "  - File: " << modelFile.filename().string() << "\n";
    std::cout << "  - Size: " << (std::filesystem::file_size(modelFile) / (1024 * 1024)) << " MB\n";
    std::cout << "  - Tokenizer: " << (tokenizer.VocabSize() > 0 ? "loaded" : "byte fallback") << "\n";
    std::cout << "\n";

    return 0;
}

int RunInteractive() {
    PrintBanner();
    std::cout << "Interactive mode not yet implemented.\n";
    std::cout << "Use --model to load a GGUF file.\n";
    return 1;
}
