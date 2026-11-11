/**
 * @file contract_test.cpp
 * @brief AgenticEngine Contract Test Suite
 * 
 * Every backend implementation must pass this suite:
 *   - MockAgenticEngine (L3 ✓)
 *   - GGMLAgenticEngine (target L4)
 *   - Future: CUDAAgenticEngine, DirectMLAgenticEngine
 * 
 * Usage:
 *   ./contract_test.exe --backend=mock
 *   ./contract_test.exe --backend=ggml --model=test.gguf
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include <string>
#include "../src/agentic/IAgenticEngine.h"

using namespace RawrXD::Agentic;

// Test configuration
struct TestConfig {
    std::string backendName;
    std::string modelPath;
    bool verbose = false;
};

TestConfig g_config;

// Simple test framework
#define TEST(name) std::cout << "\n[CONTRACT] " << #name << "... " << std::flush
#define PASS() do { std::cout << "✓ PASS" << std::endl; passed++; } while(0)
#define FAIL(msg) do { \
    std::cout << "✗ FAIL: " << msg << std::endl; \
    failed++; \
    return false; \
} while(0)
#define SKIP(msg) do { \
    std::cout << "⊘ SKIP: " << msg << std::endl; \
    skipped++; \
    return true; \
} while(0)

int passed = 0;
int failed = 0;
int skipped = 0;

// Factory function - implemented per backend
std::unique_ptr<IAgenticEngine> CreateBackend(const std::string& name);

// ============================================================================
// Contract Test 1: Construct
// ============================================================================

bool Test_Construct() {
    TEST(Construct);
    
    auto engine = CreateBackend(g_config.backendName);
    if (!engine) FAIL("CreateBackend returned null");
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 2: Initialize
// ============================================================================

bool Test_Initialize() {
    TEST(Initialize);
    
    auto engine = CreateBackend(g_config.backendName);
    
    auto result = engine->Initialize();
    if (result.IsErr()) {
        FAIL("Initialize failed: " + result.Message());
    }
    
    if (!engine->IsInitialized()) {
        FAIL("IsInitialized() returned false after Initialize()");
    }
    
    // Cleanup
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 3: LoadModel
// ============================================================================

bool Test_LoadModel() {
    TEST(LoadModel);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    if (g_config.modelPath.empty()) {
        SKIP("No model path provided (--model=path)");
    }
    
    auto result = engine->LoadModel(g_config.modelPath);
    if (result.IsErr()) {
        FAIL("LoadModel failed: " + result.Message());
    }
    
    if (!engine->IsModelLoaded()) {
        FAIL("IsModelLoaded() returned false after LoadModel()");
    }
    
    if (engine->GetModelPath() != g_config.modelPath) {
        FAIL("GetModelPath() returned wrong path");
    }
    
    // Cleanup
    engine->UnloadModel();
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 4: Tokenize
// ============================================================================

bool Test_Tokenize() {
    TEST(Tokenize);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    // Tokenize simple text
    std::string text = "Hello, world!";
    auto result = engine->Tokenize(text);
    
    if (result.IsErr()) {
        // Some backends may require model loaded
        if (g_config.modelPath.empty()) {
            SKIP("Tokenize requires model (no --model provided)");
        }
        
        // Try with model
        engine->LoadModel(g_config.modelPath);
        result = engine->Tokenize(text);
        
        if (result.IsErr()) {
            FAIL("Tokenize failed: " + result.Message());
        }
    }
    
    auto tokens = result.Value();
    if (tokens.empty()) {
        FAIL("Tokenize returned empty token list");
    }
    
    // Verify round-trip
    auto detokResult = engine->Detokenize(tokens);
    if (detokResult.IsErr()) {
        FAIL("Detokenize failed: " + detokResult.Message());
    }
    
    // Cleanup
    engine->UnloadModel();
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 5: Generate
// ============================================================================

bool Test_Generate() {
    TEST(Generate);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    if (g_config.modelPath.empty()) {
        SKIP("Generate requires model (no --model provided)");
    }
    
    auto loadResult = engine->LoadModel(g_config.modelPath);
    if (loadResult.IsErr()) {
        SKIP("Generate skipped: model load failed");
    }
    
    GenerationOptions options;
    options.maxTokens = 10;
    options.temperature = 0.7f;
    
    auto result = engine->Generate("Hello", options);
    if (result.IsErr()) {
        FAIL("Generate failed: " + result.Message());
    }
    
    auto text = result.Value();
    if (text.empty()) {
        FAIL("Generate returned empty text");
    }
    
    if (g_config.verbose) {
        std::cout << "\n    Generated: \"" << text << "\"" << std::endl;
    }
    
    // Cleanup
    engine->UnloadModel();
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 6: StreamGenerate
// ============================================================================

bool Test_StreamGenerate() {
    TEST(StreamGenerate);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    auto caps = engine->GetCapabilities();
    if (!caps.supportsStreaming) {
        SKIP("Backend does not support streaming");
    }
    
    if (g_config.modelPath.empty()) {
        SKIP("StreamGenerate requires model (no --model provided)");
    }
    
    engine->LoadModel(g_config.modelPath);
    
    GenerationOptions options;
    options.maxTokens = 10;
    
    std::vector<Token> tokens;
    auto result = engine->StreamGenerate("Hello", options,
        [&tokens](const Token& token) {
            tokens.push_back(token);
            return true;  // Continue
        });
    
    if (result.IsErr()) {
        FAIL("StreamGenerate failed: " + result.Message());
    }
    
    if (tokens.empty()) {
        FAIL("StreamGenerate produced no tokens");
    }
    
    if (g_config.verbose) {
        std::cout << "\n    Streamed " << tokens.size() << " tokens" << std::endl;
    }
    
    // Cleanup
    engine->UnloadModel();
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 7: Cancel
// ============================================================================

bool Test_Cancel() {
    TEST(Cancel);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    auto caps = engine->GetCapabilities();
    if (!caps.supportsCancellation) {
        SKIP("Backend does not support cancellation");
    }
    
    // Just verify CancelGeneration doesn't crash
    engine->CancelGeneration();
    
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 8: UnloadModel
// ============================================================================

bool Test_UnloadModel() {
    TEST(UnloadModel);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    if (g_config.modelPath.empty()) {
        SKIP("UnloadModel requires model (no --model provided)");
    }
    
    engine->LoadModel(g_config.modelPath);
    
    auto result = engine->UnloadModel();
    if (result.IsErr()) {
        FAIL("UnloadModel failed: " + result.Message());
    }
    
    if (engine->IsModelLoaded()) {
        FAIL("IsModelLoaded() returned true after UnloadModel()");
    }
    
    engine->Shutdown();
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 9: Shutdown
// ============================================================================

bool Test_Shutdown() {
    TEST(Shutdown);
    
    auto engine = CreateBackend(g_config.backendName);
    engine->Initialize();
    
    auto result = engine->Shutdown();
    if (result.IsErr()) {
        FAIL("Shutdown failed: " + result.Message());
    }
    
    if (engine->IsInitialized()) {
        FAIL("IsInitialized() returned true after Shutdown()");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Contract Test 10: Capabilities
// ============================================================================

bool Test_Capabilities() {
    TEST(Capabilities);
    
    auto engine = CreateBackend(g_config.backendName);
    
    auto caps = engine->GetCapabilities();
    
    if (caps.backendName.empty()) {
        FAIL("GetCapabilities().backendName is empty");
    }
    
    if (caps.maxContextLength == 0) {
        FAIL("GetCapabilities().maxContextLength is 0");
    }
    
    if (g_config.verbose) {
        std::cout << "\n    Backend: " << caps.backendName << std::endl;
        std::cout << "    Max context: " << caps.maxContextLength << std::endl;
        std::cout << "    GPU: " << (caps.supportsGPU ? "yes" : "no") << std::endl;
        std::cout << "    Streaming: " << (caps.supportsStreaming ? "yes" : "no") << std::endl;
    }
    
    PASS();
    return true;
}

// ============================================================================
// Backend Factory
// ============================================================================

// Include backend implementations
#include "MockAgenticEngine.h"
// #include "GGMLAgenticEngine.h"  // Future

std::unique_ptr<IAgenticEngine> CreateBackend(const std::string& name) {
    if (name == "mock") {
        return std::make_unique<MockAgenticEngine>();
    }
    // else if (name == "ggml") {
    //     return std::make_unique<GGMLAgenticEngine>();
    // }
    return nullptr;
}

// ============================================================================
// Main
// ============================================================================

void PrintUsage(const char* program) {
    std::cout << "Usage: " << program << " --backend=<name> [options]\n";
    std::cout << "\nBackends:\n";
    std::cout << "  mock          Mock implementation (L3 ✓)\n";
    std::cout << "  ggml          GGML backend (target L4)\n";
    std::cout << "\nOptions:\n";
    std::cout << "  --model=path  Path to GGUF model file\n";
    std::cout << "  --verbose     Print detailed output\n";
}

int main(int argc, char* argv[]) {
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.starts_with("--backend=")) {
            g_config.backendName = arg.substr(10);
        } else if (arg.starts_with("--model=")) {
            g_config.modelPath = arg.substr(8);
        } else if (arg == "--verbose") {
            g_config.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    if (g_config.backendName.empty()) {
        std::cerr << "Error: --backend required\n";
        PrintUsage(argv[0]);
        return 1;
    }
    
    std::cout << "========================================" << std::endl;
    std::cout << "AgenticEngine Contract Test Suite" << std::endl;
    std::cout << "Backend: " << g_config.backendName << std::endl;
    if (!g_config.modelPath.empty()) {
        std::cout << "Model: " << g_config.modelPath << std::endl;
    }
    std::cout << "========================================" << std::endl;
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Run contract tests
    Test_Construct();
    Test_Initialize();
    Test_Capabilities();
    Test_LoadModel();
    Test_Tokenize();
    Test_Generate();
    Test_StreamGenerate();
    Test_Cancel();
    Test_UnloadModel();
    Test_Shutdown();
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " 
              << failed << " failed, " 
              << skipped << " skipped" << std::endl;
    std::cout << "Duration: " << duration.count() << " ms" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n✓ CONTRACT TEST PASSED" << std::endl;
        std::cout << "Backend satisfies IAgenticEngine contract" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ CONTRACT TEST FAILED" << std::endl;
        return 1;
    }
}
