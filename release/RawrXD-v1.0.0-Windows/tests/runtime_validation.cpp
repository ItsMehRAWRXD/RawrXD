/**
 * @file runtime_validation.cpp
 * @brief Phase 1.5: Runtime Validation Test
 * 
 * Tests the actual Config, Logger, ErrorHandling, and GgmlEngine components.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include "../src/agentic/Config.h"
#include "../src/agentic/Logger.h"
#include "../src/agentic/ErrorHandling.h"
#include "../src/agentic/InferenceEngine.h"
#include "../src/agentic/GgmlEngine.h"

using namespace RawrXD::Agentic;

// Test framework
int passed = 0;
int failed = 0;

#define TEST(name) std::cout << "\n[TEST] " << #name << "... " << std::flush
#define PASS() do { std::cout << "✓ PASS" << std::endl; passed++; } while(0)
#define FAIL(msg) do { \
    std::cout << "✗ FAIL: " << msg << std::endl; \
    failed++; \
} while(0)

// ============================================================================
// Test 1: Logger
// ============================================================================
void TestLogger() {
    TEST(Logger);
    
    Logger::Instance().Initialize();
    Logger::Instance().SetLevel(LogLevel::Debug);
    
    RXD_LOG_INFO("RuntimeTest", "Logger initialized successfully");
    RXD_LOG_DEBUG("RuntimeTest", "Debug message test");
    
    Logger::Instance().Shutdown();
    PASS();
}

// ============================================================================
// Test 2: Config
// ============================================================================
void TestConfig() {
    TEST(Config);
    
    Config& config = Config::Instance();
    config.Clear();
    
    // Set values
    config.Set<std::string>("model_path", "models/test.gguf");
    config.Set<int>("max_tokens", 100);
    config.Set<float>("temperature", 0.8f);
    config.Set<bool>("streaming", true);
    
    // Verify
    if (config.Get<std::string>("model_path", "") != "models/test.gguf") {
        FAIL("String config failed");
        return;
    }
    if (config.Get<int>("max_tokens", 0) != 100) {
        FAIL("Int config failed");
        return;
    }
    if (config.Get<float>("temperature", 0.0f) != 0.8f) {
        FAIL("Float config failed");
        return;
    }
    if (config.Get<bool>("streaming", false) != true) {
        FAIL("Bool config failed");
        return;
    }
    
    PASS();
}

// ============================================================================
// Test 3: Error Handling
// ============================================================================
void TestErrorHandling() {
    TEST(ErrorHandling);
    
    // Success result
    Result<int> success = Result<int>::Ok(42);
    if (!success.IsOk() || success.Value() != 42) {
        FAIL("Success result failed");
        return;
    }
    
    // Error result
    Result<int> error = Result<int>::Err(ErrorCode::NotFound, "Not found");
    if (!error.IsErr() || error.Code() != ErrorCode::NotFound) {
        FAIL("Error result failed");
        return;
    }
    
    // Void result
    Result<void> voidOk = Result<void>::Ok();
    if (!voidOk.IsOk()) {
        FAIL("Void success failed");
        return;
    }
    
    PASS();
}

// ============================================================================
// Test 4: GGML Engine Creation
// ============================================================================
void TestEngineCreation() {
    TEST(EngineCreation);
    
    auto engine = std::make_unique<GgmlEngine>();
    if (!engine) {
        FAIL("Failed to create engine");
        return;
    }
    
    if (engine->IsInitialized()) {
        FAIL("Should not be initialized");
        return;
    }
    
    if (engine->GetName() != "GGML") {
        FAIL("Wrong engine name");
        return;
    }
    
    PASS();
}

// ============================================================================
// Test 5: GGML Engine Initialization
// ============================================================================
void TestEngineInit() {
    TEST(EngineInit);
    
    auto engine = std::make_unique<GgmlEngine>();
    
    auto result = engine->Initialize();
    if (result.IsErr()) {
        FAIL(std::string("Init failed: ") + result.Message());
        return;
    }
    
    if (!engine->IsInitialized()) {
        FAIL("Not initialized");
        return;
    }
    
    // Double init should fail
    auto result2 = engine->Initialize();
    if (result2.IsOk()) {
        FAIL("Double init should fail");
        return;
    }
    
    engine->Shutdown();
    PASS();
}

// ============================================================================
// Test 6: Model Loading
// ============================================================================
void TestModelLoading() {
    TEST(ModelLoading);
    
    auto engine = std::make_unique<GgmlEngine>();
    
    // Should fail before init
    auto r1 = engine->LoadModel("test.gguf");
    if (r1.IsOk()) {
        FAIL("Should fail before init");
        return;
    }
    
    engine->Initialize();
    
    // Should succeed after init
    auto r2 = engine->LoadModel("test.gguf");
    if (r2.IsErr()) {
        FAIL(std::string("Load failed: ") + r2.Message());
        return;
    }
    
    if (!engine->IsModelLoaded()) {
        FAIL("Model not loaded");
        return;
    }
    
    ModelInfo info = r2.Value();
    if (info.name.empty()) {
        FAIL("Model name empty");
        return;
    }
    
    std::cout << "\n      Model: " << info.name << " (" << info.architecture << ")" << std::flush;
    
    engine->UnloadModel();
    engine->Shutdown();
    PASS();
}

// ============================================================================
// Test 7: Tokenization
// ============================================================================
void TestTokenization() {
    TEST(Tokenization);
    
    auto engine = std::make_unique<GgmlEngine>();
    engine->Initialize();
    engine->LoadModel("test.gguf");
    
    auto r1 = engine->Tokenize("Hello, world!");
    if (r1.IsErr()) {
        FAIL(std::string("Tokenize failed: ") + r1.Message());
        return;
    }
    
    auto tokens = r1.Value();
    if (tokens.empty()) {
        FAIL("No tokens");
        return;
    }
    
    auto r2 = engine->Detokenize(tokens);
    if (r2.IsErr()) {
        FAIL(std::string("Detokenize failed: ") + r2.Message());
        return;
    }
    
    std::cout << "\n      Tokens: " << tokens.size() << std::flush;
    
    engine->Shutdown();
    PASS();
}

// ============================================================================
// Test 8: Text Generation
// ============================================================================
void TestGeneration() {
    TEST(Generation);
    
    auto engine = std::make_unique<GgmlEngine>();
    engine->Initialize();
    engine->LoadModel("test.gguf");
    
    GenerationParams params;
    params.maxTokens = 10;
    params.temperature = 0.7f;
    
    auto start = std::chrono::high_resolution_clock::now();
    auto result = engine->Generate("Hello", params);
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (result.IsErr()) {
        FAIL(std::string("Generate failed: ") + result.Message());
        return;
    }
    
    GenerationResult gen = result.Value();
    std::cout << "\n      Generated " << gen.tokensGenerated << " tokens in " << ms << "ms" << std::flush;
    
    engine->Shutdown();
    PASS();
}

// ============================================================================
// Test 9: Stream Generation
// ============================================================================
void TestStreamGeneration() {
    TEST(StreamGeneration);
    
    auto engine = std::make_unique<GgmlEngine>();
    engine->Initialize();
    engine->LoadModel("test.gguf");
    
    GenerationParams params;
    params.maxTokens = 5;
    
    int tokenCount = 0;
    auto callback = [&tokenCount](const TokenInfo& token) {
        tokenCount++;
    };
    
    auto result = engine->GenerateStream("Test", params, callback);
    if (result.IsErr()) {
        FAIL(std::string("Stream failed: ") + result.Message());
        return;
    }
    
    if (tokenCount == 0) {
        FAIL("No tokens generated");
        return;
    }
    
    std::cout << "\n      Streamed " << tokenCount << " tokens" << std::flush;
    
    engine->Shutdown();
    PASS();
}

// ============================================================================
// Test 10: Config Persistence
// ============================================================================
void TestConfigPersistence() {
    TEST(ConfigPersistence);
    
    Config& config = Config::Instance();
    config.Clear();
    
    config.Set<std::string>("key1", "value1");
    config.Set<int>("key2", 42);
    
    if (!config.SaveToFile("test_config.tmp")) {
        FAIL("Save failed");
        return;
    }
    
    config.Clear();
    
    if (!config.LoadFromFile("test_config.tmp")) {
        FAIL("Load failed");
        return;
    }
    
    if (config.Get<std::string>("key1", "") != "value1") {
        FAIL("String not persisted");
        return;
    }
    if (config.Get<int>("key2", 0) != 42) {
        FAIL("Int not persisted");
        return;
    }
    
    PASS();
}

// ============================================================================
// Main
// ============================================================================
int main() {
    std::cout << "🔬 RawrXD Phase 1.5: Runtime Validation\n";
    std::cout << "========================================\n";
    std::cout << "Testing unified architecture components...\n";
    
    auto start = std::chrono::high_resolution_clock::now();
    
    TestLogger();
    TestConfig();
    TestErrorHandling();
    TestEngineCreation();
    TestEngineInit();
    TestModelLoading();
    TestTokenization();
    TestGeneration();
    TestStreamGeneration();
    TestConfigPersistence();
    
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    std::cout << "\n========================================\n";
    std::cout << "Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "Duration: " << ms << "ms\n";
    std::cout << "========================================\n";
    
    if (failed == 0) {
        std::cout << "✅ ALL TESTS PASSED\n";
        std::cout << "System is operational!\n";
        return 0;
    } else {
        std::cout << "❌ Some tests failed\n";
        return 1;
    }
}
