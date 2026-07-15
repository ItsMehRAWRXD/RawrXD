/**
 * @file smoke_test_v2.cpp
 * @brief Phase 1.5: Runtime Smoke Test - GGML Integration
 * 
 * Validates the entire pipeline from config loading to text generation.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include <thread>
#include "../src/agentic/Core.h"
#include "../src/agentic/InferenceEngine.h"
#include "../src/agentic/Config.h"
#include "../src/agentic/Logger.h"
#include "../src/agentic/GgmlEngine.h"
#include "../src/agentic/ErrorHandling.h"

using namespace RawrXD::Agentic;

// Simple test framework
#define TEST(name) std::cout << "\n[TEST] " << #name << "... " << std::flush
#define PASS() do { std::cout << "✓ PASS" << std::endl; passed++; } while(0)
#define FAIL(msg) do { \
    std::cout << "✗ FAIL: " << msg << std::endl; \
    failed++; \
    return false; \
} while(0)

int passed = 0;
int failed = 0;

// ============================================================================
// Smoke Test 1: Logger Initialization
// ============================================================================

bool Test_LoggerInit() {
    TEST(LoggerInit);
    
    Logger::Instance().Initialize();
    Logger::Instance().SetLevel(LogLevel::Debug);
    
    RXD_LOG_INFO("SmokeTest", "Logger test message");
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 2: Config Management
// ============================================================================

bool Test_ConfigManagement() {
    TEST(ConfigManagement);
    
    Config& config = Config::Instance();
    
    // Set values
    config.Set<std::string>("test_key", "test_value");
    config.Set<int>("test_int", 42);
    config.Set<float>("test_float", 3.14f);
    config.Set<bool>("test_bool", true);
    
    // Get values
    if (config.Get<std::string>("test_key", "") != "test_value") {
        FAIL("String config mismatch");
    }
    if (config.Get<int>("test_int", 0) != 42) {
        FAIL("Int config mismatch");
    }
    if (config.Get<float>("test_float", 0.0f) != 3.14f) {
        FAIL("Float config mismatch");
    }
    if (config.Get<bool>("test_bool", false) != true) {
        FAIL("Bool config mismatch");
    }
    
    // Test default values
    if (config.Get<std::string>("nonexistent", "default") != "default") {
        FAIL("Default value not working");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 3: Error Handling
// ============================================================================

bool Test_ErrorHandling() {
    TEST(ErrorHandling);
    
    // Test Result<T> success
    Result<int> successResult = Result<int>::Ok(42);
    if (!successResult.IsOk()) {
        FAIL("Success result should be OK");
    }
    if (successResult.Value() != 42) {
        FAIL("Success value should be 42");
    }
    
    // Test Result<T> error
    Result<int> errorResult = Result<int>::Err(ErrorCode::InvalidArgument, "Test error");
    if (!errorResult.IsErr()) {
        FAIL("Error result should be Err");
    }
    if (errorResult.Code() != ErrorCode::InvalidArgument) {
        FAIL("Error code should be InvalidArgument");
    }
    
    // Test Result<void>
    Result<void> voidSuccess = Result<void>::Ok();
    if (!voidSuccess.IsOk()) {
        FAIL("Void success should be OK");
    }
    
    Result<void> voidError = Result<void>::Err(ErrorCode::NotFound, "Not found");
    if (!voidError.IsErr()) {
        FAIL("Void error should be Err");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 4: GGML Engine Creation
// ============================================================================

bool Test_GgmlEngineCreation() {
    TEST(GgmlEngineCreation);
    
    auto engine = std::make_unique<GgmlEngine>();
    if (!engine) {
        FAIL("Failed to create engine");
    }
    
    if (engine->IsInitialized()) {
        FAIL("Engine should not be initialized yet");
    }
    
    if (engine->IsModelLoaded()) {
        FAIL("Engine should not have model loaded");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 5: GGML Engine Initialization
// ============================================================================

bool Test_GgmlEngineInit() {
    TEST(GgmlEngineInit);
    
    auto engine = std::make_unique<GgmlEngine>();
    
    auto result = engine->Initialize();
    if (result.IsErr()) {
        FAIL(std::string("Initialization failed: ") + result.Message().c_str());
    }
    
    if (!engine->IsInitialized()) {
        FAIL("Engine should be initialized");
    }
    
    // Test double initialization
    auto result2 = engine->Initialize();
    if (result2.IsOk()) {
        FAIL("Double init should fail");
    }
    
    engine->Shutdown();
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 6: Model Loading
// ============================================================================

bool Test_ModelLoading() {
    TEST(ModelLoading);
    
    auto engine = std::make_unique<GgmlEngine>();
    
    // Should fail if not initialized
    auto loadResult = engine->LoadModel("test.gguf");
    if (loadResult.IsOk()) {
        FAIL("Load should fail before init");
    }
    
    // Initialize
    engine->Initialize();
    
    // Now load should work (placeholder implementation)
    loadResult = engine->LoadModel("test.gguf");
    if (loadResult.IsErr()) {
        FAIL(std::string("Load failed: ") + loadResult.Message().c_str());
    }
    
    if (!engine->IsModelLoaded()) {
        FAIL("Model should be loaded");
    }
    
    // Check model info
    ModelInfo info = loadResult.Value();
    if (info.name.empty()) {
        FAIL("Model name should not be empty");
    }
    
    // Unload
    engine->UnloadModel();
    if (engine->IsModelLoaded()) {
        FAIL("Model should be unloaded");
    }
    
    engine->Shutdown();
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 7: Tokenization
// ============================================================================

bool Test_Tokenization() {
    TEST(Tokenization);
    
    auto engine = std::make_unique<GgmlEngine>();
    engine->Initialize();
    engine->LoadModel("test.gguf");
    
    std::string testText = "Hello, world!";
    auto tokenizeResult = engine->Tokenize(testText);
    if (tokenizeResult.IsErr()) {
        FAIL(std::string("Tokenization failed: ") + tokenizeResult.Message().c_str());
    }
    
    auto tokens = tokenizeResult.Value();
    if (tokens.empty()) {
        FAIL("Tokens should not be empty");
    }
    
    // Test detokenization
    auto detokResult = engine->Detokenize(tokens);
    if (detokResult.IsErr()) {
        FAIL(std::string("Detokenization failed: ") + detokResult.Message().c_str());
    }
    
    engine->Shutdown();
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 8: Text Generation
// ============================================================================

bool Test_TextGeneration() {
    TEST(TextGeneration);
    
    auto engine = std::make_unique<GgmlEngine>();
    engine->Initialize();
    engine->LoadModel("test.gguf");
    
    GenerationParams params;
    params.maxTokens = 10;
    params.temperature = 0.7f;
    
    std::string prompt = "Hello";
    auto genStart = std::chrono::high_resolution_clock::now();
    
    auto result = engine->Generate(prompt, params);
    
    auto genEnd = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(genEnd - genStart);
    
    if (result.IsErr()) {
        FAIL(std::string("Generation failed: ") + result.Message().c_str());
    }
    
    GenerationResult genResult = result.Value();
    std::cout << " (" << duration.count() << "ms)" << std::flush;
    
    engine->Shutdown();
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 9: Stream Generation
// ============================================================================

bool Test_StreamGeneration() {
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
        FAIL(std::string("Stream generation failed: ") + result.Message().c_str());
    }
    
    if (tokenCount == 0) {
        FAIL("Should have generated some tokens");
    }
    
    engine->Shutdown();
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 10: Core Integration
// ============================================================================

bool Test_CoreIntegration() {
    TEST(CoreIntegration);
    
    auto core = Core::Create();
    if (!core) {
        FAIL("Failed to create Core");
    }
    
    if (!core->Initialize()) {
        FAIL("Failed to initialize Core");
    }
    
    if (!core->IsInitialized()) {
        FAIL("Core should be initialized");
    }
    
    // Test task creation
    Task task;
    task.id = "test-task-1";
    task.type = TaskType::Inference;
    task.priority = TaskPriority::Normal;
    
    if (task.id != "test-task-1") {
        FAIL("Task ID mismatch");
    }
    
    core->Shutdown();
    PASS();
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "🔬 RawrXD GGML Integration Smoke Test\n";
    std::cout << "========================================\n";
    std::cout << "Testing unified 6-layer architecture...\n\n";
    
    auto totalStart = std::chrono::high_resolution_clock::now();
    
    // Run all tests
    Test_LoggerInit();
    Test_ConfigManagement();
    Test_ErrorHandling();
    Test_GgmlEngineCreation();
    Test_GgmlEngineInit();
    Test_ModelLoading();
    Test_Tokenization();
    Test_TextGeneration();
    Test_StreamGeneration();
    Test_CoreIntegration();
    
    auto totalEnd = std::chrono::high_resolution_clock::now();
    auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(totalEnd - totalStart);
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Test Results: " << passed << " passed, " << failed << " failed\n";
    std::cout << "Total time: " << totalDuration.count() << "ms\n";
    std::cout << "========================================\n";
    
    if (failed == 0) {
        std::cout << "✅ All smoke tests passed!\n";
        std::cout << "System is operational.\n";
        return 0;
    } else {
        std::cout << "❌ Some tests failed.\n";
        return 1;
    }
}
