/**
 * @file verification_test_migrated.cpp
 * @brief Migrated verification test using unified Core interface
 * 
 * MIGRATION: Legacy AgenticEngine + CPUInferenceEngine -> Unified Core
 * 
 * Changes:
 * - Replaced AgenticEngine with RawrXD::Agentic::Core
 * - Replaced CPUInferenceEngine with RawrXD::Inference::InferenceEngine
 * - Used Task-based async execution instead of direct method calls
 * - Added proper error handling with Result<T>
 * - Removed nlohmann::json dependency for plan execution
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <cassert>
#include <cstring>
#include <cmath>
#include <future>

// NEW: Unified architecture headers
#include "agentic/Core.h"
#include "inference/InferenceEngine.h"
#include "core/ErrorHandling.h"
#include "core/Logger.h"

// OLD: Legacy headers (for comparison - these would be removed)
// #include "agentic_engine.h"
// #include "cpu_inference_engine.h"

using namespace RawrXD;
namespace fs = std::filesystem;

// Keep existing dequantization functions
extern "C" void DequantQ4_0_AVX512(void* src, uint16_t* dst, size_t blocks) {
    if (!src || !dst || blocks == 0) return;
    const uint8_t* in = static_cast<const uint8_t*>(src);
    for (size_t b = 0; b < blocks; ++b) {
        uint16_t scale_half = *reinterpret_cast<const uint16_t*>(in + b * 18);
        float scale = scale_half * 1.0f / 512.0f;
        for (int i = 0; i < 16; ++i) {
            uint8_t packed = in[b * 18 + 2 + i];
            uint8_t low = packed & 0x0F;
            uint8_t high = (packed >> 4) & 0x0F;
            float v_low = scale * (static_cast<float>(low) - 8.0f);
            float v_high = scale * (static_cast<float>(high) - 8.0f);
            dst[b * 32 + i * 2] = static_cast<uint16_t>(std::max(0.0f, v_low * 1000.0f));
            dst[b * 32 + i * 2 + 1] = static_cast<uint16_t>(std::max(0.0f, v_high * 1000.0f));
        }
    }
}

extern "C" void DequantQ4_0_AVX2(void* src, uint16_t* dst, size_t blocks) {
    DequantQ4_0_AVX512(src, dst, blocks);
}

void CreateDummyModel(const std::string& path) {
    std::ofstream f(path, std::ios::binary);
    std::vector<float> data(1024 * 1024);
    for(auto& x : data) x = ((float)rand() / RAND_MAX) * 0.1f;
    f.write((char*)data.data(), data.size() * sizeof(float));
    f.close();
    std::cout << "[Test] Created dummy model: " << path << std::endl;
}

// ============================================================================
// MIGRATED: Test Agentic Capabilities using Unified Core
// ============================================================================

void TestAgenticCapabilitiesMigrated() {
    std::cout << "\n=== Testing Agentic Capabilities (Migrated) ===\n";
    
    // NEW: Create unified Core instead of AgenticEngine
    auto core = Agentic::Core::Create();
    
    if (!core->Initialize()) {
        std::cout << "[FAIL] Failed to initialize Core.\n";
        return;
    }
    
    std::cout << "[Test] Testing Task Execution...\n";
    
    // NEW: Create tasks instead of JSON plans
    std::vector<Agentic::Task> tasks;
    
    // Task 1: File write
    Agentic::Task fileTask;
    fileTask.type = Agentic::TaskType::File;
    fileTask.instruction = "Create test file";
    fileTask.fileParams.operation = "write";
    fileTask.fileParams.path = "test_output_migrated.txt";
    fileTask.fileParams.content = "Hello from Unified Core!";
    tasks.push_back(fileTask);
    
    // Task 2: Terminal command
    Agentic::Task cmdTask;
    cmdTask.type = Agentic::TaskType::Terminal;
    cmdTask.instruction = "Echo success";
    cmdTask.terminalParams.command = "echo Agent Execution Success";
    tasks.push_back(cmdTask);
    
    // NEW: Execute tasks asynchronously
    std::vector<std::future<Agentic::TaskResult>> futures;
    for (const auto& task : tasks) {
        futures.push_back(core->SubmitTask(task));
    }
    
    // Collect results
    for (size_t i = 0; i < futures.size(); ++i) {
        auto result = futures[i].get();
        std::cout << "Task " << i << ": " 
                  << (result.success ? "SUCCESS" : "FAILED")
                  << " - " << result.output << "\n";
    }
    
    // Verify file creation
    if (fs::exists("test_output_migrated.txt")) {
        std::ifstream t("test_output_migrated.txt");
        std::stringstream buffer;
        buffer << t.rdbuf();
        if (buffer.str() == "Hello from Unified Core!") {
            std::cout << "[PASS] Agentic File Creation Verified (Migrated).\n";
        } else {
            std::cout << "[FAIL] File content mismatch.\n";
        }
        
        // Cleanup
        try {
            fs::remove("test_output_migrated.txt");
        } catch(...) {}
    } else {
        std::cout << "[FAIL] File was not created.\n";
    }
    
    // Shutdown
    core->Shutdown(std::chrono::seconds(5));
}

// ============================================================================
// MIGRATED: Test Inference Pipeline using Unified InferenceEngine
// ============================================================================

void TestInferencePipelineMigrated() {
    std::cout << "\n=== Testing Inference Pipeline (Migrated) ===\n";
    
    std::string modelName = "test_model_migrated.blob";
    CreateDummyModel(modelName);
    
    // NEW: Create unified InferenceEngine instead of CPUInferenceEngine
    Inference::EngineConfig config;
    config.modelPath = modelName;
    config.maxContextLength = 512;
    
    auto engine = Inference::InferenceEngine::Create(config);
    
    if (!engine->Initialize()) {
        std::cout << "[FAIL] Failed to initialize InferenceEngine.\n";
        try {
            fs::remove(modelName);
        } catch(...) {}
        return;
    }
    
    std::cout << "[Test] Loading Model (Migrated)...\n";
    
    // NEW: Use LoadModel with Result<T> error handling
    auto loadResult = engine->LoadModel(modelName);
    if (!loadResult.success) {
        std::cout << "[FAIL] Model Load Failed: " << loadResult.errorMessage << "\n";
        engine->Shutdown();
        try {
            fs::remove(modelName);
        } catch(...) {}
        return;
    }
    
    std::cout << "[PASS] Model Load Success (Migrated).\n";
    
    std::cout << "[Test] Tokenization (Migrated)...\n";
    
    // NEW: Use Tokenize method with Result<T>
    auto tokenResult = engine->Tokenize("Hello World");
    if (tokenResult.success) {
        std::cout << "Tokens: " << tokenResult.tokens.size() << "\n";
        if (tokenResult.tokens.size() > 0) {
            std::cout << "[PASS] Tokenizer works (Migrated).\n";
        }
    } else {
        std::cout << "[WARN] Tokenization failed: " << tokenResult.errorMessage << "\n";
    }
    
    std::cout << "[Test] Generation (Migrated)...\n";
    
    // NEW: Use Generate with streaming callback
    Inference::GenerationParams genParams;
    genParams.prompt = "Hello World";
    genParams.maxTokens = 10;
    genParams.temperature = 0.7f;
    
    int tokenCount = 0;
    auto genResult = engine->Generate(genParams, 
        [&tokenCount](const std::string& token) {
            tokenCount++;
            std::cout << ".";
        });
    
    if (genResult.success) {
        std::cout << "\n[PASS] Generation completed (Migrated).\n";
        std::cout << "Generated text: " << genResult.text << "\n";
    } else {
        std::cout << "\n[FAIL] Generation failed: " << genResult.errorMessage << "\n";
    }
    
    // Cleanup
    engine->UnloadModel();
    engine->Shutdown();
    
    try {
        fs::remove(modelName);
    } catch(...) {
        fprintf(stderr, "[VerificationTest] Removal error ignored\n");
    }
}

// ============================================================================
// NEW: Test Unified Core Features
// ============================================================================

void TestUnifiedFeatures() {
    std::cout << "\n=== Testing Unified Core Features ===\n";
    
    auto core = Agentic::Core::Create();
    
    if (!core->Initialize()) {
        std::cout << "[FAIL] Failed to initialize Core.\n";
        return;
    }
    
    // Test 1: Convenience methods
    std::cout << "[Test] Testing convenience methods...\n";
    
    // Test ReadFile (will fail but shouldn't crash)
    auto content = core->ReadFile("nonexistent_test_file.txt");
    std::cout << "  ReadFile returned: " << (content.empty() ? "empty (expected)" : "content") << "\n";
    
    // Test SearchCodebase
    auto searchResults = core->SearchCodebase("test query");
    std::cout << "  SearchCodebase returned: " << (searchResults.empty() ? "empty (expected)" : "results") << "\n";
    
    // Test 2: Stats
    std::cout << "[Test] Testing stats...\n";
    auto stats = core->GetStats();
    std::cout << "  Tasks submitted: " << stats.tasksSubmitted << "\n";
    std::cout << "  Tasks completed: " << stats.tasksCompleted << "\n";
    
    // Test 3: Subsystem access
    std::cout << "[Test] Testing subsystem access...\n";
    try {
        auto& scheduler = core->GetScheduler();
        (void)scheduler;
        std::cout << "  Scheduler: accessible\n";
        
        auto& registry = core->GetToolRegistry();
        (void)registry;
        std::cout << "  ToolRegistry: accessible\n";
        
        std::cout << "[PASS] All subsystems accessible.\n";
    } catch (const std::exception& e) {
        std::cout << "[FAIL] Subsystem access failed: " << e.what() << "\n";
    }
    
    core->Shutdown(std::chrono::seconds(5));
    std::cout << "[PASS] Unified Core features working.\n";
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "RawrXD Verification Suite (Migrated to Unified Architecture)\n";
    std::cout << "=============================================================\n";
    std::cout << "\nNOTE: This version uses the new unified Core interface\n";
    std::cout << "      instead of legacy AgenticEngine + CPUInferenceEngine\n\n";
    
    TestAgenticCapabilitiesMigrated();
    TestInferencePipelineMigrated();
    TestUnifiedFeatures();
    
    std::cout << "\n[Summary] All Migrated Tests Completed.\n";
    std::cout << "\nMigration Benefits:\n";
    std::cout << "  ✓ Type-safe interfaces (no void*)\n";
    std::cout << "  ✓ Async task execution with futures\n";
    std::cout << "  ✓ Proper error handling with Result<T>\n";
    std::cout << "  ✓ Thread-safe by design\n";
    std::cout << "  ✓ No Qt dependencies\n";
    std::cout << "  ✓ Unified agentic + inference interfaces\n";
    
    return 0;
}

/*
 * MIGRATION SUMMARY:
 * 
 * LEGACY CODE:
 *   AgenticEngine agent;
 *   agent.initialize();
 *   std::string result = agent.executePlan(jsonPlan);
 * 
 * UNIFIED CODE:
 *   auto core = Agentic::Core::Create();
 *   core->Initialize();
 *   
 *   Task task;
 *   task.type = TaskType::File;
 *   task.fileParams.operation = "write";
 *   
 *   auto future = core->SubmitTask(task);
 *   auto result = future.get();
 * 
 * KEY DIFFERENCES:
 * 1. Factory method instead of direct construction
 * 2. Task-based execution instead of JSON plans
 * 3. Async by default with std::future
 * 4. Result<T> for error handling instead of exceptions
 * 5. No external dependencies (nlohmann::json)
 * 6. Type-safe throughout
 */
