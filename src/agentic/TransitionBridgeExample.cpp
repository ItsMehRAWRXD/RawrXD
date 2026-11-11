/**
 * @file TransitionBridgeExample.cpp
 * @brief Example of using TransitionBridge for gradual migration
 * 
 * This file demonstrates:
 * 1. BEFORE: Legacy code using AgenticEngine*
 * 2. DURING: Migration using TransitionBridge
 * 3. AFTER: Fully migrated code using unified Core
 * 
 * @copyright RawrXD 2026
 */

// ============================================================================
// BEFORE: Legacy Code (Original)
// ============================================================================

#if 0  // Original legacy code

#include "agentic_engine.h"
#include "cpu_inference_engine.h"

class LegacyCodeExample {
public:
    void Initialize() {
        m_engine = new AgenticEngine();
        m_engine->initialize();
        
        m_inference = new CPUInferenceEngine();
        m_inference->LoadModel("model.gguf");
    }
    
    void Shutdown() {
        delete m_engine;
        delete m_inference;
    }
    
    std::string GenerateCode(const std::string& prompt) {
        return m_engine->generateCode(prompt);
    }
    
    std::string AnalyzeCode(const std::string& code) {
        return m_engine->analyzeCode(code);
    }
    
    void ExecutePlan(const nlohmann::json& plan) {
        for (const auto& step : plan) {
            if (step["type"] == "file_edit") {
                m_engine->writeFile(step["target"], step["content"]);
            } else if (step["type"] == "command") {
                m_engine->executeCommand(step["cmd"]);
            }
        }
    }
    
private:
    AgenticEngine* m_engine = nullptr;
    CPUInferenceEngine* m_inference = nullptr;
};

#endif

// ============================================================================
// DURING: Migration Using TransitionBridge
// ============================================================================

// ============================================================================
// DURING: Migration Using TransitionBridge
// ============================================================================

#include "TransitionBridge.h"
#include <iostream>
#include <vector>
#include <tuple>

namespace MigrationExample {

class MigratingCodeExample {
public:
    MigratingCodeExample() {
        // Track that this file is using legacy features
        TRACK_LEGACY_USAGE("AgenticEngine");
        TRACK_LEGACY_USAGE("CPUInferenceEngine");
    }
    
    void Initialize() {
        // Step 1: Use transition bridge factory
        m_engine = CREATE_AGENTIC_ENGINE();
        m_engine->initialize();
        
        // Step 2: Can still use legacy-style initialization
        std::cout << "[Migration] Engine initialized\n";
        
        // Track progress
        TRACK_MIGRATION("Initialize");
    }
    
    void Shutdown() {
        // No manual delete needed - smart pointer handles it
        m_engine = nullptr;
        std::cout << "[Migration] Engine shutdown\n";
    }
    
    // Legacy-compatible method
    std::string GenerateCode(const std::string& prompt) {
        // This uses the legacy-compatible wrapper
        return m_engine->generateCode(prompt);
    }
    
    // Legacy-compatible method
    std::string AnalyzeCode(const std::string& code) {
        return m_engine->analyzeCode(code);
    }
    
    // NEW: Can also use unified API directly
    std::future<RawrXD::Agentic::TaskResult> GenerateCodeAsync(const std::string& prompt) {
        auto core = m_engine.GetUnifiedCore();
        
        RawrXD::Agentic::Task task;
        task.type = RawrXD::Agentic::TaskType::Inference;
        task.instruction = "Generate code";
        task.inferenceParams.prompt = prompt;
        task.inferenceParams.maxTokens = 512;
        
        return core->SubmitTask(task);
    }
    
    // Migrated plan execution
    std::string ExecutePlan(const std::vector<std::tuple<std::string, std::string, std::string>>& steps) {
        // Use migration helper
        return RawrXD::Migration::ExecuteLegacyPlan(m_engine, steps);
    }
    
    // NEW: Access unified Core for advanced features
    void UseUnifiedFeatures() {
        auto core = m_engine.GetUnifiedCore();
        
        // Now have access to full unified API
        auto stats = core->GetStats();
        std::cout << "Tasks submitted: " << stats.tasksSubmitted << "\n";
        
        // Can submit batch tasks
        std::vector<RawrXD::Agentic::Task> tasks;
        // ... populate tasks ...
        auto futures = core->SubmitBatch(tasks);
        
        // Can access subsystems
        auto& scheduler = core->GetScheduler();
        auto& registry = core->GetToolRegistry();
        (void)scheduler;
        (void)registry;
    }
    
    // Get migration progress
    void PrintMigrationStatus() {
        auto& tracker = RawrXD::Migration::MigrationTracker::GetInstance();
        tracker.PrintReport();
    }
    
private:
    // Transition type - works like AgenticEngine* but with smart pointer semantics
    LEGACY_AGENTIC_ENGINE m_engine;
};

} // namespace MigrationExample

// ============================================================================
// AFTER: Fully Migrated Code
// ============================================================================

#if 0  // Target state after full migration

#include "agentic/Core.h"
#include "inference/InferenceEngine.h"

namespace FullyMigrated {

class ModernCodeExample {
public:
    void Initialize() {
        m_core = RawrXD::Agentic::Core::Create();
        m_core->Initialize();
        
        m_inference = RawrXD::Inference::InferenceEngine::Create({});
        m_inference->Initialize();
    }
    
    void Shutdown() {
        m_core->Shutdown(std::chrono::seconds(5));
        m_inference->Shutdown();
    }
    
    // Async by default
    std::future<RawrXD::Agentic::TaskResult> GenerateCode(const std::string& prompt) {
        RawrXD::Agentic::Task task;
        task.type = RawrXD::Agentic::TaskType::Inference;
        task.inferenceParams.prompt = prompt;
        return m_core->SubmitTask(task);
    }
    
    // Proper error handling with Result<T>
    RawrXD::Core::Result<std::string> AnalyzeCode(const std::string& code) {
        RawrXD::Agentic::Task task;
        task.type = RawrXD::Agentic::TaskType::Inference;
        task.inferenceParams.prompt = "Analyze: " + code;
        
        auto result = m_core->ExecuteSync(task);
        if (result.success) {
            return RawrXD::Core::Result<std::string>::Ok(result.output);
        }
        return RawrXD::Core::Result<std::string>::Error(
            RawrXD::Core::ErrorCode::InternalError, 
            result.errorMessage
        );
    }
    
    // Type-safe task execution
    void ExecuteTasks(const std::vector<RawrXD::Agentic::Task>& tasks) {
        auto futures = m_core->SubmitBatch(tasks);
        
        for (auto& future : futures) {
            auto result = future.get();
            if (result.success) {
                std::cout << "Task completed: " << result.output << "\n";
            } else {
                std::cerr << "Task failed: " << result.errorMessage << "\n";
            }
        }
    }
    
private:
    std::shared_ptr<RawrXD::Agentic::Core> m_core;
    std::shared_ptr<RawrXD::Inference::InferenceEngine> m_inference;
};

} // namespace FullyMigrated

#endif

// ============================================================================
// Demonstration
// ============================================================================

int main() {
    std::cout << "=== TransitionBridge Example ===\n\n";
    
    std::cout << "Stage 1: Legacy code using raw pointers\n";
    std::cout << "  AgenticEngine* engine = new AgenticEngine();\n";
    std::cout << "  engine->initialize();\n";
    std::cout << "  // Manual memory management\n";
    std::cout << "  delete engine;\n\n";
    
    std::cout << "Stage 2: Migration using TransitionBridge\n";
    std::cout << "  LEGACY_AGENTIC_ENGINE engine = CREATE_AGENTIC_ENGINE();\n";
    std::cout << "  engine->initialize();\n";
    std::cout << "  // Smart pointer - no manual delete\n";
    std::cout << "  // Can access unified API: engine.GetUnifiedCore()\n\n";
    
    {
        MigrationExample::MigratingCodeExample example;
        example.Initialize();
        
        std::cout << "Using legacy-compatible API:\n";
        auto result = example.GenerateCode("Hello");
        std::cout << "  Result: " << result.substr(0, 50) << "...\n\n";
        
        std::cout << "Using unified API:\n";
        auto future = example.GenerateCodeAsync("Hello");
        auto taskResult = future.get();
        std::cout << "  Result: " << (taskResult.success ? "Success" : "Failed") << "\n\n";
        
        example.PrintMigrationStatus();
        example.Shutdown();
    }
    
    std::cout << "\nStage 3: Fully migrated code\n";
    std::cout << "  auto core = RawrXD::Agentic::Core::Create();\n";
    std::cout << "  core->Initialize();\n";
    std::cout << "  // Full unified API\n";
    std::cout << "  auto future = core->SubmitTask(task);\n";
    std::cout << "  // Async by default, type-safe, thread-safe\n\n";
    
    std::cout << "=== Migration Complete ===\n";
    
    return 0;
}

/*
 * COMPILATION:
 *   g++ -std=c++17 TransitionBridgeExample.cpp Core.cpp -I. -Isrc -o transition_example
 * 
 * MIGRATION WORKFLOW:
 * 
 * 1. Identify file using legacy API
 * 2. Replace #include "agentic_engine.h" with #include "agentic/TransitionBridge.h"
 * 3. Replace AgenticEngine* with LEGACY_AGENTIC_ENGINE
 * 4. Replace 'new AgenticEngine()' with CREATE_AGENTIC_ENGINE()
 * 5. Remove 'delete' statements
 * 6. Test - code should work unchanged
 * 7. Gradually migrate to unified API using GetUnifiedCore()
 * 8. Once fully migrated, remove TransitionBridge and use Core directly
 */
