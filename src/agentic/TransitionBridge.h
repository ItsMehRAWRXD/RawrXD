/**
 * @file TransitionBridge.h
 * @brief Bridge header for gradual migration from legacy to unified architecture
 * 
 * This header provides:
 * 1. Type aliases for gradual transition
 * 2. Factory functions that create unified implementations
 * 3. Compatibility macros for common patterns
 * 4. Deprecation warnings to guide migration
 * 
 * Usage:
 *   Replace #include "agentic_engine.h" with #include "agentic/TransitionBridge.h"
 *   Gradually migrate from legacy types to unified types
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include "Core.h"
#include "LegacyCoreAdapter.h"
#include <memory>
#include <iostream>
#include <mutex>
#include <unordered_map>
#include <vector>

// ============================================================================
// Deprecation Macros
// ============================================================================

#ifdef _MSC_VER
    #define DEPRECATED(msg) __declspec(deprecated(msg))
#else
    #define DEPRECATED(msg) [[deprecated(msg)]]
#endif

// ============================================================================
// Type Aliases for Gradual Migration
// ============================================================================

namespace RawrXD {
namespace Migration {

/**
 * @brief Transition type: Legacy AgenticEngine -> Unified Core
 * 
 * DEPRECATED: Use RawrXD::Agentic::Core directly
 * Migration path:
 *   OLD: AgenticEngine* engine;
 *   NEW: std::shared_ptr<Agentic::Core> core;
 */
using AgenticEngine DEPRECATED("Use RawrXD::Agentic::Core instead") = Agentic::Core;

/**
 * @brief Smart pointer wrapper for legacy compatibility
 * 
 * Provides automatic conversion from legacy raw pointers to unified smart pointers
 */
class AgenticEnginePtr {
public:
    AgenticEnginePtr() = default;
    AgenticEnginePtr(std::nullptr_t) {}
    
    // Construct from unified Core
    AgenticEnginePtr(std::shared_ptr<Agentic::Core> core) : m_core(core) {}
    
    // Factory: Create new instance (replaces 'new AgenticEngine()')
    static AgenticEnginePtr Create() {
        return AgenticEnginePtr(Agentic::Core::Create());
    }
    
    // Factory: Wrap existing legacy engine (for adapter pattern)
    static AgenticEnginePtr FromLegacy(void* legacyEngine) {
        return AgenticEnginePtr(Agentic::Core::CreateLegacyAdapter(legacyEngine));
    }
    
    // Legacy-compatible methods
    void initialize() {
        if (m_core) m_core->Initialize();
    }
    
    bool isInitialized() const {
        return m_core && m_core->IsInitialized();
    }
    
    // Convenience methods (legacy API compatibility)
    std::string generateCode(const std::string& prompt) {
        if (!m_core) return "Error: Not initialized";
        
        Agentic::Task task;
        task.type = Agentic::TaskType::Inference;
        task.instruction = "Generate code: " + prompt;
        task.inferenceParams.prompt = prompt;
        task.inferenceParams.maxTokens = 512;
        
        auto result = m_core->ExecuteSync(task);
        return result.success ? result.output : result.errorMessage;
    }
    
    std::string analyzeCode(const std::string& code) {
        if (!m_core) return "Error: Not initialized";
        
        Agentic::Task task;
        task.type = Agentic::TaskType::Inference;
        task.instruction = "Analyze code";
        task.inferenceParams.prompt = "Analyze this code:\n" + code;
        task.inferenceParams.maxTokens = 1024;
        
        auto result = m_core->ExecuteSync(task);
        return result.success ? result.output : result.errorMessage;
    }
    
    std::string readFile(const std::string& path) {
        return m_core ? m_core->ReadFile(path) : "";
    }
    
    std::string writeFile(const std::string& path, const std::string& content) {
        return m_core && m_core->WriteFile(path, content) ? "Success" : "Failed";
    }
    
    std::string listDir(const std::string& path) {
        return m_core ? m_core->SearchCodebase(path) : "";
    }
    
    std::string executeCommand(const std::string& command) {
        return m_core ? m_core->ExecuteCommand(command) : "";
    }
    
    // Unified access (for new code)
    std::shared_ptr<Agentic::Core> GetUnifiedCore() { return m_core; }
    const std::shared_ptr<Agentic::Core>& GetUnifiedCore() const { return m_core; }
    
    // Operators for pointer-like behavior
    Agentic::Core* operator->() { return m_core.get(); }
    const Agentic::Core* operator->() const { return m_core.get(); }
    Agentic::Core& operator*() { return *m_core; }
    const Agentic::Core& operator*() const { return *m_core; }
    
    explicit operator bool() const { return m_core != nullptr; }
    bool operator==(std::nullptr_t) const { return m_core == nullptr; }
    bool operator!=(std::nullptr_t) const { return m_core != nullptr; }
    
private:
    std::shared_ptr<Agentic::Core> m_core;
};

// ============================================================================
// Migration Helper Functions
// ============================================================================

/**
 * @brief Convert legacy task to unified Task
 */
inline Agentic::Task ConvertLegacyTask(const std::string& type, 
                                        const std::string& instruction,
                                        const std::string& params = "") {
    Agentic::Task task;
    task.instruction = instruction;
    
    if (type == "file" || type == "file_edit") {
        task.type = Agentic::TaskType::File;
        // Parse params as JSON or simple format
        // For now, assume simple format: "operation|path|content"
        size_t pos1 = params.find('|');
        if (pos1 != std::string::npos) {
            task.fileParams.operation = params.substr(0, pos1);
            size_t pos2 = params.find('|', pos1 + 1);
            if (pos2 != std::string::npos) {
                task.fileParams.path = params.substr(pos1 + 1, pos2 - pos1 - 1);
                task.fileParams.content = params.substr(pos2 + 1);
            } else {
                task.fileParams.path = params.substr(pos1 + 1);
            }
        }
    }
    else if (type == "command" || type == "terminal") {
        task.type = Agentic::TaskType::Terminal;
        task.terminalParams.command = params.empty() ? instruction : params;
    }
    else if (type == "inference" || type == "generate") {
        task.type = Agentic::TaskType::Inference;
        task.inferenceParams.prompt = instruction;
        task.inferenceParams.maxTokens = 512;
    }
    else {
        task.type = Agentic::TaskType::Custom;
    }
    
    return task;
}

/**
 * @brief Execute legacy-style plan using unified Core
 */
inline std::string ExecuteLegacyPlan(AgenticEnginePtr& engine,
                                      const std::vector<std::tuple<std::string, std::string, std::string>>& steps) {
    if (!engine) return "Error: Engine not initialized";
    
    std::string report;
    for (const auto& [type, target, content] : steps) {
        auto task = ConvertLegacyTask(type, target, content);
        auto result = engine.GetUnifiedCore()->ExecuteSync(task);
        
        report += "[" + std::string(result.success ? "PASS" : "FAIL") + "] ";
        report += type + ": " + target + "\n";
        if (!result.success) {
            report += "  Error: " + result.errorMessage + "\n";
        }
    }
    
    return report;
}

// ============================================================================
// Migration Status Tracking
// ============================================================================

class MigrationTracker {
public:
    static MigrationTracker& GetInstance() {
        static MigrationTracker instance;
        return instance;
    }
    
    void RecordLegacyUsage(const std::string& file, const std::string& feature) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_legacyUsages[file].push_back(feature);
    }
    
    void RecordMigration(const std::string& file, const std::string& feature) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_migratedFeatures[file].push_back(feature);
    }
    
    std::vector<std::string> GetLegacyUsages(const std::string& file) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_legacyUsages.find(file);
        return (it != m_legacyUsages.end()) ? it->second : std::vector<std::string>{};
    }
    
    double GetMigrationProgress() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        size_t total = m_legacyUsages.size() + m_migratedFeatures.size();
        return total > 0 ? (double)m_migratedFeatures.size() / total * 100.0 : 100.0;
    }
    
    void PrintReport() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::cout << "\n=== Migration Report ===\n";
        std::cout << "Progress: " << GetMigrationProgress() << "%\n";
        std::cout << "Legacy files: " << m_legacyUsages.size() << "\n";
        std::cout << "Migrated files: " << m_migratedFeatures.size() << "\n";
        
        if (!m_legacyUsages.empty()) {
            std::cout << "\nRemaining legacy usages:\n";
            for (const auto& [file, features] : m_legacyUsages) {
                std::cout << "  " << file << ": " << features.size() << " features\n";
            }
        }
    }
    
private:
    MigrationTracker() = default;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::vector<std::string>> m_legacyUsages;
    std::unordered_map<std::string, std::vector<std::string>> m_migratedFeatures;
};

// Macro to track legacy usage
#define TRACK_LEGACY_USAGE(feature) \
    RawrXD::Migration::MigrationTracker::GetInstance().RecordLegacyUsage(__FILE__, feature)

// Macro to track migration
#define TRACK_MIGRATION(feature) \
    RawrXD::Migration::MigrationTracker::GetInstance().RecordMigration(__FILE__, feature)

} // namespace Migration
} // namespace RawrXD

// ============================================================================
// Backward Compatibility Macros
// ============================================================================

// Allow code to use AgenticEngine* with smart pointer semantics
#define LEGACY_AGENTIC_ENGINE RawrXD::Migration::AgenticEnginePtr

// Helper to create engine (replaces 'new AgenticEngine()')
#define CREATE_AGENTIC_ENGINE() RawrXD::Migration::AgenticEnginePtr::Create()

// Helper to wrap legacy engine
#define WRAP_LEGACY_ENGINE(ptr) RawrXD::Migration::AgenticEnginePtr::FromLegacy(ptr)

// ============================================================================
// Migration Guide Comments
// ============================================================================

/*
 * MIGRATION CHECKLIST:
 * 
 * Step 1: Replace includes
 *   OLD: #include "agentic_engine.h"
 *   NEW: #include "agentic/TransitionBridge.h"
 * 
 * Step 2: Replace type declarations
 *   OLD: AgenticEngine* m_engine;
 *   NEW: LEGACY_AGENTIC_ENGINE m_engine;
 * 
 * Step 3: Replace construction
 *   OLD: m_engine = new AgenticEngine();
 *   NEW: m_engine = CREATE_AGENTIC_ENGINE();
 * 
 * Step 4: Replace initialization
 *   OLD: m_engine->initialize();
 *   NEW: m_engine->initialize(); // Same API
 * 
 * Step 5: Gradually migrate to unified API
 *   OLD: m_engine->generateCode(prompt);
 *   NEW: auto core = m_engine.GetUnifiedCore();
 *        // Use unified API...
 * 
 * Step 6: Remove transition layer
 *   FINAL: std::shared_ptr<RawrXD::Agentic::Core> m_core;
 */
