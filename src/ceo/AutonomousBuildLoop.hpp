// ============================================================================
// AutonomousBuildLoop.hpp — The Self-Building, Self-Testing, Self-Repairing Loop
// This is the heart of the "AI software engineer" capability
// ============================================================================
#pragma once

#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace CEO {

using json = nlohmann::json;

// ============================================================================
// Build Configuration
// ============================================================================
struct BuildConfig {
    std::string buildCommand = "cmake --build build";
    std::string testCommand = "ctest --test-dir build";
    std::string cleanCommand = "cmake --build build --target clean";
    std::string configureCommand = "cmake -B build -S .";
    
    int buildTimeoutSec = 300;
    int testTimeoutSec = 600;
    int maxRepairAttempts = 5;
    
    bool incrementalBuild = true;
    bool parallelBuild = true;
    int parallelJobs = 0; // 0 = auto-detect
};

// ============================================================================
// Build Result
// ============================================================================
struct BuildResult {
    bool success = false;
    int exitCode = 0;
    std::string stdout_output;
    std::string stderr_output;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::chrono::milliseconds duration;
    
    json toJSON() const {
        json j;
        j["success"] = success;
        j["exit_code"] = exitCode;
        j["errors"] = errors;
        j["warnings"] = warnings;
        j["duration_ms"] = duration.count();
        return j;
    }
};

// ============================================================================
// Test Result
// ============================================================================
struct TestResult {
    bool success = false;
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    int skippedTests = 0;
    std::vector<std::string> failedTestNames;
    std::string output;
    std::chrono::milliseconds duration;
    
    json toJSON() const {
        json j;
        j["success"] = success;
        j["total"] = totalTests;
        j["passed"] = passedTests;
        j["failed"] = failedTests;
        j["skipped"] = skippedTests;
        j["failed_tests"] = failedTestNames;
        j["duration_ms"] = duration.count();
        return j;
    }
};

// ============================================================================
// Code Change
// ============================================================================
struct CodeChange {
    std::string filePath;
    std::string originalContent;
    std::string newContent;
    std::string description;
    bool applied = false;
    bool reverted = false;
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Autonomous Build Loop
// Implements: PLAN → MODIFY → BUILD → TEST → ANALYZE → PATCH → REPEAT
// ============================================================================
class AutonomousBuildLoop {
public:
    AutonomousBuildLoop();
    ~AutonomousBuildLoop();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Configuration
    void SetConfig(const BuildConfig& config) { m_config = config; }
    const BuildConfig& GetConfig() const { return m_config; }
    
    // Main Operations
    // Generate code and apply it
    bool GenerateAndApplyCode(const std::string& description, 
                              const std::vector<std::string>& targetFiles);
    
    // Build the project
    bool Build();
    BuildResult GetLastBuildResult() const { return m_lastBuildResult; }
    
    // Run tests
    bool Test();
    TestResult GetLastTestResult() const { return m_lastTestResult; }
    
    // Debug/Repair - the magic happens here
    bool Debug(const std::string& errorDescription);
    
    // Full autonomous cycle
    bool RunFullCycle(const std::string& goal);
    
    // State
    bool IsBuilding() const { return m_isBuilding.load(); }
    bool IsTesting() const { return m_isTesting.load(); }
    int GetRepairAttemptCount() const { return m_repairAttempts.load(); }
    
    // Change management
    std::vector<CodeChange> GetPendingChanges() const;
    bool ApplyChange(const CodeChange& change);
    bool RevertChange(const std::string& filePath);
    bool RevertAllChanges();
    
    // Callbacks
    using BuildCallback = std::function<void(const BuildResult&)>;
    using TestCallback = std::function<void(const TestResult&)>;
    using RepairCallback = std::function<void(const std::string& attempt, int count)>;
    
    void SetBuildCallback(BuildCallback cb) { m_buildCb = cb; }
    void SetTestCallback(TestCallback cb) { m_testCb = cb; }
    void SetRepairCallback(RepairCallback cb) { m_repairCb = cb; }
    
    // Export/Import
    json ExportState() const;
    bool ImportState(const json& state);
    
private:
    // Internal operations
    BuildResult ExecuteBuild();
    TestResult ExecuteTest();
    bool AnalyzeErrors();
    bool GenerateRepair();
    bool ApplyRepair();
    
    // Error parsing
    std::vector<std::string> ParseCompilerErrors(const std::string& output);
    std::vector<std::string> ParseTestFailures(const std::string& output);
    
    // File operations
    bool ReadFile(const std::string& path, std::string& content);
    bool WriteFile(const std::string& path, const std::string& content);
    bool BackupFile(const std::string& path);
    bool RestoreFile(const std::string& path);
    
    // Command execution
    BuildResult RunCommand(const std::string& command, int timeoutSec);
    
private:
    BuildConfig m_config;
    
    // State
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_isBuilding{false};
    std::atomic<bool> m_isTesting{false};
    std::atomic<int> m_repairAttempts{0};
    std::atomic<bool> m_cancelled{false};
    
    // Results
    BuildResult m_lastBuildResult;
    TestResult m_lastTestResult;
    
    // Change tracking
    std::vector<CodeChange> m_changes;
    mutable std::mutex m_changesMutex;
    
    // Callbacks
    BuildCallback m_buildCb;
    TestCallback m_testCb;
    RepairCallback m_repairCb;
};

} // namespace CEO
} // namespace RawrXD
