// ============================================================================
// GoldenRecoveryTests.hpp — Golden Recovery Validation Suite
// ============================================================================
// Mission 2.3: Golden Recovery Tests
//
// Test 08: Agentic Recovery - Worker Crash
// Test 09: Agentic Recovery - Memory Pressure
// Test 10: Agentic Recovery - State Rollback
// Test 11: Agentic Recovery - Exception Storm
//
// Each test produces:
//   run-XXXXX-EXECUTED/
//   ├── fault_manifest.json
//   ├── recovery_log.json
//   ├── telemetry.json
//   ├── stdout.log
//   ├── sha256.json
//   └── result.json
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>

#include "nlohmann/json.hpp"
#include "../fault_injection/FaultInjector.hpp"
#include "../recovery_telemetry/RecoveryTelemetry.hpp"

namespace RawrXD {
namespace Validation {

// Forward declarations
class WorkerCrashInjector;
class MemoryPressureInjector;
class ServiceKillInjector;
class StateCorruptionInjector;
class ExceptionStormInjector;

// ============================================================================
// Test Result
// ============================================================================
struct GoldenTestResult {
    std::string testId;
    std::string testName;
    std::string timestamp;
    bool passed = false;
    std::string failureReason;
    
    // Timing
    uint64_t setupTimeMs = 0;
    uint64_t injectionTimeMs = 0;
    uint64_t detectionTimeMs = 0;
    uint64_t recoveryTimeMs = 0;
    uint64_t totalTimeMs = 0;
    
    // Metrics
    bool faultDetected = false;
    bool recoveryInitiated = false;
    bool recoverySuccessful = false;
    int retryCount = 0;
    
    // Artifacts
    std::string artifactDirectory;
    std::string faultManifestPath;
    std::string recoveryLogPath;
    std::string telemetryPath;
    std::string stdoutPath;
    std::string sha256Path;
    std::string resultPath;
    
    nlohmann::json toJson() const;
};

// ============================================================================
// Golden Recovery Test Base
// ============================================================================
class GoldenRecoveryTest {
public:
    GoldenRecoveryTest(const std::string& id, const std::string& name);
    virtual ~GoldenRecoveryTest() = default;
    
    // Test execution
    GoldenTestResult run();
    
    // Test information
    const std::string& getId() const { return m_testId; }
    const std::string& getName() const { return m_testName; }
    bool isEnabled() const { return m_enabled; }
    void setEnabled(bool enabled) { m_enabled = enabled; }
    
    // Configuration
    void setArtifactDirectory(const std::string& dir) { m_artifactDir = dir; }
    void setTimeoutMs(uint64_t timeout) { m_timeoutMs = timeout; }

protected:
    // Override in derived classes
    virtual bool setup() = 0;
    virtual bool executeFaultInjection() = 0;
    virtual bool waitForDetection() = 0;
    virtual bool waitForRecovery() = 0;
    virtual bool verifyRecovery() = 0;
    virtual void teardown() = 0;
    
    // Utilities
    bool createArtifactDirectory();
    bool saveArtifacts();
    std::string calculateSHA256(const std::string& filepath) const;
    
    std::string m_testId;
    std::string m_testName;
    bool m_enabled = true;
    std::string m_artifactDir;
    uint64_t m_timeoutMs = 30000; // 30 second default
    
    GoldenTestResult m_result;
    std::chrono::steady_clock::time_point m_startTime;
};

// ============================================================================
// Test 08: Worker Crash Recovery
// ============================================================================
class Test08_WorkerCrashRecovery : public GoldenRecoveryTest {
public:
    Test08_WorkerCrashRecovery();
    
protected:
    bool setup() override;
    bool executeFaultInjection() override;
    bool waitForDetection() override;
    bool waitForRecovery() override;
    bool verifyRecovery() override;
    void teardown() override;
    
private:
    std::shared_ptr<WorkerCrashInjector> m_injector;
    std::string m_workerName;
    std::thread m_workerThread;
    std::atomic<bool> m_workerRunning{false};
    std::atomic<bool> m_recoveryDetected{false};
    
    void workerLoop();
};

// ============================================================================
// Test 09: Memory Pressure Recovery
// ============================================================================
class Test09_MemoryPressureRecovery : public GoldenRecoveryTest {
public:
    Test09_MemoryPressureRecovery();
    
protected:
    bool setup() override;
    bool executeFaultInjection() override;
    bool waitForDetection() override;
    bool waitForRecovery() override;
    bool verifyRecovery() override;
    void teardown() override;
    
private:
    std::shared_ptr<MemoryPressureInjector> m_injector;
    std::atomic<bool> m_pressureDetected{false};
    std::atomic<bool> m_cacheCleared{false};
    size_t m_targetMemoryMB = 512;
};

// ============================================================================
// Test 10: State Rollback Recovery
// ============================================================================
class Test10_StateRollbackRecovery : public GoldenRecoveryTest {
public:
    Test10_StateRollbackRecovery();
    
protected:
    bool setup() override;
    bool executeFaultInjection() override;
    bool waitForDetection() override;
    bool waitForRecovery() override;
    bool verifyRecovery() override;
    void teardown() override;
    
private:
    std::shared_ptr<StateCorruptionInjector> m_injector;
    struct TestState {
        uint32_t magic = 0xDEADBEEF;
        uint64_t counter = 0;
        char data[256];
    } m_testState;
    std::atomic<bool> m_corruptionDetected{false};
    std::atomic<bool> m_rollbackCompleted{false};
};

// ============================================================================
// Test 11: Exception Storm Recovery
// ============================================================================
class Test11_ExceptionStormRecovery : public GoldenRecoveryTest {
public:
    Test11_ExceptionStormRecovery();
    
protected:
    bool setup() override;
    bool executeFaultInjection() override;
    bool waitForDetection() override;
    bool waitForRecovery() override;
    bool verifyRecovery() override;
    void teardown() override;
    
private:
    std::shared_ptr<ExceptionStormInjector> m_injector;
    std::atomic<bool> m_stormDetected{false};
    std::atomic<bool> m_stormMitigated{false};
    int m_exceptionCount = 50;
    int m_ratePerSecond = 10;
};

// ============================================================================
// Golden Recovery Test Suite
// ============================================================================
class GoldenRecoveryTestSuite {
public:
    static GoldenRecoveryTestSuite& instance();
    
    // Test registration
    void registerTest(std::shared_ptr<GoldenRecoveryTest> test);
    void unregisterTest(const std::string& testId);
    
    // Test execution
    std::vector<GoldenTestResult> runAllTests();
    GoldenTestResult runTest(const std::string& testId);
    std::vector<GoldenTestResult> runTests(const std::vector<std::string>& testIds);
    
    // Test queries
    std::vector<std::shared_ptr<GoldenRecoveryTest>> getAllTests() const;
    std::shared_ptr<GoldenRecoveryTest> getTest(const std::string& testId) const;
    std::vector<std::string> getTestIds() const;
    
    // Configuration
    void setArtifactBaseDirectory(const std::string& dir) { m_artifactBaseDir = dir; }
    void setGlobalTimeoutMs(uint64_t timeout) { m_globalTimeoutMs = timeout; }
    
    // Results
    std::vector<GoldenTestResult> getLastResults() const { return m_lastResults; }
    nlohmann::json exportResults() const;
    bool saveResultsToFile(const std::string& filepath) const;
    
    // Reset
    void reset();

private:
    GoldenRecoveryTestSuite() = default;
    ~GoldenRecoveryTestSuite() = default;
    
    std::map<std::string, std::shared_ptr<GoldenRecoveryTest>> m_tests;
    mutable std::mutex m_testsMutex;
    
    std::string m_artifactBaseDir = "validation/recovery_tests";
    uint64_t m_globalTimeoutMs = 60000;
    std::vector<GoldenTestResult> m_lastResults;
    
    void initializeDefaultTests();
};

// ============================================================================
// Test Runner
// ============================================================================
int RunGoldenRecoveryTests(int argc, char* argv[]);

} // namespace Validation
} // namespace RawrXD