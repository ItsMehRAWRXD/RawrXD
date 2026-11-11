// ============================================================================
// GoldenRecoveryTests.cpp — Golden Recovery Test Implementation
// ============================================================================

#include "GoldenRecoveryTests.hpp"
#include "../../validation/fault_injection/WorkerCrashInjector.hpp"
#include "../../validation/fault_injection/MemoryPressureInjector.hpp"
#include "../../validation/fault_injection/StateCorruptionInjector.hpp"
#include "../../validation/fault_injection/ExceptionStormInjector.hpp"
#include "../../validation/recovery_telemetry/RecoveryTelemetry.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <chrono>
#include <thread>

namespace RawrXD {
namespace Validation {

// ============================================================================
// Golden Test Result Implementation
// ============================================================================
nlohmann::json GoldenTestResult::toJson() const {
    nlohmann::json j;
    j["test_id"] = testId;
    j["test_name"] = testName;
    j["timestamp"] = timestamp;
    j["passed"] = passed;
    j["failure_reason"] = failureReason;
    j["setup_time_ms"] = setupTimeMs;
    j["injection_time_ms"] = injectionTimeMs;
    j["detection_time_ms"] = detectionTimeMs;
    j["recovery_time_ms"] = recoveryTimeMs;
    j["total_time_ms"] = totalTimeMs;
    j["fault_detected"] = faultDetected;
    j["recovery_initiated"] = recoveryInitiated;
    j["recovery_successful"] = recoverySuccessful;
    j["retry_count"] = retryCount;
    j["artifact_directory"] = artifactDirectory;
    j["fault_manifest_path"] = faultManifestPath;
    j["recovery_log_path"] = recoveryLogPath;
    j["telemetry_path"] = telemetryPath;
    j["stdout_path"] = stdoutPath;
    j["sha256_path"] = sha256Path;
    j["result_path"] = resultPath;
    return j;
}

// ============================================================================
// Golden Recovery Test Base Implementation
// ============================================================================
GoldenRecoveryTest::GoldenRecoveryTest(const std::string& id, const std::string& name)
    : m_testId(id), m_testName(name) {
}

GoldenTestResult GoldenRecoveryTest::run() {
    m_result = GoldenTestResult();
    m_result.testId = m_testId;
    m_result.testName = m_testName;
    
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
    m_result.timestamp = ss.str();
    
    m_startTime = std::chrono::steady_clock::now();
    
    std::cout << "[TEST] Starting " << m_testId << ": " << m_testName << std::endl;
    
    try {
        // Setup
        auto setupStart = std::chrono::steady_clock::now();
        if (!setup()) {
            m_result.passed = false;
            m_result.failureReason = "Setup failed";
            teardown();
            return m_result;
        }
        m_result.setupTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - setupStart).count();
        
        // Create artifact directory
        if (!createArtifactDirectory()) {
            m_result.passed = false;
            m_result.failureReason = "Failed to create artifact directory";
            teardown();
            return m_result;
        }
        
        // Execute fault injection
        auto injectionStart = std::chrono::steady_clock::now();
        if (!executeFaultInjection()) {
            m_result.passed = false;
            m_result.failureReason = "Fault injection failed";
            teardown();
            return m_result;
        }
        m_result.injectionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - injectionStart).count();
        
        // Wait for detection
        auto detectionStart = std::chrono::steady_clock::now();
        if (!waitForDetection()) {
            m_result.passed = false;
            m_result.failureReason = "Fault detection timeout or failed";
            teardown();
            return m_result;
        }
        m_result.detectionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - detectionStart).count();
        m_result.faultDetected = true;
        
        // Wait for recovery
        auto recoveryStart = std::chrono::steady_clock::now();
        if (!waitForRecovery()) {
            m_result.passed = false;
            m_result.failureReason = "Recovery timeout or failed";
            teardown();
            return m_result;
        }
        m_result.recoveryTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - recoveryStart).count();
        m_result.recoveryInitiated = true;
        
        // Verify recovery
        if (!verifyRecovery()) {
            m_result.passed = false;
            m_result.failureReason = "Recovery verification failed";
            teardown();
            return m_result;
        }
        m_result.recoverySuccessful = true;
        
        // Save artifacts
        saveArtifacts();
        
        m_result.passed = true;
        m_result.totalTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - m_startTime).count();
        
        std::cout << "[PASS] " << m_testId << " completed in " << m_result.totalTimeMs << "ms" << std::endl;
        
    } catch (const std::exception& e) {
        m_result.passed = false;
        m_result.failureReason = std::string("Exception: ") + e.what();
        std::cerr << "[FAIL] " << m_testId << ": " << e.what() << std::endl;
    }
    
    teardown();
    return m_result;
}

bool GoldenRecoveryTest::createArtifactDirectory() {
    std::stringstream ss;
    ss << m_artifactDir << "/run-" << m_testId << "-" << m_result.timestamp.substr(0, 10) << "-EXECUTED";
    m_result.artifactDirectory = ss.str();
    
    try {
        std::filesystem::create_directories(m_result.artifactDirectory);
        return true;
    } catch (...) {
        return false;
    }
}

bool GoldenRecoveryTest::saveArtifacts() {
    try {
        // Save result.json
        m_result.resultPath = m_result.artifactDirectory + "/result.json";
        std::ofstream resultFile(m_result.resultPath);
        resultFile << m_result.toJson().dump(2);
        resultFile.close();
        
        // Save telemetry
        m_result.telemetryPath = m_result.artifactDirectory + "/telemetry.json";
        RecoveryTelemetryCollector::instance().saveToFile(m_result.telemetryPath);
        
        // Calculate SHA256
        m_result.sha256Path = m_result.artifactDirectory + "/sha256.json";
        nlohmann::json sha256Data;
        sha256Data["result_json"] = calculateSHA256(m_result.resultPath);
        sha256Data["telemetry_json"] = calculateSHA256(m_result.telemetryPath);
        std::ofstream sha256File(m_result.sha256Path);
        sha256File << sha256Data.dump(2);
        sha256File.close();
        
        return true;
    } catch (...) {
        return false;
    }
}

std::string GoldenRecoveryTest::calculateSHA256(const std::string& filepath) const {
    // Simplified - in production would use actual SHA256
    std::ifstream file(filepath, std::ios::binary);
    if (!file) return "ERROR";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    // Simple hash for demonstration
    size_t hash = 0;
    for (char c : content) {
        hash = hash * 31 + c;
    }
    
    std::stringstream result;
    result << std::hex << hash;
    return result.str();
}

// ============================================================================
// Test 08: Worker Crash Recovery Implementation
// ============================================================================
Test08_WorkerCrashRecovery::Test08_WorkerCrashRecovery()
    : GoldenRecoveryTest("TEST-08", "Agentic Recovery - Worker Crash") {
    m_workerName = "TestWorker_" + std::to_string(std::hash<std::thread::id>{}(std::this_thread::get_id()));
}

bool Test08_WorkerCrashRecovery::setup() {
    m_injector = std::make_shared<WorkerCrashInjector>();
    m_injector->initialize();
    
    // Start a test worker thread
    m_workerRunning.store(true);
    m_workerThread = std::thread(&Test08_WorkerCrashRecovery::workerLoop, this);
    
    // Register the worker
    m_injector->registerWorkerThread(m_workerThread.get_id(), m_workerName);
    
    // Give worker time to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    return m_injector->isAvailable();
}

void Test08_WorkerCrashRecovery::workerLoop() {
    int counter = 0;
    while (m_workerRunning.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        counter++;
        // Simulate some work
        if (counter > 10000) counter = 0;
    }
}

bool Test08_WorkerCrashRecovery::executeFaultInjection() {
    auto result = m_injector->injectByName(m_workerName);
    return result.success;
}

bool Test08_WorkerCrashRecovery::waitForDetection() {
    // In a real implementation, this would wait for the AgenticDeepThinkingEngine
    // to detect the worker crash. For now, simulate detection.
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 5000) {
        // Check if fault was detected
        auto events = RecoveryTelemetryCollector::instance().getEventsByType(
            RecoveryEventType::FAULT_DETECTED);
        for (const auto& event : events) {
            if (event.faultId.find("WORKER") != std::string::npos) {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test08_WorkerCrashRecovery::waitForRecovery() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 10000) {
        if (m_recoveryDetected.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test08_WorkerCrashRecovery::verifyRecovery() {
    // Verify that the worker was restarted or recovery was successful
    const auto& metrics = RecoveryTelemetryCollector::instance().getMetrics();
    return metrics.totalRecoveriesSuccessful.load() > 0;
}

void Test08_WorkerCrashRecovery::teardown() {
    // Signal worker to stop
    m_workerRunning.store(false);
    
    // Give worker a chance to exit gracefully
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Detach thread if it's still running (avoid deadlock)
    if (m_workerThread.joinable()) {
        m_workerThread.detach();
    }
    
    if (m_injector) {
        m_injector->shutdown();
    }
}

// ============================================================================
// Test 09: Memory Pressure Recovery Implementation
// ============================================================================
Test09_MemoryPressureRecovery::Test09_MemoryPressureRecovery()
    : GoldenRecoveryTest("TEST-09", "Agentic Recovery - Memory Pressure") {
}

bool Test09_MemoryPressureRecovery::setup() {
    m_injector = std::make_shared<MemoryPressureInjector>();
    m_injector->initialize();
    m_injector->setPressureMode(MemoryPressureInjector::PressureMode::GRADUAL);
    m_injector->setTargetMemoryMB(m_targetMemoryMB);
    
    // Set up telemetry callback
    RecoveryTelemetryCollector::instance().setEventCallback(
        [this](const RecoveryEvent& event) {
            if (event.type == RecoveryEventType::CACHE_CLEARED) {
                m_cacheCleared.store(true);
            }
            if (event.type == RecoveryEventType::FAULT_DETECTED &&
                event.trigger.find("MEMORY") != std::string::npos) {
                m_pressureDetected.store(true);
            }
        });
    
    return true;
}

bool Test09_MemoryPressureRecovery::executeFaultInjection() {
    auto result = m_injector->injectGradualPressure(m_targetMemoryMB, 5);
    return result.success;
}

bool Test09_MemoryPressureRecovery::waitForDetection() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 10000) {
        if (m_pressureDetected.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test09_MemoryPressureRecovery::waitForRecovery() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 15000) {
        if (m_cacheCleared.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test09_MemoryPressureRecovery::verifyRecovery() {
    // Verify memory was released
    const auto& metrics = RecoveryTelemetryCollector::instance().getMetrics();
    return m_cacheCleared.load() && metrics.totalRecoveriesSuccessful.load() > 0;
}

void Test09_MemoryPressureRecovery::teardown() {
    if (m_injector) {
        m_injector->releaseAllPressure();
        m_injector->shutdown();
    }
}

// ============================================================================
// Test 10: State Rollback Recovery Implementation
// ============================================================================
Test10_StateRollbackRecovery::Test10_StateRollbackRecovery()
    : GoldenRecoveryTest("TEST-10", "Agentic Recovery - State Rollback") {
}

bool Test10_StateRollbackRecovery::setup() {
    m_injector = std::make_shared<StateCorruptionInjector>();
    m_injector->initialize();
    
    // Initialize test state
    m_testState.magic = 0xDEADBEEF;
    m_testState.counter = 42;
    std::strcpy(m_testState.data, "Test state data");
    
    // Register the state region
    m_injector->registerStateRegion("TestState", &m_testState, sizeof(m_testState));
    
    // Set up telemetry callback
    RecoveryTelemetryCollector::instance().setEventCallback(
        [this](const RecoveryEvent& event) {
            if (event.type == RecoveryEventType::ROLLBACK_COMPLETED) {
                m_rollbackCompleted.store(true);
            }
            if (event.type == RecoveryEventType::FAULT_DETECTED &&
                event.trigger.find("STATE") != std::string::npos) {
                m_corruptionDetected.store(true);
            }
        });
    
    return true;
}

bool Test10_StateRollbackRecovery::executeFaultInjection() {
    auto result = m_injector->corruptRegion("TestState");
    return result.success;
}

bool Test10_StateRollbackRecovery::waitForDetection() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 5000) {
        if (m_corruptionDetected.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test10_StateRollbackRecovery::waitForRecovery() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 10000) {
        if (m_rollbackCompleted.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test10_StateRollbackRecovery::verifyRecovery() {
    // Verify state was restored
    bool magicOk = m_testState.magic == 0xDEADBEEF;
    bool counterOk = m_testState.counter == 42;
    bool dataOk = std::strcmp(m_testState.data, "Test state data") == 0;
    
    return magicOk && counterOk && dataOk && m_rollbackCompleted.load();
}

void Test10_StateRollbackRecovery::teardown() {
    if (m_injector) {
        m_injector->unregisterStateRegion("TestState");
        m_injector->shutdown();
    }
}

// ============================================================================
// Test 11: Exception Storm Recovery Implementation
// ============================================================================
Test11_ExceptionStormRecovery::Test11_ExceptionStormRecovery()
    : GoldenRecoveryTest("TEST-11", "Agentic Recovery - Exception Storm") {
}

bool Test11_ExceptionStormRecovery::setup() {
    m_injector = std::make_shared<ExceptionStormInjector>();
    m_injector->initialize();
    m_injector->setStormMode(ExceptionStormInjector::StormMode::BURST);
    m_injector->setExceptionCount(m_exceptionCount);
    m_injector->setRatePerSecond(m_ratePerSecond);
    
    // Set up telemetry callback
    RecoveryTelemetryCollector::instance().setEventCallback(
        [this](const RecoveryEvent& event) {
            if (event.type == RecoveryEventType::RECOVERY_COMPLETED &&
                event.trigger.find("STORM") != std::string::npos) {
                m_stormMitigated.store(true);
            }
            if (event.type == RecoveryEventType::FAULT_DETECTED &&
                event.trigger.find("STORM") != std::string::npos) {
                m_stormDetected.store(true);
            }
        });
    
    return true;
}

bool Test11_ExceptionStormRecovery::executeFaultInjection() {
    auto result = m_injector->injectBurst(m_exceptionCount, m_ratePerSecond);
    return result.success;
}

bool Test11_ExceptionStormRecovery::waitForDetection() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 10000) {
        if (m_stormDetected.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test11_ExceptionStormRecovery::waitForRecovery() {
    auto start = std::chrono::steady_clock::now();
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
           std::chrono::steady_clock::now() - start).count() < 15000) {
        if (m_stormMitigated.load()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool Test11_ExceptionStormRecovery::verifyRecovery() {
    // Verify no cascading failures and storm was handled
    const auto& metrics = RecoveryTelemetryCollector::instance().getMetrics();
    bool noCascading = metrics.currentConsecutiveFailures.load() < 3;
    return m_stormMitigated.load() && noCascading;
}

void Test11_ExceptionStormRecovery::teardown() {
    if (m_injector) {
        m_injector->shutdown();
    }
}

// ============================================================================
// Golden Recovery Test Suite Implementation
// ============================================================================
GoldenRecoveryTestSuite& GoldenRecoveryTestSuite::instance() {
    static GoldenRecoveryTestSuite instance;
    static bool initialized = false;
    if (!initialized) {
        instance.initializeDefaultTests();
        initialized = true;
    }
    return instance;
}

void GoldenRecoveryTestSuite::initializeDefaultTests() {
    registerTest(std::make_shared<Test08_WorkerCrashRecovery>());
    registerTest(std::make_shared<Test09_MemoryPressureRecovery>());
    registerTest(std::make_shared<Test10_StateRollbackRecovery>());
    registerTest(std::make_shared<Test11_ExceptionStormRecovery>());
}

void GoldenRecoveryTestSuite::registerTest(std::shared_ptr<GoldenRecoveryTest> test) {
    std::lock_guard<std::mutex> lock(m_testsMutex);
    if (test) {
        test->setArtifactDirectory(m_artifactBaseDir);
        test->setTimeoutMs(m_globalTimeoutMs);
        m_tests[test->getId()] = test;
    }
}

void GoldenRecoveryTestSuite::unregisterTest(const std::string& testId) {
    std::lock_guard<std::mutex> lock(m_testsMutex);
    m_tests.erase(testId);
}

std::vector<GoldenTestResult> GoldenRecoveryTestSuite::runAllTests() {
    std::vector<std::string> testIds;
    {
        std::lock_guard<std::mutex> lock(m_testsMutex);
        for (const auto& pair : m_tests) {
            if (pair.second->isEnabled()) {
                testIds.push_back(pair.first);
            }
        }
    }
    return runTests(testIds);
}

GoldenTestResult GoldenRecoveryTestSuite::runTest(const std::string& testId) {
    std::shared_ptr<GoldenRecoveryTest> test;
    {
        std::lock_guard<std::mutex> lock(m_testsMutex);
        auto it = m_tests.find(testId);
        if (it != m_tests.end()) {
            test = it->second;
        }
    }
    
    if (!test) {
        GoldenTestResult result;
        result.testId = testId;
        result.passed = false;
        result.failureReason = "Test not found";
        return result;
    }
    
    return test->run();
}

std::vector<GoldenTestResult> GoldenRecoveryTestSuite::runTests(const std::vector<std::string>& testIds) {
    m_lastResults.clear();
    
    for (const auto& testId : testIds) {
        auto result = runTest(testId);
        m_lastResults.push_back(result);
    }
    
    return m_lastResults;
}

std::vector<std::shared_ptr<GoldenRecoveryTest>> GoldenRecoveryTestSuite::getAllTests() const {
    std::lock_guard<std::mutex> lock(m_testsMutex);
    std::vector<std::shared_ptr<GoldenRecoveryTest>> result;
    for (const auto& pair : m_tests) {
        result.push_back(pair.second);
    }
    return result;
}

std::shared_ptr<GoldenRecoveryTest> GoldenRecoveryTestSuite::getTest(const std::string& testId) const {
    std::lock_guard<std::mutex> lock(m_testsMutex);
    auto it = m_tests.find(testId);
    if (it != m_tests.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::string> GoldenRecoveryTestSuite::getTestIds() const {
    std::lock_guard<std::mutex> lock(m_testsMutex);
    std::vector<std::string> ids;
    for (const auto& pair : m_tests) {
        ids.push_back(pair.first);
    }
    return ids;
}

nlohmann::json GoldenRecoveryTestSuite::exportResults() const {
    nlohmann::json j;
    j["timestamp"] = []() {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t_now), "%Y-%m-%dT%H:%M:%SZ");
        return ss.str();
    }();
    
    j["summary"]["total_tests"] = m_lastResults.size();
    j["summary"]["passed"] = std::count_if(m_lastResults.begin(), m_lastResults.end(),
        [](const GoldenTestResult& r) { return r.passed; });
    j["summary"]["failed"] = std::count_if(m_lastResults.begin(), m_lastResults.end(),
        [](const GoldenTestResult& r) { return !r.passed; });
    
    j["results"] = nlohmann::json::array();
    for (const auto& result : m_lastResults) {
        j["results"].push_back(result.toJson());
    }
    
    return j;
}

bool GoldenRecoveryTestSuite::saveResultsToFile(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) {
        return false;
    }
    file << exportResults().dump(2);
    return file.good();
}

void GoldenRecoveryTestSuite::reset() {
    std::lock_guard<std::mutex> lock(m_testsMutex);
    m_tests.clear();
    m_lastResults.clear();
    initializeDefaultTests();
}

// ============================================================================
// Test Runner
// ============================================================================
int RunGoldenRecoveryTests(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "Golden Recovery Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Initialize telemetry
    RecoveryTelemetryLogger::instance().initialize("validation/recovery_tests/logs");
    
    // Parse arguments
    std::vector<std::string> testIds;
    for (int i = 1; i < argc; ++i) {
        testIds.push_back(argv[i]);
    }
    
    // Run tests
    std::vector<GoldenTestResult> results;
    if (testIds.empty()) {
        std::cout << "Running all tests..." << std::endl;
        results = GoldenRecoveryTestSuite::instance().runAllTests();
    } else {
        std::cout << "Running specified tests..." << std::endl;
        results = GoldenRecoveryTestSuite::instance().runTests(testIds);
    }
    
    // Print summary
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    for (const auto& result : results) {
        if (result.passed) {
            passed++;
            std::cout << "[PASS] " << result.testId << ": " << result.testName << std::endl;
        } else {
            failed++;
            std::cout << "[FAIL] " << result.testId << ": " << result.testName << std::endl;
            std::cout << "       Reason: " << result.failureReason << std::endl;
        }
    }
    
    std::cout << std::endl;
    std::cout << "Total: " << results.size() << ", Passed: " << passed << ", Failed: " << failed << std::endl;
    
    // Save results
    std::string resultsPath = "validation/recovery_tests/golden_recovery_results.json";
    if (GoldenRecoveryTestSuite::instance().saveResultsToFile(resultsPath)) {
        std::cout << "Results saved to: " << resultsPath << std::endl;
    }
    
    // Print metrics
    const auto& metrics = RecoveryTelemetryCollector::instance().getMetrics();
    std::cout << std::endl;
    std::cout << "Recovery Metrics:" << std::endl;
    std::cout << "  MTTD: " << metrics.getMTTD() << " ms" << std::endl;
    std::cout << "  MTTR: " << metrics.getMTTR() << " ms" << std::endl;
    std::cout << "  Success Rate: " << (metrics.getSuccessRate() * 100.0) << "%" << std::endl;
    std::cout << "  False Positive Rate: " << (metrics.getFalsePositiveRate() * 100.0) << "%" << std::endl;
    
    return failed > 0 ? 1 : 0;
}

} // namespace Validation
} // namespace RawrXD

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    return RawrXD::Validation::RunGoldenRecoveryTests(argc, argv);
}