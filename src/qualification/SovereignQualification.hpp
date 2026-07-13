// SovereignQualification.hpp
// Phase D.4 Batch 5/5 — Full System Qualification
// Comprehensive qualification suite for production readiness

#ifndef SOVEREIGN_QUALIFICATION_HPP
#define SOVEREIGN_QUALIFICATION_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>
#include <optional>
#include <future>

namespace Sovereign {

// Forward declarations
class SovereignUnifiedRuntime;
class SovereignSecurityLayer;
class SovereignObservability;

// ============================================================================
// Qualification Types
// ============================================================================

enum class TestCategory {
    UNIT,           // Unit tests
    INTEGRATION,    // Integration tests
    PERFORMANCE,    // Performance benchmarks
    SECURITY,       // Security tests
    STRESS,         // Stress tests
    RECOVERY,       // Recovery tests
    COMPATIBILITY,  // Compatibility tests
    END_TO_END      // Full system tests
};

enum class TestStatus {
    NOT_RUN,
    RUNNING,
    PASSED,
    FAILED,
    SKIPPED,
    ERROR
};

enum class Severity {
    CRITICAL,       // Must pass for production
    HIGH,           // Important for production
    MEDIUM,         // Should pass
    LOW             // Nice to have
};

// ============================================================================
// Test Definition
// ============================================================================

struct TestDefinition {
    std::string id;
    std::string name;
    std::string description;
    TestCategory category;
    Severity severity;
    std::chrono::seconds timeout;
    std::vector<std::string> dependencies;
    std::map<std::string, std::string> parameters;
    
    TestDefinition()
        : category(TestCategory::UNIT)
        , severity(Severity::MEDIUM)
        , timeout(std::chrono::seconds(60))
    {}
};

// ============================================================================
// Test Result
// ============================================================================

struct TestResult {
    std::string test_id;
    TestStatus status;
    std::string message;
    std::chrono::milliseconds duration;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point completed_at;
    std::map<std::string, std::string> details;
    std::vector<std::string> logs;
    std::optional<double> performance_metric;
    
    TestResult()
        : status(TestStatus::NOT_RUN)
    {}
};

// ============================================================================
// Qualification Criteria
// ============================================================================

struct QualificationCriteria {
    // Pass thresholds
    double min_pass_rate_critical;
    double min_pass_rate_high;
    double min_pass_rate_medium;
    double min_pass_rate_low;
    
    // Performance thresholds
    double max_inference_latency_p95_ms;
    double min_inference_throughput_tps;
    double max_agent_creation_time_ms;
    double max_swarm_consensus_time_ms;
    
    // Reliability thresholds
    double min_uptime_percent;
    uint32_t max_recovery_time_seconds;
    uint32_t max_error_rate_percent;
    
    // Security thresholds
    bool require_auth_enabled;
    bool require_audit_logging;
    bool require_encryption;
    
    QualificationCriteria()
        : min_pass_rate_critical(1.0)
        , min_pass_rate_high(0.95)
        , min_pass_rate_medium(0.90)
        , min_pass_rate_low(0.80)
        , max_inference_latency_p95_ms(1000.0)
        , min_inference_throughput_tps(50.0)
        , max_agent_creation_time_ms(500.0)
        , max_swarm_consensus_time_ms(2000.0)
        , min_uptime_percent(99.9)
        , max_recovery_time_seconds(30)
        , max_error_rate_percent(1)
        , require_auth_enabled(true)
        , require_audit_logging(true)
        , require_encryption(true)
    {}
};

// ============================================================================
// Test Suite
// ============================================================================

class TestSuite {
public:
    using TestFunction = std::function<TestResult(const TestDefinition&)>;
    
    TestSuite();
    ~TestSuite();
    
    // Registration
    void RegisterTest(const TestDefinition& definition, TestFunction func);
    void UnregisterTest(const std::string& test_id);
    
    // Discovery
    std::vector<TestDefinition> GetTests(TestCategory category = 
        static_cast<TestCategory>(-1));
    std::vector<TestDefinition> GetTestsBySeverity(Severity severity);
    std::optional<TestDefinition> GetTest(const std::string& test_id);
    
    // Execution
    TestResult RunTest(const std::string& test_id);
    std::vector<TestResult> RunCategory(TestCategory category);
    std::vector<TestResult> RunSeverity(Severity severity);
    std::vector<TestResult> RunAll();
    
    // Parallel execution
    std::vector<TestResult> RunParallel(const std::vector<std::string>& test_ids,
                                         uint32_t max_concurrency = 4);
    
    // Results
    std::optional<TestResult> GetResult(const std::string& test_id);
    std::vector<TestResult> GetAllResults();
    void ClearResults();
    
    // Statistics
    struct TestStatistics {
        size_t total_tests;
        size_t passed;
        size_t failed;
        size_t skipped;
        size_t errors;
        double pass_rate;
        std::chrono::milliseconds total_duration;
        std::map<TestCategory, size_t> by_category;
        std::map<Severity, double> pass_rate_by_severity;
    };
    TestStatistics GetStatistics() const;
    
private:
    std::map<std::string, std::pair<TestDefinition, TestFunction>> tests_;
    std::map<std::string, TestResult> results_;
    mutable std::mutex tests_mutex_;
    
    bool CheckDependencies(const TestDefinition& def);
};

// ============================================================================
// Qualification Report
// ============================================================================

struct QualificationReport {
    std::string report_id;
    std::string version;
    std::chrono::system_clock::time_point generated_at;
    std::chrono::milliseconds total_duration;
    
    QualificationCriteria criteria;
    TestSuite::TestStatistics statistics;
    std::vector<TestResult> results;
    
    // Evaluation
    bool qualified;
    std::vector<std::string> blockers;
    std::vector<std::string> warnings;
    std::vector<std::string> recommendations;
    
    // Performance summary
    struct PerformanceSummary {
        double avg_inference_latency_ms;
        double p95_inference_latency_ms;
        double avg_throughput_tps;
        double avg_agent_creation_ms;
        double avg_swarm_consensus_ms;
        double measured_uptime_percent;
    };
    std::optional<PerformanceSummary> performance;
    
    QualificationReport()
        : qualified(false)
    {}
};

// ============================================================================
// Built-in Tests
// ============================================================================

class BuiltInTests {
public:
    static void RegisterAll(TestSuite& suite,
                           SovereignUnifiedRuntime* runtime,
                           SovereignSecurityLayer* security,
                           SovereignObservability* observability);
    
    // Unit tests
    static TestResult TestRuntimeInitialization(const TestDefinition& def);
    static TestResult TestSecurityLayer(const TestDefinition& def);
    static TestResult TestObservabilityLayer(const TestDefinition& def);
    
    // Integration tests
    static TestResult TestRuntimeSecurityIntegration(const TestDefinition& def);
    static TestResult TestRuntimeObservabilityIntegration(const TestDefinition& def);
    static TestResult TestSecurityObservabilityIntegration(const TestDefinition& def);
    
    // Performance tests
    static TestResult TestInferenceLatency(const TestDefinition& def);
    static TestResult TestInferenceThroughput(const TestDefinition& def);
    static TestResult TestAgentCreationPerformance(const TestDefinition& def);
    static TestResult TestSwarmCoordinationPerformance(const TestDefinition& def);
    
    // Security tests
    static TestResult TestAuthentication(const TestDefinition& def);
    static TestResult TestAuthorization(const TestDefinition& def);
    static TestResult TestAuditLogging(const TestDefinition& def);
    static TestResult TestAPIKeyManagement(const TestDefinition& def);
    
    // Stress tests
    static TestResult TestConcurrentInference(const TestDefinition& def);
    static TestResult TestMemoryPressure(const TestDefinition& def);
    static TestResult TestHighLoadAgents(const TestDefinition& def);
    
    // Recovery tests
    static TestResult TestFailureDetection(const TestDefinition& def);
    static TestResult TestCheckpointRecovery(const TestDefinition& def);
    static TestResult TestGracefulDegradation(const TestDefinition& def);
    
    // Compatibility tests
    static TestResult TestOllamaCompatibility(const TestDefinition& def);
    static TestResult TestAPICompatibility(const TestDefinition& def);
    
    // End-to-end tests
    static TestResult TestFullInferencePipeline(const TestDefinition& def);
    static TestResult TestAgentWorkflow(const TestDefinition& def);
    static TestResult TestSwarmWorkflow(const TestDefinition& def);
    static TestResult TestAutonomousOperation(const TestDefinition& def);
};

// ============================================================================
// Qualification Runner
// ============================================================================

class QualificationRunner {
public:
    QualificationRunner();
    ~QualificationRunner();
    
    // Configuration
    void SetCriteria(const QualificationCriteria& criteria);
    void SetRuntime(SovereignUnifiedRuntime* runtime);
    void SetSecurity(SovereignSecurityLayer* security);
    void SetObservability(SovereignObservability* observability);
    
    // Registration
    void RegisterBuiltInTests();
    void RegisterCustomTest(const TestDefinition& def, 
                           TestSuite::TestFunction func);
    
    // Execution modes
    QualificationReport RunFullQualification();
    QualificationReport RunQuickQualification();
    QualificationReport RunCategory(TestCategory category);
    QualificationReport RunSeverity(Severity severity);
    QualificationReport RunTests(const std::vector<std::string>& test_ids);
    
    // Reporting
    std::string GenerateReport(const QualificationReport& report);
    void ExportReport(const QualificationReport& report, const std::string& path);
    void PrintReport(const QualificationReport& report);
    
    // Evaluation
    bool EvaluateQualification(const QualificationReport& report);
    std::vector<std::string> GetBlockers(const QualificationReport& report);
    std::vector<std::string> GetWarnings(const QualificationReport& report);
    
private:
    std::unique_ptr<TestSuite> test_suite_;
    QualificationCriteria criteria_;
    
    SovereignUnifiedRuntime* runtime_;
    SovereignSecurityLayer* security_;
    SovereignObservability* observability_;
    
    QualificationReport EvaluateResults(const std::vector<TestResult>& results);
    std::string FormatReport(const QualificationReport& report);
};

// ============================================================================
// CLI Interface
// ============================================================================

class QualificationCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    struct QualificationConfig {
        bool full_qualification;
        bool quick_qualification;
        std::vector<std::string> categories;
        std::vector<std::string> severities;
        std::vector<std::string> test_ids;
        std::string output_path;
        bool verbose;
        uint32_t concurrency;
        
        QualificationConfig()
            : full_qualification(false)
            , quick_qualification(false)
            , verbose(false)
            , concurrency(4)
        {}
    };
    
    static void PrintUsage();
    static void PrintHelp();
    static QualificationConfig ParseArgs(int argc, char* argv[]);
    static TestCategory StringToCategory(const std::string& str);
    static Severity StringToSeverity(const std::string& str);
};

// ============================================================================
// Main Qualification Command
// ============================================================================

class SovereignQualification {
public:
    static SovereignQualification& GetInstance();
    
    // Initialization
    void Initialize(SovereignUnifiedRuntime* runtime = nullptr,
                   SovereignSecurityLayer* security = nullptr,
                   SovereignObservability* observability = nullptr);
    void Shutdown();
    bool IsInitialized() const;
    
    // Qualification
    QualificationReport RunFull();
    QualificationReport RunQuick();
    QualificationReport RunCategory(TestCategory category);
    QualificationReport RunSeverity(Severity severity);
    
    // Status
    bool IsQualified() const;
    std::string GetQualificationStatus() const;
    
    // Last report
    std::optional<QualificationReport> GetLastReport() const;
    
private:
    SovereignQualification();
    ~SovereignQualification();
    
    SovereignQualification(const SovereignQualification&) = delete;
    SovereignQualification& operator=(const SovereignQualification&) = delete;
    
    std::unique_ptr<QualificationRunner> runner_;
    std::optional<QualificationReport> last_report_;
    mutable std::mutex report_mutex_;
    
    bool initialized_;
    mutable std::mutex init_mutex_;
};

} // namespace Sovereign

#endif // SOVEREIGN_QUALIFICATION_HPP
