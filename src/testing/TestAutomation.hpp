/**
 * TestAutomation.hpp
 *
 * Phase I Batch 4/5: Test Automation & CI/CD Integration
 *
 * Automated test execution, test scheduling, CI/CD pipeline integration,
 * and test result reporting.
 */

#pragma once

#include "UnitTestFramework.hpp"
#include "IntegrationTestFramework.hpp"
#include "E2ETestFramework.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace Testing {

// ============================================================================
// Forward Declarations
// ============================================================================

class TestScheduler;
class TestPipeline;
class TestReporter;
class TestArtifactManager;

// ============================================================================
// Test Stage
// ============================================================================

/**
 * Stage in a test pipeline.
 */
enum class TestStage {
    PRE_COMMIT,      // Pre-commit checks
    UNIT,            // Unit tests
    INTEGRATION,     // Integration tests
    E2E,             // End-to-end tests
    PERFORMANCE,     // Performance tests
    SECURITY,        // Security tests
    ACCESSIBILITY,   // Accessibility tests
    VISUAL,          // Visual regression tests
    LOAD,            // Load tests
    STRESS,          // Stress tests
    PRODUCTION       // Production smoke tests
};

std::string TestStageToString(TestStage stage);

// ============================================================================
// Test Job
// ============================================================================

/**
 * Individual test job.
 */
struct TestJob {
    std::string id;
    std::string name;
    std::string description;
    TestStage stage;
    
    // Execution
    std::string command;
    std::vector<std::string> arguments;
    std::map<std::string, std::string> environment;
    std::string workingDirectory;
    uint64_t timeoutMs;
    
    // Dependencies
    std::vector<std::string> dependsOn;  // Job IDs that must complete first
    std::vector<std::string> artifacts;   // Artifacts to collect
    
    // Conditions
    bool runOnFailure;   // Run even if previous jobs failed
    bool allowFailure;   // Don't fail pipeline if this job fails
    std::string condition; // Conditional expression
    
    // Retry
    uint32_t maxRetries;
    uint64_t retryDelayMs;
    
    // State
    enum class Status {
        PENDING,
        QUEUED,
        RUNNING,
        SUCCEEDED,
        FAILED,
        SKIPPED,
        CANCELLED,
        TIMED_OUT
    };
    Status status;
    uint64_t startTime;
    uint64_t endTime;
    std::string output;
    std::string errorMessage;
    int exitCode;
    
    TestJob() : timeoutMs(300000), runOnFailure(false), allowFailure(false),
                maxRetries(0), retryDelayMs(0), status(Status::PENDING),
                startTime(0), endTime(0), exitCode(-1) {}
};

// ============================================================================
// Test Pipeline
// ============================================================================

/**
 * CI/CD test pipeline.
 */
class TestPipeline {
public:
    struct Config {
        std::string name;
        std::string description;
        std::string triggerBranch;
        std::vector<std::string> triggerBranches;
        std::vector<std::string> triggerPaths;
        bool triggerOnPullRequest;
        bool triggerOnSchedule;
        std::string schedule;  // Cron expression
        
        // Environment
        std::string runner;
        std::vector<std::string> runners;
        std::map<std::string, std::string> environment;
        std::string container;
        
        // Options
        bool failFast;
        uint32_t parallelJobs;
        bool allowManualTrigger;
        bool requireApproval;
    };
    
    explicit TestPipeline(const Config& config);
    
    // Jobs
    void AddJob(const TestJob& job);
    void AddJobs(const std::vector<TestJob>& jobs);
    void RemoveJob(const std::string& jobId);
    
    // Dependencies
    void AddDependency(const std::string& job, const std::string& dependsOn);
    
    // Execution
    struct ExecutionResult {
        bool success;
        std::string pipelineId;
        uint64_t startTime;
        uint64_t endTime;
        uint64_t durationMs;
        
        std::vector<TestJob> jobs;
        uint32_t succeeded;
        uint32_t failed;
        uint32_t skipped;
        uint32_t cancelled;
        
        std::map<std::string, std::string> artifacts;
        std::string reportUrl;
    };
    
    ExecutionResult Execute();
    ExecutionResult Execute(const std::vector<std::string>& jobFilter);
    
    // Status
    std::string GetStatusJson() const;
    void Cancel();
    void RetryFailed();
    
    // Export
    std::string ExportToYaml() const;
    std::string ExportToJson() const;
    
private:
    Config config_;
    std::vector<TestJob> jobs_;
    std::map<std::string, std::vector<std::string>> dependencies_;
    
    std::atomic<bool> cancelled_{false};
    std::vector<std::thread> runningJobs_;
    mutable std::mutex jobsMutex_;
    
    std::vector<TestJob> GetExecutionOrder() const;
    bool CanExecute(const TestJob& job, const std::set<std::string>& completed) const;
    void ExecuteJob(TestJob& job);
};

// ============================================================================
// Test Scheduler
// ============================================================================

/**
 * Scheduled test execution.
 */
class TestScheduler {
public:
    struct ScheduledTest {
        std::string id;
        std::string name;
        std::string description;
        std::string cronExpression;
        std::string timezone;
        
        // What to run
        std::string pipelineId;
        std::vector<std::string> testSuites;
        std::vector<TestStage> stages;
        
        // Notifications
        std::vector<std::string> notifyOnSuccess;
        std::vector<std::string> notifyOnFailure;
        
        // Options
        bool enabled;
        uint32_t maxConcurrentRuns;
        bool skipIfRunning;
        
        // State
        uint64_t lastRunTime;
        uint64_t nextRunTime;
        uint32_t runCount;
        uint32_t successCount;
        uint32_t failureCount;
    };
    
    TestScheduler();
    ~TestScheduler();
    
    // Schedule management
    void AddSchedule(const ScheduledTest& schedule);
    void RemoveSchedule(const std::string& scheduleId);
    void EnableSchedule(const std::string& scheduleId, bool enabled);
    void UpdateSchedule(const std::string& scheduleId, const ScheduledTest& schedule);
    
    // Query
    std::vector<ScheduledTest> GetSchedules() const;
    std::vector<ScheduledTest> GetDueSchedules() const;
    
    // Execution
    void Start();
    void Stop();
    bool IsRunning() const;
    
    void TriggerNow(const std::string& scheduleId);
    void TriggerPipeline(const std::string& pipelineId);
    
    // History
    struct RunHistory {
        std::string scheduleId;
        uint64_t startTime;
        uint64_t endTime;
        bool success;
        std::string reportUrl;
    };
    std::vector<RunHistory> GetRunHistory(const std::string& scheduleId) const;
    
private:
    std::vector<ScheduledTest> schedules_;
    mutable std::mutex schedulesMutex_;
    
    std::atomic<bool> running_{false};
    std::thread schedulerThread_;
    
    std::vector<RunHistory> history_;
    mutable std::mutex historyMutex_;
    
    void SchedulerLoop();
    uint64_t CalculateNextRun(const ScheduledTest& schedule) const;
    bool IsDue(const ScheduledTest& schedule) const;
    void ExecuteSchedule(const ScheduledTest& schedule);
};

// ============================================================================
// Test Reporter
// ============================================================================

/**
 * Test result reporting and notifications.
 */
class TestReporter {
public:
    enum class ReportFormat {
        CONSOLE,
        JSON,
        XML_JUNIT,
        HTML,
        MARKDOWN,
        PDF,
        SLACK,
        EMAIL,
        TEAMS,
        WEBHOOK
    };
    
    struct ReportConfig {
        ReportFormat format;
        std::string outputPath;
        bool includePassed = true;
        bool includeFailed = true;
        bool includeSkipped = true;
        bool includeDetails = true;
        bool includeLogs = false;
        bool includeScreenshots = false;
        bool includeCoverage = true;
        bool includeMetrics = true;
        std::string templatePath;
    };
    
    explicit TestReporter(const ReportConfig& config);
    
    // Report generation
    std::string GenerateReport(const TestRunner::Summary& summary,
                               const std::vector<TestExecutionResult>& results);
    std::string GenerateReport(const IntegrationTestRunner::Summary& summary);
    std::string GenerateReport(const E2ETestSuite::Summary& summary);
    std::string GenerateReport(const TestPipeline::ExecutionResult& result);
    
    // Notifications
    void SendSlackNotification(const std::string& webhookUrl,
                               const TestRunner::Summary& summary);
    void SendEmailNotification(const std::string& smtpServer,
                               const std::vector& recipients,
                               const TestRunner::Summary& summary);
    void SendTeamsNotification(const std::string& webhookUrl,
                               const TestRunner::Summary& summary);
    void SendWebhookNotification(const std::string& url,
                                   const std::string& payload);
    
    // Trend analysis
    std::string GenerateTrendReport(const std::vector<TestRunner::Summary>& history);
    std::string GenerateComparisonReport(const TestRunner::Summary& current,
                                          const TestRunner::Summary& baseline);
    
private:
    ReportConfig config_;
    
    std::string FormatConsole(const TestRunner::Summary& summary);
    std::string FormatJson(const TestRunner::Summary& summary);
    std::string FormatXml(const TestRunner::Summary& summary);
    std::string FormatHtml(const TestRunner::Summary& summary);
    std::string FormatMarkdown(const TestRunner::Summary& summary);
};

// ============================================================================
// Test Artifact Manager
// ============================================================================

/**
 * Manages test artifacts (screenshots, logs, reports).
 */
class TestArtifactManager {
public:
    struct Artifact {
        std::string id;
        std::string name;
        std::string type;
        std::string path;
        uint64_t size;
        std::string hash;
        uint64_t createdAt;
        std::map<std::string, std::string> metadata;
        std::string testName;
        std::string testSuite;
        std::string pipelineId;
        std::string jobId;
    };
    
    struct Config {
        std::string storagePath = "./test-artifacts";
        uint64_t maxStorageSize = 10ULL * 1024 * 1024 * 1024;  // 10 GB
        uint32_t retentionDays = 30;
        bool compress = true;
        bool deduplicate = true;
    };
    
    explicit TestArtifactManager(const Config& config);
    
    // Storage
    std::string StoreArtifact(const std::string& sourcePath,
                              const std::map<std::string, std::string>& metadata);
    std::string StoreArtifact(const std::string& name,
                              const std::vector<uint8_t>& data,
                              const std::map<std::string, std::string>& metadata);
    
    // Retrieval
    bool RetrieveArtifact(const std::string& artifactId, const std::string& destinationPath);
    std::vector<uint8_t> RetrieveArtifact(const std::string& artifactId);
    std::optional<Artifact> GetArtifactInfo(const std::string& artifactId);
    
    // Query
    std::vector<Artifact> GetArtifacts(const std::string& testName) const;
    std::vector<Artifact> GetArtifacts(const std::string& testSuite,
                                          const std::chrono::system_clock::time_point& since) const;
    std::vector<Artifact> GetArtifactsByType(const std::string& type) const;
    
    // Management
    void DeleteArtifact(const std::string& artifactId);
    void DeleteOldArtifacts(uint32_t days);
    void CleanUpStorage();
    
    // Compression
    std::vector<uint8_t> Compress(const std::vector<uint8_t>& data);
    std::vector<uint8_t> Decompress(const std::vector<uint8_t>& data);
    
    // Stats
    uint64_t GetStorageUsed() const;
    uint64_t GetArtifactCount() const;
    
private:
    Config config_;
    std::map<std::string, Artifact> artifacts_;
    mutable std::mutex artifactsMutex_;
    
    std::string GenerateArtifactId();
    std::string CalculateHash(const std::vector<uint8_t>& data);
};

// ============================================================================
// Quality Gate
// ============================================================================

/**
 * Quality gate for CI/CD.
 */
class QualityGate {
public:
    struct Threshold {
        double minCodeCoverage = 80.0;
        double minTestSuccessRate = 95.0;
        uint32_t maxCriticalIssues = 0;
        uint32_t maxHighIssues = 10;
        uint32_t maxMediumIssues = 50;
        double maxAverageResponseTimeMs = 1000.0;
        double maxP95ResponseTimeMs = 2000.0;
        double maxErrorRate = 0.01;
        double minMaintainabilityIndex = 70.0;
        double maxCyclomaticComplexity = 20.0;
        double maxDuplicationPercent = 5.0;
    };
    
    struct Metrics {
        double codeCoverage;
        double testSuccessRate;
        uint32_t criticalIssues;
        uint32_t highIssues;
        uint32_t mediumIssues;
        double averageResponseTimeMs;
        double p95ResponseTimeMs;
        double errorRate;
        double maintainabilityIndex;
        double cyclomaticComplexity;
        double duplicationPercent;
    };
    
    struct Result {
        bool passed;
        std::vector<std::string> failures;
        std::vector<std::string> warnings;
        Metrics metrics;
        Threshold threshold;
    };
    
    explicit QualityGate(const Threshold& threshold);
    
    // Evaluation
    Result Evaluate(const Metrics& metrics);
    
    // Individual checks
    bool CheckCodeCoverage(double coverage);
    bool CheckTestSuccessRate(double rate);
    bool CheckIssues(uint32_t critical, uint32_t high, uint32_t medium);
    bool CheckPerformance(double avgResponse, double p95Response);
    bool CheckErrorRate(double rate);
    bool CheckMaintainability(double index);
    bool CheckComplexity(double complexity);
    bool CheckDuplication(double duplication);
    
    // Configuration
    void SetThreshold(const Threshold& threshold);
    void SetBlocker(const std::string& metric, bool blocker);
    
    // Report
    std::string GenerateReport(const Result& result);
    
private:
    Threshold threshold_;
    std::map<std::string, bool> blockers_;
};

// ============================================================================
// CI/CD Providers
// ============================================================================

/**
 * GitHub Actions integration.
 */
class GitHubActionsIntegration {
public:
    static bool IsRunningInGitHubActions();
    static std::string GetWorkflow();
    static std::string GetRunId();
    static std::string GetRepository();
    static std::string GetBranch();
    static std::string GetCommit();
    static std::string GetActor();
    
    static void SetOutput(const std::string& name, const std::string& value);
    static void SetSecret(const std::string& name);
    static void AddPath(const std::string& path);
    static void LogCommand(const std::string& command, const std::string& message);
    static void LogError(const std::string& message);
    static void LogWarning(const std::string& message);
    static void LogNotice(const std::string& message);
    static void LogGroup(const std::string& title);
    static void EndGroup();
    
    static std::string GenerateWorkflowYaml(const TestPipeline& pipeline);
};

/**
 * GitLab CI integration.
 */
class GitLabCIIntegration {
public:
    static bool IsRunningInGitLabCI();
    static std::string GetPipelineId();
    static std::string GetJobId();
    static std::string GetProject();
    static std::string GetBranch();
    static std::string GetCommit();
    static std::string GetUser();
    
    static void SetVariable(const std::string& name, const std::string& value);
    static void ReportMetric(const std::string& name, double value);
    static void ReportTestResults(const std::string& junitXmlPath);
    static void ReportCoverage(const std::string& coberturaXmlPath);
    
    static std::string GenerateGitlabCiYaml(const TestPipeline& pipeline);
};

/**
 * Azure DevOps integration.
 */
class AzureDevOpsIntegration {
public:
    static bool IsRunningInAzureDevOps();
    static std::string GetBuildId();
    static std::string GetBuildNumber();
    static std::string GetProject();
    static std::string GetRepository();
    static std::string GetBranch();
    static std::string GetCommit();
    
    static void SetVariable(const std::string& name, const std::string& value);
    static void SetOutput(const std::string& name, const std::string& value);
    static void LogCommand(const std::string& command, const std::string& message);
    static void LogIssue(const std::string& type, const std::string& message);
    static void UploadArtifact(const std::string& name, const std::string& path);
    static void PublishTestResults(const std::string& format, const std::string& path);
    static void PublishCoverage(const std::string& path);
    
    static std::string GenerateAzurePipelinesYaml(const TestPipeline& pipeline);
};

// ============================================================================
// Test Automation System
// ============================================================================

/**
 * Integrated test automation system.
 */
class TestAutomation {
public:
    struct Config {
        std::string name;
        std::string version;
        std::string configPath;
        bool autoDiscover = true;
        bool parallel = true;
        uint32_t maxParallel = 4;
    };
    
    explicit TestAutomation(const Config& config);
    ~TestAutomation();
    
    // Initialize
    bool Initialize();
    void Shutdown();
    
    // Components
    void SetScheduler(std::shared_ptr<TestScheduler> scheduler);
    void SetArtifactManager(std::shared_ptr<TestArtifactManager> manager);
    void SetReporter(std::shared_ptr<TestReporter> reporter);
    void SetQualityGate(std::shared_ptr<QualityGate> gate);
    
    // Pipelines
    void RegisterPipeline(std::shared_ptr<TestPipeline> pipeline);
    void UnregisterPipeline(const std::string& pipelineId);
    
    // Execution
    TestPipeline::ExecutionResult RunPipeline(const std::string& pipelineId);
    TestPipeline::ExecutionResult RunPipeline(const std::string& pipelineId,
                                               const std::vector<std::string>& stages);
    
    // Scheduling
    void SchedulePipeline(const std::string& pipelineId, const std::string& cronExpression);
    void UnschedulePipeline(const std::string& pipelineId);
    
    // Status
    std::string GetStatusJson() const;
    
    // Results
    void PublishResults(const TestPipeline::ExecutionResult& result);
    
private:
    Config config_;
    
    std::shared_ptr<TestScheduler> scheduler_;
    std::shared_ptr<TestArtifactManager> artifactManager_;
    std::shared_ptr<TestReporter> reporter_;
    std::shared_ptr<QualityGate> qualityGate_;
    
    std::map<std::string, std::shared_ptr<TestPipeline>> pipelines_;
    mutable std::mutex pipelinesMutex_;
};

} // namespace Testing
