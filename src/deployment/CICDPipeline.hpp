/**
 * CICDPipeline.hpp
 *
 * Phase K Batch 3/5: CI/CD Pipeline
 *
 * Continuous integration and deployment pipeline management
 * with support for multiple CI/CD platforms.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <functional>

namespace Deployment {

// ============================================================================
// Forward Declarations
// ============================================================================

class Pipeline;
class PipelineStage;
class PipelineJob;
class PipelineRunner;
class ArtifactStore;

// ============================================================================
// Pipeline Types
// ============================================================================

enum class PipelineStatus {
    PENDING,
    QUEUED,
    RUNNING,
    SUCCEEDED,
    FAILED,
    CANCELLED,
    SKIPPED,
    BLOCKED
};

enum class TriggerType {
    MANUAL,
    SCHEDULED,
    WEBHOOK,
    API,
    PUSH,
    PULL_REQUEST,
    TAG,
    MERGE
};

// ============================================================================
// Pipeline Configuration
// ============================================================================

/**
 * Pipeline configuration.
 */
struct PipelineConfig {
    std::string name;
    std::string description;
    std::string version;
    
    // Triggers
    std::vector<TriggerType> triggers;
    std::vector<std::string> branches;
    std::vector<std::string> tags;
    std::vector<std::string> paths;
    std::string cronSchedule;
    
    // Environment
    std::string runner;
    std::vector<std::string> runners;
    std::map<std::string, std::string> environment;
    std::string container;
    std::vector<std::string> services;
    
    // Options
    bool failFast;
    bool allowFailure;
    uint32_t timeoutMinutes;
    uint32_t parallel;
    bool autoCancel;
    bool skipIfNoChanges;
    
    // Notifications
    std::vector<std::string> notifyOnSuccess;
    std::vector<std::string> notifyOnFailure;
    std::vector<std::string> notifyOnFixed;
};

// ============================================================================
// Pipeline Variable
// ============================================================================

/**
 * Pipeline variable.
 */
struct PipelineVariable {
    std::string name;
    std::string value;
    bool secret;
    bool protected_;
    std::string description;
    std::optional<std::string> defaultValue;
    std::vector<std::string> allowedValues;
};

// ============================================================================
// Pipeline Cache
// ============================================================================

/**
 * Pipeline cache configuration.
 */
struct PipelineCache {
    std::string key;
    std::vector<std::string> paths;
    std::optional<std::string> fallbackKey;
    std::optional<uint64_t> maxSize;
    bool uploadOnFailure;
};

// ============================================================================
// Pipeline Artifact
// ============================================================================

/**
 * Pipeline artifact.
 */
struct PipelineArtifact {
    std::string name;
    std::vector<std::string> paths;
    std::optional<std::string> destination;
    std::optional<uint64_t> expireDays;
    std::optional<std::string> when;  // always, on_success, on_failure
};

// ============================================================================
// Pipeline Job
// ============================================================================

/**
 * Pipeline job definition.
 */
class PipelineJob {
public:
    struct Config {
        std::string name;
        std::string description;
        std::vector<std::string> commands;
        std::string script;
        std::vector<std::string> beforeScript;
        std::vector<std::string> afterScript;
        
        // Environment
        std::string image;
        std::vector<std::string> services;
        std::map<std::string, std::string> variables;
        std::vector<std::pair<std::string, std::string>> artifacts;
        std::vector<PipelineCache> caches;
        
        // Conditions
        std::vector<std::string> only;
        std::vector<std::string> except;
        std::vector<std::string> rules;
        std::string when;  // on_success, on_failure, always, manual, delayed
        bool allowFailure;
        uint32_t timeoutMinutes;
        uint32_t retry;
        
        // Dependencies
        std::vector<std::string> needs;
        std::vector<std::string> dependencies;
        std::vector<std::string> artifactsFrom;
        
        // Parallel
        bool parallel;
        uint32_t parallelMatrix;
        std::map<std::string, std::vector<std::string>> matrix;
        
        // Runner
        std::vector<std::string> tags;
        std::map<std::string, std::string> runner;
    };
    
    explicit PipelineJob(const Config& config);
    
    // Execution
    bool Execute();
    bool Execute(const std::map<std::string, std::string>& variables);
    void Cancel();
    void Retry();
    
    // Status
    PipelineStatus GetStatus() const;
    std::string GetOutput() const;
    int GetExitCode() const;
    std::chrono::system_clock::time_point GetStartTime() const;
    std::chrono::system_clock::time_point GetEndTime() const;
    std::chrono::seconds GetDuration() const;
    
    // Artifacts
    std::vector<PipelineArtifact> GetArtifacts() const;
    bool UploadArtifacts();
    bool DownloadArtifacts(const std::string& jobName);
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetName() const { return config_.name; }
    
private:
    Config config_;
    PipelineStatus status_;
    std::string output_;
    int exitCode_;
    std::chrono::system_clock::time_point startTime_;
    std::chrono::system_clock::time_point endTime_;
    mutable std::mutex mutex_;
    
    std::string ExpandVariables(const std::string& command,
                                 const std::map<std::string, std::string>& variables);
};

// ============================================================================
// Pipeline Stage
// ============================================================================

/**
 * Pipeline stage containing multiple jobs.
 */
class PipelineStage {
public:
    struct Config {
        std::string name;
        std::vector<std::string> needs;
        bool parallel;
        bool failFast;
    };
    
    explicit PipelineStage(const Config& config);
    
    // Jobs
    void AddJob(std::shared_ptr<PipelineJob> job);
    void AddJobs(const std::vector<std::shared_ptr<PipelineJob>>& jobs);
    std::vector<std::shared_ptr<PipelineJob>> GetJobs() const;
    std::shared_ptr<PipelineJob> GetJob(const std::string& name) const;
    
    // Execution
    bool Execute();
    void Cancel();
    
    // Status
    PipelineStatus GetStatus() const;
    bool IsComplete() const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetName() const { return config_.name; }
    
private:
    Config config_;
    std::vector<std::shared_ptr<PipelineJob>> jobs_;
    std::atomic<PipelineStatus> status_{PipelineStatus::PENDING};
};

// ============================================================================
// Pipeline
// ============================================================================

/**
 * Complete CI/CD pipeline.
 */
class Pipeline {
public:
    struct Trigger {
        TriggerType type;
        std::string branch;
        std::string commit;
        std::string author;
        std::string message;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> metadata;
    };
    
    struct Run {
        std::string id;
        std::string pipelineId;
        Trigger trigger;
        PipelineStatus status;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point started;
        std::chrono::system_clock::time_point finished;
        std::chrono::seconds duration;
        std::vector<std::shared_ptr<PipelineStage>> stages;
        std::map<std::string, std::string> variables;
        std::string triggeredBy;
        std::string url;
    };
    
    explicit Pipeline(const PipelineConfig& config);
    
    // Stages
    void AddStage(std::shared_ptr<PipelineStage> stage);
    void AddStages(const std::vector<std::shared_ptr<PipelineStage>>& stages);
    std::vector<std::shared_ptr<PipelineStage>> GetStages() const;
    std::shared_ptr<PipelineStage> GetStage(const std::string& name) const;
    
    // Variables
    void AddVariable(const PipelineVariable& variable);
    void SetVariable(const std::string& name, const std::string& value);
    std::optional<PipelineVariable> GetVariable(const std::string& name) const;
    std::map<std::string, std::string> GetVariables() const;
    
    // Execution
    std::string Trigger(const Trigger& trigger);
    bool Cancel(const std::string& runId);
    bool Retry(const std::string& runId);
    bool Skip(const std::string& runId);
    
    // Status
    Run GetRun(const std::string& runId) const;
    std::vector<Run> GetRuns() const;
    std::vector<Run> GetRuns(PipelineStatus status) const;
    PipelineStatus GetStatus(const std::string& runId) const;
    
    // Artifacts
    std::vector<PipelineArtifact> GetArtifacts(const std::string& runId) const;
    bool DownloadArtifact(const std::string& runId, const std::string& artifactName,
                          const std::string& destination);
    
    // Export
    std::string ToGitLabCI() const;
    std::string ToGitHubActions() const;
    std::string ToAzurePipelines() const;
    std::string ToJenkinsfile() const;
    std::string ToCircleCI() const;
    std::string ToTravisCI() const;
    std::string ToDrone() const;
    std::string ToBuildkite() const;
    std::string ToTekton() const;
    std::string ToArgoWorkflows() const;
    
    // Import
    bool FromGitLabCI(const std::string& yaml);
    bool FromGitHubActions(const std::string& yaml);
    bool FromAzurePipelines(const std::string& yaml);
    bool FromJenkinsfile(const std::string& groovy);
    
private:
    PipelineConfig config_;
    std::vector<std::shared_ptr<PipelineStage>> stages_;
    std::vector<PipelineVariable> variables_;
    std::map<std::string, Run> runs_;
    mutable std::mutex mutex_;
    
    std::string GenerateRunId();
    std::vector<std::shared_ptr<PipelineStage>> GetExecutionOrder();
};

// ============================================================================
// Pipeline Runner
// ============================================================================

/**
 * Pipeline execution engine.
 */
class PipelineRunner {
public:
    struct Config {
        std::string name;
        std::string type;  // local, docker, kubernetes, remote
        uint32_t maxParallelJobs;
        uint32_t maxConcurrentPipelines;
        std::map<std::string, std::string> environment;
        std::vector<std::string> tags;
        std::string executor;
        bool failFast;
    };
    
    explicit PipelineRunner(const Config& config);
    
    // Registration
    void RegisterPipeline(std::shared_ptr<Pipeline> pipeline);
    void UnregisterPipeline(const std::string& name);
    
    // Execution
    bool Run(const std::string& pipelineName, const Pipeline::Trigger& trigger);
    bool RunStage(const std::string& pipelineName, const std::string& stageName);
    bool RunJob(const std::string& pipelineName, const std::string& jobName);
    
    // Control
    void Cancel(const std::string& runId);
    void CancelAll();
    void Pause();
    void Resume();
    
    // Status
    struct Status {
        bool running;
        uint32_t activePipelines;
        uint32_t queuedPipelines;
        uint32_t activeJobs;
        uint32_t queuedJobs;
        std::chrono::system_clock::time_point uptime;
    };
    Status GetStatus() const;
    
    // Logs
    std::string GetLogs(const std::string& runId) const;
    std::string GetJobLogs(const std::string& runId, const std::string& jobName) const;
    void StreamLogs(const std::string& runId, std::function<void(const std::string&)> callback);
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<Pipeline>> pipelines_;
    std::map<std::string, std::thread> runningPipelines_;
    std::atomic<bool> paused_{false};
    mutable std::mutex mutex_;
    
    void ExecutePipeline(const std::string& runId, std::shared_ptr<Pipeline> pipeline,
                         const Pipeline::Trigger& trigger);
};

// ============================================================================
// Artifact Store
// ============================================================================

/**
 * Pipeline artifact storage.
 */
class ArtifactStore {
public:
    struct Config {
        std::string type;  // local, s3, gcs, azure, minio
        std::string path;
        std::string bucket;
        std::string region;
        std::string endpoint;
        std::string accessKey;
        std::string secretKey;
        bool ssl;
        uint64_t maxSize;
        uint32_t retentionDays;
    };
    
    struct ArtifactMetadata {
        std::string id;
        std::string name;
        std::string runId;
        std::string pipelineName;
        std::string jobName;
        uint64_t size;
        std::string checksum;
        std::chrono::system_clock::time_point created;
        std::chrono::system_clock::time_point expires;
        std::map<std::string, std::string> metadata;
    };
    
    explicit ArtifactStore(const Config& config);
    
    // Storage
    std::string Upload(const std::string& runId, const std::string& jobName,
                       const PipelineArtifact& artifact);
    bool Download(const std::string& artifactId, const std::string& destination);
    bool Delete(const std::string& artifactId);
    
    // Query
    std::vector<ArtifactMetadata> ListArtifacts(const std::string& runId) const;
    std::vector<ArtifactMetadata> ListArtifacts(const std::string& pipelineName,
                                                   const std::string& jobName) const;
    std::optional<ArtifactMetadata> GetArtifact(const std::string& artifactId) const;
    
    // Cleanup
    bool CleanupExpired();
    bool CleanupRun(const std::string& runId);
    
    // Stats
    struct Stats {
        uint64_t totalSize;
        uint32_t artifactCount;
        uint32_t runCount;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    
    std::string CalculateChecksum(const std::string& filePath);
    std::string GenerateArtifactId();
};

// ============================================================================
// GitHub Actions Integration
// ============================================================================

/**
 * GitHub Actions specific integration.
 */
class GitHubActionsIntegration {
public:
    // Environment
    static bool IsRunningInGitHubActions();
    static std::string GetWorkflow();
    static std::string GetRunId();
    static std::string GetRunNumber();
    static std::string GetActor();
    static std::string GetRepository();
    static std::string GetEventName();
    static std::string GetSha();
    static std::string GetRef();
    static std::string GetBranch();
    static std::string GetHeadRef();
    static std::string GetBaseRef();
    
    // Outputs
    static void SetOutput(const std::string& name, const std::string& value);
    static void SetSecret(const std::string& value);
    static void AddPath(const std::string& path);
    static void ExportVariable(const std::string& name, const std::string& value);
    
    // Logging
    static void Debug(const std::string& message);
    static void Info(const std::string& message);
    static void Warning(const std::string& message);
    static void Error(const std::string& message);
    static void Group(const std::string& name);
    static void EndGroup();
    
    // Artifacts
    static bool UploadArtifact(const std::string& name,
                                const std::vector<std::string>& paths);
    static bool DownloadArtifact(const std::string& name,
                                  const std::string& destination);
    
    // Cache
    static bool Cache(const std::vector<std::string>& paths, const std::string& key);
    static bool RestoreCache(const std::string& key);
    
    // Workflow commands
    static std::string GenerateWorkflow(const Pipeline& pipeline);
    static std::string GenerateCompositeAction(const PipelineJob& job);
    static std::string GenerateReusableWorkflow(const Pipeline& pipeline);
};

// ============================================================================
// GitLab CI Integration
// ============================================================================

/**
 * GitLab CI specific integration.
 */
class GitLabCIIntegration {
public:
    // Environment
    static bool IsRunningInGitLabCI();
    static std::string GetPipelineId();
    static std::string GetJobId();
    static std::string GetJobName();
    static std::string GetJobStage();
    static std::string GetProjectId();
    static std::string GetProjectUrl();
    static std::string GetCommitSha();
    static std::string GetCommitBranch();
    static std::string GetCommitTag();
    static std::string GetCommitMessage();
    static std::string GetUserLogin();
    
    // Artifacts
    static bool UploadArtifact(const std::string& name,
                                const std::vector<std::string>& paths,
                                const std::optional<std::string>& expire = std::nullopt);
    static bool DownloadArtifact(const std::string& jobName,
                                  const std::string& destination);
    
    // Cache
    static bool Cache(const std::vector<std::string>& paths);
    
    // Reports
    static bool UploadTestReport(const std::string& junitXmlPath);
    static bool UploadCoverageReport(const std::string& coberturaXmlPath);
    static bool UploadCodeQualityReport(const std::string& jsonPath);
    static bool UploadSastReport(const std::string& jsonPath);
    static bool UploadDependencyScanningReport(const std::string& jsonPath);
    
    // Metrics
    static void ReportMetric(const std::string& name, double value);
    
    // Workflow
    static std::string GenerateGitLabCI(const Pipeline& pipeline);
    static std::string GenerateInclude(const std::vector<Pipeline>& pipelines);
};

// ============================================================================
// Azure Pipelines Integration
// ============================================================================

/**
 * Azure Pipelines specific integration.
 */
class AzurePipelinesIntegration {
public:
    // Environment
    static bool IsRunningInAzurePipelines();
    static std::string GetBuildId();
    static std::string GetBuildNumber();
    static std::string GetBuildUri();
    static std::string GetSourceBranch();
    static std::string GetSourceVersion();
    static std::string GetRepositoryName();
    static std::string GetTeamProject();
    static std::string GetAgentName();
    static std::string GetAgentJobName();
    
    // Variables
    static void SetVariable(const std::string& name, const std::string& value);
    static void SetVariable(const std::string& name, const std::string& value,
                            bool isSecret, bool isOutput);
    static std::string GetVariable(const std::string& name);
    
    // Logging
    static void LogIssue(const std::string& type, const std::string& message);
    static void LogSection(const std::string& name);
    static void LogCommand(const std::string& command);
    static void AddAttachment(const std::string& type, const std::string& name,
                               const std::string& path);
    
    // Artifacts
    static bool PublishArtifact(const std::string& artifactName,
                                 const std::string& path,
                                 const std::string& targetPath = "");
    static bool DownloadArtifact(const std::string& artifactName,
                                  const std::string& path);
    
    // Test results
    static bool PublishTestResults(const std::string& resultFormat,
                                    const std::vector<std::string>& resultFiles);
    static bool PublishCodeCoverage(const std::string& coverageTool,
                                     const std::string& summaryFile);
    
    // Workflow
    static std::string GenerateAzurePipelines(const Pipeline& pipeline);
    static std::string GenerateTemplate(const PipelineStage& stage);
};

// ============================================================================
// Pipeline Analytics
// ============================================================================

/**
 * Pipeline analytics and insights.
 */
class PipelineAnalytics {
public:
    struct Metrics {
        uint32_t totalRuns;
        uint32_t successfulRuns;
        uint32_t failedRuns;
        double successRate;
        std::chrono::seconds averageDuration;
        std::chrono::seconds medianDuration;
        std::chrono::seconds p95Duration;
        std::chrono::seconds p99Duration;
    };
    
    struct StageMetrics {
        std::string stageName;
        uint32_t runs;
        double successRate;
        std::chrono::seconds averageDuration;
        std::chrono::seconds totalDuration;
    };
    
    struct JobMetrics {
        std::string jobName;
        uint32_t runs;
        double successRate;
        std::chrono::seconds averageDuration;
        uint32_t retries;
        double retryRate;
    };
    
    struct Trend {
        std::chrono::system_clock::time_point timestamp;
        double successRate;
        std::chrono::seconds duration;
        uint32_t runCount;
    };
    
    // Analysis
    Metrics AnalyzePipeline(const std::string& pipelineName,
                            std::chrono::system_clock::time_point since);
    std::vector<StageMetrics> AnalyzeStages(const std::string& pipelineName,
                                             std::chrono::system_clock::time_point since);
    std::vector<JobMetrics> AnalyzeJobs(const std::string& pipelineName,
                                        std::chrono::system_clock::time_point since);
    
    // Trends
    std::vector<Trend> GetSuccessTrend(const std::string& pipelineName,
                                         std::chrono::hours interval);
    std::vector<Trend> GetDurationTrend(const std::string& pipelineName,
                                          std::chrono::hours interval);
    
    // Insights
    std::vector<std::string> GetSlowJobs(const std::string& pipelineName);
    std::vector<std::string> GetFlakyJobs(const std::string& pipelineName);
    std::vector<std::string> GetBottlenecks(const std::string& pipelineName);
    std::vector<std::string> GetOptimizationSuggestions(const std::string& pipelineName);
    
    // Comparison
    struct Comparison {
        std::string pipelineName;
        Metrics metrics;
        double improvement;
    };
    std::vector<Comparison> ComparePipelines();
    
    // Export
    std::string GenerateReport(const std::string& pipelineName);
    bool ExportToDashboard(const std::string& pipelineName, const std::string& url);
    
private:
    std::map<std::string, std::vector<Pipeline::Run>> history_;
    
    double CalculateFlakiness(const std::string& jobName);
    std::chrono::seconds CalculateDuration(const Pipeline::Run& run);
};

} // namespace Deployment
