/**
 * MLOpsPipeline.hpp
 *
 * Phase L Batch 5/5: MLOps Pipeline & Experiment Tracking
 *
 * Complete MLOps infrastructure for experiment tracking, pipeline orchestration,
 * feature store, and automated model retraining.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <queue>
#include <chrono>
#include <future>

namespace AI_ML {

// ============================================================================
// Forward Declarations
// ============================================================================

class Experiment;
class Run;
class Artifact;
class MLOpsPipeline;
class FeatureStore;
class DataVersioning;

// ============================================================================
// Experiment Status
// ============================================================================

enum class ExperimentStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    CANCELLED
};

// ============================================================================
// Run Status
// ============================================================================

enum class RunStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED,
    KILLED
};

// ============================================================================
// Metric
// ============================================================================

/**
 * Metric value with timestamp.
 */
struct Metric {
    std::string key;
    double value;
    std::chrono::system_clock::time_point timestamp;
    std::optional<int32_t> step;
    std::map<std::string, std::string> metadata;
    
    Metric(const std::string& k, double v) 
        : key(k), value(v), timestamp(std::chrono::system_clock::now()) {}
};

// ============================================================================
// Parameter
// ============================================================================

/**
 * Parameter value.
 */
struct Parameter {
    enum class Type {
        STRING,
        INT,
        FLOAT,
        BOOL
    };
    
    std::string key;
    Type type;
    std::string stringValue;
    int64_t intValue;
    double floatValue;
    bool boolValue;
    
    static Parameter String(const std::string& key, const std::string& value);
    static Parameter Int(const std::string& key, int64_t value);
    static Parameter Float(const std::string& key, double value);
    static Parameter Bool(const std::string& key, bool value);
    
    std::string ToString() const;
};

// ============================================================================
// Artifact
// ============================================================================

/**
 * Artifact (file or directory) tracked in an experiment.
 */
class Artifact {
public:
    struct Config {
        std::string name;
        std::string path;
        std::string type;  // model, dataset, plot, log, etc.
        std::map<std::string, std::string> metadata;
        std::optional<uint64_t> sizeBytes;
        std::optional<std::string> checksum;
    };
    
    explicit Artifact(const Config& config);
    
    // Upload/Download
    bool Upload(const std::string& destination);
    bool Download(const std::string& destination);
    
    // Validation
    bool ValidateChecksum();
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetUri() const;
    
private:
    Config config_;
};

// ============================================================================
// Run
// ============================================================================

/**
 * Single run of an experiment.
 */
class Run {
public:
    struct Config {
        std::string runId;
        std::string experimentId;
        std::string runName;
        RunStatus status;
        std::chrono::system_clock::time_point startTime;
        std::optional<std::chrono::system_clock::time_point> endTime;
        std::map<std::string, Parameter> parameters;
        std::map<std::string, std::vector<Metric>> metrics;
        std::vector<std::shared_ptr<Artifact>> artifacts;
        std::map<std::string, std::string> tags;
        std::optional<std::string> parentRunId;
    };
    
    explicit Run(const Config& config);
    
    // Lifecycle
    void Start();
    void Complete();
    void Fail(const std::string& error);
    void Kill();
    
    // Parameters
    void LogParameter(const Parameter& param);
    void LogParameters(const std::map<std::string, Parameter>& params);
    std::optional<Parameter> GetParameter(const std::string& key) const;
    
    // Metrics
    void LogMetric(const std::string& key, double value, int32_t step = -1);
    void LogMetrics(const std::map<std::string, double>& metrics, int32_t step = -1);
    void LogMetricsBatch(const std::vector<Metric>& metrics);
    std::vector<Metric> GetMetrics(const std::string& key) const;
    std::optional<Metric> GetLatestMetric(const std::string& key) const;
    
    // Artifacts
    void LogArtifact(const std::string& localPath, 
                     const std::string& artifactPath = "",
                     const std::map<std::string, std::string>& metadata = {});
    void LogArtifacts(const std::vector<std::string>& paths);
    std::vector<std::shared_ptr<Artifact>> GetArtifacts() const;
    std::optional<std::shared_ptr<Artifact>> GetArtifact(const std::string& name) const;
    
    // Tags
    void SetTag(const std::string& key, const std::string& value);
    std::optional<std::string> GetTag(const std::string& key) const;
    
    // Model
    void LogModel(const std::string& modelPath,
                  const std::map<std::string, std::string>& metadata = {});
    
    // System metrics
    void LogSystemMetrics();
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetRunId() const { return config_.runId; }
    RunStatus GetStatus() const { return config_.status; }
    std::chrono::seconds GetDuration() const;
    
    // Comparison
    struct Comparison {
        std::string metric;
        double thisValue;
        double otherValue;
        double difference;
        bool isBetter;
    };
    std::vector<Comparison> CompareTo(const Run& other) const;
    
private:
    Config config_;
    mutable std::mutex mutex_;
    
    void PersistMetrics();
    void PersistParameters();
};

// ============================================================================
// Experiment
// ============================================================================

/**
 * Experiment with multiple runs.
 */
class Experiment {
public:
    struct Config {
        std::string experimentId;
        std::string name;
        std::string description;
        std::string artifactLocation;
        std::chrono::system_clock::time_point creationTime;
        std::map<std::string, std::string> tags;
    };
    
    explicit Experiment(const Config& config);
    
    // Run management
    std::shared_ptr<Run> StartRun(const std::string& runName = "");
    std::shared_ptr<Run> GetRun(const std::string& runId) const;
    std::vector<std::shared_ptr<Run>> GetRuns() const;
    std::vector<std::shared_ptr<Run>> GetRunsWithStatus(RunStatus status) const;
    
    // Search runs
    std::vector<std::shared_ptr<Run>> SearchRuns(
        const std::map<std::string, std::string>& filter) const;
    std::vector<std::shared_ptr<Run>> SearchRunsByMetric(
        const std::string& metric, double minValue, double maxValue) const;
    
    // Best run
    std::optional<std::shared_ptr<Run>> GetBestRun(const std::string& metric,
                                                        bool maximize = true) const;
    
    // Comparison
    struct ExperimentComparison {
        std::string metric;
        double mean1;
        double mean2;
        double std1;
        double std2;
        double pValue;
        bool significant;
    };
    std::vector<ExperimentComparison> CompareTo(const Experiment& other) const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetExperimentId() const { return config_.experimentId; }
    
private:
    Config config_;
    std::vector<std::shared_ptr<Run>> runs_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Experiment Tracker
// ============================================================================

/**
 * Central experiment tracking system.
 */
class ExperimentTracker {
public:
    struct Config {
        std::string trackingUri;
        std::string defaultArtifactRoot;
        bool autoLogSystemMetrics;
        bool autoLogParameters;
    };
    
    explicit ExperimentTracker(const Config& config);
    
    // Experiment management
    std::shared_ptr<Experiment> CreateExperiment(const std::string& name,
                                                   const std::string& description = "");
    std::optional<std::shared_ptr<Experiment>> GetExperiment(const std::string& experimentId);
    std::vector<std::shared_ptr<Experiment>> ListExperiments() const;
    bool DeleteExperiment(const std::string& experimentId);
    
    // Active experiment
    void SetExperiment(const std::string& experimentId);
    std::optional<std::shared_ptr<Experiment>> GetActiveExperiment();
    
    // Run management
    std::shared_ptr<Run> StartRun(const std::string& runName = "");
    void EndRun();
    std::optional<std::shared_ptr<Run>> GetActiveRun();
    
    // Search
    std::vector<std::shared_ptr<Run>> SearchRuns(
        const std::map<std::string, std::string>& filter) const;
    
    // Import/Export
    bool ExportToMLflow(const std::string& mlflowUri);
    bool ExportToWandB(const std::string& wandbProject);
    bool ImportFromMLflow(const std::string& mlflowUri, 
                          const std::string& experimentId);
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<Experiment>> experiments_;
    std::optional<std::string> activeExperimentId_;
    std::optional<std::shared_ptr<Run>> activeRun_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Pipeline Stage
// ============================================================================

/**
 * Single stage in an ML pipeline.
 */
class PipelineStage {
public:
    using StageFunction = std::function<bool(const std::map<std::string, std::string>&,
                                               std::map<std::string, std::string>&)>>;
    
    struct Config {
        std::string name;
        StageFunction function;
        std::vector<std::string> dependencies;
        std::vector<std::string> outputs;
        std::map<std::string, std::string> parameters;
        std::chrono::seconds timeout;
        uint32_t maxRetries;
        bool cacheResults;
    };
    
    explicit PipelineStage(const Config& config);
    
    // Execution
    bool Execute(const std::map<std::string, std::string>& inputs,
                 std::map<std::string, std::string>& outputs);
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    const std::string& GetName() const { return config_.name; }
    const std::vector<std::string>& GetDependencies() const { return config_.dependencies; }
    
private:
    Config config_;
    uint32_t retryCount_;
};

// ============================================================================
// Pipeline
// ============================================================================

/**
 * ML pipeline with multiple stages.
 */
class Pipeline {
public:
    struct Config {
        std::string name;
        std::string description;
        std::vector<std::shared_ptr<PipelineStage>> stages;
        bool enableParallelExecution;
        uint32_t maxParallelStages;
        std::string experimentId;
    };
    
    explicit Pipeline(const Config& config);
    
    // Stage management
    void AddStage(std::shared_ptr<PipelineStage> stage);
    void RemoveStage(const std::string& name);
    std::shared_ptr<PipelineStage> GetStage(const std::string& name) const;
    std::vector<std::shared_ptr<PipelineStage>> GetStages() const;
    
    // Execution
    struct ExecutionResult {
        bool success;
        std::map<std::string, std::string> outputs;
        std::chrono::seconds duration;
        std::map<std::string, bool> stageResults;
        std::optional<std::string> errorMessage;
    };
    
    ExecutionResult Execute(const std::map<std::string, std::string>& inputs);
    std::future<ExecutionResult> ExecuteAsync(const std::map<std::string, std::string>& inputs);
    
    // Scheduling
    void Schedule(const std::map<std::string, std::string>& inputs,
                    std::chrono::system_clock::time_point runTime);
    void ScheduleRecurring(const std::map<std::string, std::string>& inputs,
                            std::chrono::seconds interval);
    void CancelScheduled();
    
    // Validation
    bool Validate() const;
    std::vector<std::string> GetValidationErrors() const;
    
    // Visualization
    std::string ToDot() const;
    std::string ToMermaid() const;
    
private:
    Config config_;
    std::map<std::string, std::shared_ptr<PipelineStage>> stages_;
    mutable std::mutex mutex_;
    
    std::vector<std::shared_ptr<PipelineStage>> TopologicalSort() const;
    ExecutionResult ExecuteSequential(const std::map<std::string, std::string>& inputs);
    ExecutionResult ExecuteParallel(const std::map<std::string, std::string>& inputs);
};

// ============================================================================
// Feature Store
// ============================================================================

/**
 * Feature store for ML feature management.
 */
class FeatureStore {
public:
    struct Feature {
        std::string name;
        std::string type;
        std::string description;
        std::vector<std::string> entities;
        std::chrono::seconds ttl;
        std::map<std::string, std::string> metadata;
        std::optional<std::string> transformation;
    };
    
    struct FeatureVector {
        std::string entityId;
        std::map<std::string, std::vector<float>> features;
        std::chrono::system_clock::time_point timestamp;
    };
    
    struct Config {
        std::string backend;  // redis, postgres, bigquery, etc.
        std::string connectionString;
        bool enableOnlineStore;
        bool enableOfflineStore;
        std::chrono::seconds featureTtl;
    };
    
    explicit FeatureStore(const Config& config);
    
    // Feature definition
    void RegisterFeature(const Feature& feature);
    void UpdateFeature(const std::string& name, const Feature& feature);
    void DeleteFeature(const std::string& name);
    std::optional<Feature> GetFeature(const std::string& name) const;
    std::vector<Feature> ListFeatures() const;
    std::vector<Feature> ListFeaturesForEntity(const std::string& entity) const;
    
    // Feature serving (online)
    std::map<std::string, std::vector<float>> GetOnlineFeatures(
        const std::string& entityId,
        const std::vector<std::string>& featureNames);
    
    std::vector<std::map<std::string, std::vector<float>>> GetOnlineFeaturesBatch(
        const std::vector<std::string>& entityIds,
        const std::vector<std::string>& featureNames);
    
    // Feature retrieval (offline)
    std::vector<FeatureVector> GetOfflineFeatures(
        const std::vector<std::string>& featureNames,
        const std::chrono::system_clock::time_point& startTime,
        const std::chrono::system_clock::time_point& endTime);
    
    // Feature ingestion
    void IngestFeatures(const std::string& entityId,
                        const std::map<std::string, std::vector<float>>& features);
    void IngestFeaturesBatch(const std::vector<FeatureVector>& featureVectors);
    
    // Materialization
    void MaterializeFeatures(const std::vector<std::string>& featureNames);
    void ScheduleMaterialization(std::chrono::seconds interval);
    
    // Statistics
    struct FeatureStatistics {
        std::string featureName;
        double mean;
        double std;
        double min;
        double max;
        uint64_t count;
        uint64_t nullCount;
    };
    FeatureStatistics GetFeatureStatistics(const std::string& featureName) const;
    
    // Validation
    bool ValidateFeatureValues(const std::string& featureName,
                                const std::vector<float>& values);
    
private:
    Config config_;
    std::map<std::string, Feature> features_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Data Versioning
// ============================================================================

/**
 * Data versioning for ML datasets.
 */
class DataVersioning {
public:
    struct DatasetVersion {
        std::string datasetName;
        std::string version;
        std::string path;
        std::string checksum;
        uint64_t sizeBytes;
        uint64_t numRows;
        std::chrono::system_clock::time_point createdAt;
        std::map<std::string, std::string> metadata;
        std::optional<std::string> parentVersion;
        std::vector<std::string> tags;
    };
    
    struct Config {
        std::string storagePath;
        bool enableChecksums;
        bool enableCompression;
    };
    
    explicit DataVersioning(const Config& config);
    
    // Version management
    DatasetVersion CreateVersion(const std::string& datasetName,
                                  const std::string& sourcePath,
                                  const std::map<std::string, std::string>& metadata = {});
    std::optional<DatasetVersion> GetVersion(const std::string& datasetName,
                                               const std::string& version) const;
    std::vector<DatasetVersion> ListVersions(const std::string& datasetName) const;
    std::optional<DatasetVersion> GetLatestVersion(const std::string& datasetName) const;
    
    // Tagging
    void TagVersion(const std::string& datasetName,
                    const std::string& version,
                    const std::string& tag);
    void UntagVersion(const std::string& datasetName,
                      const std::string& version,
                      const std::string& tag);
    std::optional<DatasetVersion> GetVersionByTag(const std::string& datasetName,
                                                     const std::string& tag) const;
    
    // Comparison
    struct VersionDiff {
        uint64_t rowsAdded;
        uint64_t rowsRemoved;
        uint64_t rowsModified;
        std::vector<std::string> schemaChanges;
    };
    VersionDiff CompareVersions(const std::string& datasetName,
                                   const std::string& version1,
                                   const std::string& version2) const;
    
    // Lineage
    std::vector<DatasetVersion> GetLineage(const std::string& datasetName,
                                             const std::string& version) const;
    
    // Cleanup
    void DeleteVersion(const std::string& datasetName, const std::string& version);
    void DeleteOldVersions(const std::string& datasetName, uint32_t keepLast);
    
private:
    Config config_;
    std::map<std::string, std::vector<DatasetVersion>> datasets_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Model Monitoring
// ============================================================================

/**
 * Model monitoring for production models.
 */
class ModelMonitoring {
public:
    struct DriftConfig {
        std::string metric;
        float threshold;
        std::chrono::seconds windowSize;
        std::string comparisonMethod;  // ks_test, psi, wasserstein
    };
    
    struct Alert {
        std::string alertId;
        std::string modelName;
        std::string modelVersion;
        std::string alertType;  // drift, performance, data_quality
        std::string severity;   // low, medium, high, critical
        std::string message;
        std::chrono::system_clock::time_point timestamp;
        std::map<std::string, std::string> details;
    };
    
    struct Config {
        std::string trackingUri;
        std::vector<DriftConfig> driftConfigs;
        std::chrono::seconds checkInterval;
        std::function<void(const Alert&)> alertCallback;
    };
    
    explicit ModelMonitoring(const Config& config);
    
    // Monitoring setup
    void MonitorModel(const std::string& modelName,
                      const std::string& modelVersion,
                      const std::string& referenceDataPath);
    void StopMonitoring(const std::string& modelName,
                        const std::string& modelVersion);
    
    // Log predictions
    void LogPrediction(const std::string& modelName,
                       const std::string& modelVersion,
                       const std::vector<float>& features,
                       const std::vector<float>& prediction);
    void LogPredictionWithLabel(const std::string& modelName,
                                 const std::string& modelVersion,
                                 const std::vector<float>& features,
                                 const std::vector<float>& prediction,
                                 const std::vector<float>& actual);
    
    // Drift detection
    bool CheckForDrift(const std::string& modelName,
                       const std::string& modelVersion);
    std::map<std::string, float> GetDriftScores(const std::string& modelName,
                                                  const std::string& modelVersion) const;
    
    // Performance tracking
    struct PerformanceMetrics {
        double accuracy;
        double precision;
        double recall;
        double f1Score;
        double latencyP50;
        double latencyP95;
        double latencyP99;
        double throughput;
    };
    PerformanceMetrics GetPerformanceMetrics(const std::string& modelName,
                                              const std::string& modelVersion) const;
    
    // Alerts
    std::vector<Alert> GetActiveAlerts() const;
    void AcknowledgeAlert(const std::string& alertId);
    void ResolveAlert(const std::string& alertId);
    
    // Reports
    std::string GenerateReport(const std::string& modelName,
                               const std::string& modelVersion,
                               const std::chrono::system_clock::time_point& startTime,
                               const std::chrono::system_clock::time_point& endTime) const;
    
private:
    Config config_;
    std::map<std::string, std::map<std::string, std::string>> monitoredModels_;
    std::vector<Alert> activeAlerts_;
    mutable std::mutex mutex_;
    
    void DriftDetectionLoop();
    std::thread driftThread_;
    std::atomic<bool> stopDriftDetection_;
};

// ============================================================================
// MLOps Pipeline
// ============================================================================

/**
 * Complete MLOps pipeline orchestration.
 */
class MLOpsPipeline {
public:
    struct Config {
        std::string trackingUri;
        std::string artifactStore;
        std::string featureStoreUri;
        std::string modelRegistryUri;
        bool enableAutoRetraining;
        bool enableModelMonitoring;
    };
    
    explicit MLOpsPipeline(const Config& config);
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Experiment tracking
    std::shared_ptr<ExperimentTracker> GetExperimentTracker();
    
    // Feature store
    std::shared_ptr<FeatureStore> GetFeatureStore();
    
    // Data versioning
    std::shared_ptr<DataVersioning> GetDataVersioning();
    
    // Model monitoring
    std::shared_ptr<ModelMonitoring> GetModelMonitoring();
    
    // Pipeline execution
    std::shared_ptr<Pipeline> CreatePipeline(const std::string& name,
                                                const std::string& description);
    void ExecutePipeline(std::shared_ptr<Pipeline> pipeline,
                         const std::map<std::string, std::string>& inputs);
    
    // Auto-retraining
    void EnableAutoRetraining(bool enable);
    void SetRetrainingTrigger(const std::string& modelName,
                              const std::string& triggerType,  // drift, schedule, performance
                              const std::map<std::string, std::string>& config);
    
    // Model promotion
    bool PromoteModel(const std::string& modelName,
                      const std::string& version,
                      const std::string& stage);  // staging, production
    
    // Health check
    bool HealthCheck() const;
    
private:
    Config config_;
    std::shared_ptr<ExperimentTracker> experimentTracker_;
    std::shared_ptr<FeatureStore> featureStore_;
    std::shared_ptr<DataVersioning> dataVersioning_;
    std::shared_ptr<ModelMonitoring> modelMonitoring_;
    std::vector<std::shared_ptr<Pipeline>> pipelines_;
    mutable std::mutex mutex_;
};

} // namespace AI_ML
