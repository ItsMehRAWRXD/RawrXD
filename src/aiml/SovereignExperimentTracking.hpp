// Phase D.13 Batch 3/5: Experiment Tracking
// MLflow-style experiment management
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>
#include <any>

namespace Sovereign {
namespace AIML {

// ============================================================================
// Experiment Types
// ============================================================================

enum class ExperimentStatus {
    RUNNING = 0,
    COMPLETED = 1,
    FAILED = 2,
    INTERRUPTED = 3
};

enum class RunStatus {
    RUNNING = 0,
    SCHEDULED = 1,
    COMPLETED = 2,
    FAILED = 3,
    KILLED = 4
};

struct Experiment {
    std::string experiment_id;
    std::string name;
    std::string description;
    std::string artifact_location;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_updated;
    std::map<std::string, std::string> tags;
};

struct Run {
    std::string run_id;
    std::string experiment_id;
    std::string user_id;
    std::string run_name;
    RunStatus status;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    std::map<std::string, std::any> params;
    std::map<std::string, double> metrics;
    std::map<std::string, std::string> tags;
    std::string artifact_uri;
    std::string parent_run_id;
    std::vector<std::string> child_runs;
};

// ============================================================================
// Experiment Manager
// ============================================================================

class ExperimentManager {
public:
    struct Config {
        std::string tracking_uri;
        std::string artifact_store_path;
        bool enable_git_tracking = true;
        bool enable_system_metrics = true;
    };
    
    explicit ExperimentManager(const Config& config);
    ~ExperimentManager();
    
    bool Initialize();
    void Shutdown();
    
    // Experiment CRUD
    std::string CreateExperiment(const std::string& name, 
                                  const std::string& artifact_location = "");
    bool DeleteExperiment(const std::string& experiment_id);
    bool RenameExperiment(const std::string& experiment_id, const std::string& new_name);
    Experiment GetExperiment(const std::string& experiment_id) const;
    std::vector<Experiment> GetAllExperiments() const;
    std::vector<Experiment> SearchExperiments(const std::string& query) const;
    
    // Experiment metadata
    bool SetExperimentTag(const std::string& experiment_id, 
                          const std::string& key, 
                          const std::string& value);
    std::map<std::string, std::string> GetExperimentTags(const std::string& experiment_id) const;
    
private:
    Config config_;
    std::map<std::string, Experiment> experiments_;
    mutable std::mutex experiments_mutex_;
};

// ============================================================================
// Run Manager
// ============================================================================

class RunManager {
public:
    struct Config {
        std::chrono::seconds auto_log_interval{60};
        int max_runs_per_experiment = 1000;
        bool enable_nested_runs = true;
    };
    
    explicit RunManager(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Run lifecycle
    std::string StartRun(const std::string& experiment_id, 
                         const std::string& run_name = "",
                         const std::string& parent_run_id = "");
    bool EndRun(const std::string& run_id, RunStatus status = RunStatus::COMPLETED);
    bool KillRun(const std::string& run_id);
    
    // Run queries
    Run GetRun(const std::string& run_id) const;
    std::vector<Run> GetRuns(const std::string& experiment_id) const;
    std::vector<Run> GetRunsByStatus(RunStatus status) const;
    std::vector<Run> SearchRuns(const std::string& experiment_id,
                                 const std::map<std::string, std::string>& filters) const;
    
    // Run metadata
    bool SetRunTag(const std::string& run_id, 
                   const std::string& key, 
                   const std::string& value);
    std::map<std::string, std::string> GetRunTags(const std::string& run_id) const;
    
    // Parameters
    bool LogParam(const std::string& run_id, 
                  const std::string& key, 
                  const std::any& value);
    bool LogParams(const std::string& run_id, 
                   const std::map<std::string, std::any>& params);
    std::map<std::string, std::any> GetParams(const std::string& run_id) const;
    
    // Metrics
    bool LogMetric(const std::string& run_id, 
                   const std::string& key, 
                   double value, 
                   int step = 0);
    bool LogMetrics(const std::string& run_id, 
                    const std::map<std::string, double>& metrics,
                    int step = 0);
    std::vector<std::pair<int, double>> GetMetricHistory(const std::string& run_id,
                                                          const std::string& key) const;
    
    // Active run
    std::string GetActiveRun() const;
    bool IsActiveRun(const std::string& run_id) const;
    
private:
    Config config_;
    std::map<std::string, Run> runs_;
    std::map<std::string, std::vector<std::pair<int, double>>> metric_history_;
    std::string active_run_id_;
    mutable std::mutex runs_mutex_;
};

// ============================================================================
// Artifact Store
// ============================================================================

class ArtifactStore {
public:
    struct Config {
        std::string base_path;
        std::string backend = "local";  // local, s3, gcs, azure
        std::map<std::string, std::string> backend_config;
    };
    
    explicit ArtifactStore(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // Artifact operations
    bool LogArtifact(const std::string& run_id, 
                     const std::string& local_path,
                     const std::string& artifact_path = "");
    bool LogArtifacts(const std::string& run_id,
                      const std::string& local_dir,
                      const std::string& artifact_path = "");
    
    // Download
    bool DownloadArtifact(const std::string& run_id,
                          const std::string& artifact_path,
                          const std::string& local_path);
    std::vector<std::string> ListArtifacts(const std::string& run_id,
                                           const std::string& path = "") const;
    
    // Model artifacts
    bool LogModel(const std::string& run_id,
                  const std::string& model_name,
                  const std::string& model_path,
                  const std::map<std::string, std::any>& flavor_config = {});
    
private:
    Config config_;
};

// ============================================================================
// Auto-logging
// ============================================================================

class AutoLogger {
public:
    struct Config {
        bool log_system_metrics = true;
        bool log_git_info = true;
        bool log_source_code = false;
        std::chrono::seconds log_interval{60};
    };
    
    explicit AutoLogger(const Config& config);
    
    bool Initialize();
    void Shutdown();
    
    // System metrics
    void StartSystemLogging(const std::string& run_id);
    void StopSystemLogging(const std::string& run_id);
    
    // Git info
    void LogGitInfo(const std::string& run_id);
    
    // Source code
    void LogSourceCode(const std::string& run_id, const std::string& source_dir);
    
private:
    Config config_;
    std::set<std::string> logging_runs_;
    std::thread logging_thread_;
    std::atomic<bool> running_{false};
    
    void LoggingLoop();
    std::map<std::string, double> GetSystemMetrics();
};

// ============================================================================
// Experiment Comparison
// ============================================================================

class ExperimentComparison {
public:
    // Compare runs
    struct ComparisonResult {
        std::vector<std::string> run_ids;
        std::map<std::string, std::map<std::string, std::any>> params;
        std::map<std::string, std::map<std::string, double>> metrics;
        std::map<std::string, std::map<std::string, std::string>> tags;
    };
    
    ComparisonResult CompareRuns(const std::vector<std::string>& run_ids) const;
    
    // Diff
    std::map<std::string, std::pair<std::any, std::any>> DiffRuns(
        const std::string& run_id_1, 
        const std::string& run_id_2) const;
    
    // Best run
    std::string GetBestRun(const std::string& experiment_id,
                           const std::string& metric_name,
                           bool maximize = true) const;
    
    // Parallel coordinates
    std::string ExportParallelCoordinates(const std::vector<std::string>& run_ids,
                                          const std::string& output_path) const;
    
    // Scatter plot
    std::string ExportScatterPlot(const std::vector<std::string>& run_ids,
                                  const std::string& x_metric,
                                  const std::string& y_metric,
                                  const std::string& output_path) const;
};

// ============================================================================
// Experiment Tracking Runtime
// ============================================================================

class ExperimentTrackingRuntime {
public:
    struct Config {
        ExperimentManager::Config manager;
        RunManager::Config runs;
        ArtifactStore::Config artifacts;
        AutoLogger::Config autolog;
    };
    
    explicit ExperimentTrackingRuntime(const Config& config);
    ~ExperimentTrackingRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ExperimentManager* GetExperimentManager();
    RunManager* GetRunManager();
    ArtifactStore* GetArtifactStore();
    AutoLogger* GetAutoLogger();
    ExperimentComparison* GetComparison();
    
    // High-level API
    std::string CreateExperimentAndStartRun(const std::string& experiment_name,
                                             const std::string& run_name = "");
    bool Log(const std::string& run_id,
             const std::map<std::string, std::any>& params = {},
             const std::map<std::string, double>& metrics = {});
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ExperimentManager> experiment_manager_;
    std::unique_ptr<RunManager> run_manager_;
    std::unique_ptr<ArtifactStore> artifact_store_;
    std::unique_ptr<AutoLogger> auto_logger_;
    std::unique_ptr<ExperimentComparison> comparison_;
};

} // namespace AIML
} // namespace Sovereign
