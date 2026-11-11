// Phase O.2/5: Experiment Tracking
// RawrXD Experiment Tracker - ML experiment management

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <variant>
#include <optional>

namespace RawrXD {
namespace ML {

// Experiment status
enum class ExperimentStatus {
    PENDING,      // Created but not started
    RUNNING,      // Currently executing
    COMPLETED,    // Finished successfully
    FAILED,       // Failed with error
    ABORTED,      // Manually stopped
    PAUSED        // Temporarily paused
};

// Metric value types
using MetricValue = std::variant<
    int64_t,
    double,
    std::string
>;

// Experiment parameter
struct Parameter {
    std::string key;
    MetricValue value;
    std::string description;
};

// Experiment metric
struct Metric {
    std::string key;
    MetricValue value;
    std::chrono::system_clock::time_point timestamp;
    uint64_t step;  // Training step/iteration
    std::unordered_map<std::string, std::string> context;
};

// Experiment tag
struct Tag {
    std::string key;
    std::string value;
};

// Experiment artifact (output files)
struct ExperimentArtifact {
    std::string id;
    std::string name;
    std::string type;  // e.g., "model", "checkpoint", "plot", "log"
    std::string path;
    uint64_t size_bytes;
    std::string checksum;
    std::chrono::system_clock::time_point created_at;
    std::unordered_map<std::string, std::string> metadata;
};

// Experiment definition
struct Experiment {
    std::string id;
    std::string name;
    std::string description;
    std::string project_id;
    std::string user_id;
    
    // Configuration
    std::vector<Parameter> parameters;
    std::vector<Tag> tags;
    
    // Status
    ExperimentStatus status;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point started_at;
    std::chrono::system_clock::time_point ended_at;
    std::chrono::milliseconds duration_ms;
    
    // Execution
    std::string run_id;           // Unique run identifier
    std::string parent_run_id;    // For nested runs
    std::vector<std::string> child_run_ids;
    
    // Results
    std::vector<Metric> metrics;
    std::vector<ExperimentArtifact> artifacts;
    std::string notes;
    
    // Environment
    struct Environment {
        std::string rawrxd_version;
        std::string git_commit;
        std::string git_branch;
        std::unordered_map<std::string, std::string> system_info;
        std::unordered_map<std::string, std::string> dependencies;
    } environment;
    
    // Error tracking
    std::string error_message;
    std::string error_stacktrace;
};

// Project definition
struct Project {
    std::string id;
    std::string name;
    std::string description;
    std::string owner;
    std::vector<std::string> collaborators;
    std::chrono::system_clock::time_point created_at;
    uint32_t experiment_count;
    std::unordered_map<std::string, std::string> metadata;
};

// Run comparison
struct RunComparison {
    std::string base_run_id;
    std::string compare_run_id;
    std::unordered_map<std::string, std::pair<MetricValue, MetricValue>> metric_differences;
    std::unordered_map<std::string, std::pair<MetricValue, MetricValue>> parameter_differences;
    float overall_improvement;  // Percentage
};

// Experiment tracker interface
class IExperimentTracker {
public:
    virtual ~IExperimentTracker() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& storage_path) = 0;
    virtual void Shutdown() = 0;
    
    // Project management
    virtual std::string CreateProject(const std::string& name, 
                                       const std::string& description,
                                       const std::string& owner) = 0;
    virtual bool DeleteProject(const std::string& project_id) = 0;
    virtual std::optional<Project> GetProject(const std::string& project_id) = 0;
    virtual std::vector<Project> ListProjects(const std::string& user_id = "") = 0;
    virtual bool UpdateProject(const std::string& project_id, const Project& project) = 0;
    
    // Experiment lifecycle
    virtual std::string CreateExperiment(const std::string& project_id,
                                          const std::string& name,
                                          const std::vector<Parameter>& parameters = {}) = 0;
    virtual bool StartExperiment(const std::string& experiment_id) = 0;
    virtual bool EndExperiment(const std::string& experiment_id, 
                                bool success = true,
                                const std::string& error_message = "") = 0;
    virtual bool AbortExperiment(const std::string& experiment_id, 
                                  const std::string& reason) = 0;
    virtual bool PauseExperiment(const std::string& experiment_id) = 0;
    virtual bool ResumeExperiment(const std::string& experiment_id) = 0;
    
    // Experiment queries
    virtual std::optional<Experiment> GetExperiment(const std::string& experiment_id) = 0;
    virtual std::vector<Experiment> ListExperiments(const std::string& project_id = "",
                                                       ExperimentStatus status = ExperimentStatus::PENDING,
                                                       uint32_t limit = 100) = 0;
    virtual std::vector<Experiment> SearchExperiments(const std::string& query,
                                                          const std::string& project_id = "") = 0;
    
    // Metrics logging
    virtual bool LogMetric(const std::string& experiment_id,
                           const std::string& key,
                           MetricValue value,
                           uint64_t step = 0,
                           const std::unordered_map<std::string, std::string>& context = {}) = 0;
    virtual bool LogMetrics(const std::string& experiment_id,
                            const std::unordered_map<std::string, MetricValue>& metrics,
                            uint64_t step = 0) = 0;
    virtual bool LogBatchMetrics(const std::string& experiment_id,
                                  const std::vector<Metric>& metrics) = 0;
    
    // Parameter logging
    virtual bool LogParameter(const std::string& experiment_id,
                              const std::string& key,
                              MetricValue value,
                              const std::string& description = "") = 0;
    virtual bool LogParameters(const std::string& experiment_id,
                               const std::vector<Parameter>& parameters) = 0;
    
    // Artifact management
    virtual bool LogArtifact(const std::string& experiment_id,
                             const ExperimentArtifact& artifact) = 0;
    virtual std::vector<ExperimentArtifact> GetArtifacts(const std::string& experiment_id,
                                                           const std::string& type = "") = 0;
    
    // Tag management
    virtual bool SetTag(const std::string& experiment_id,
                        const std::string& key,
                        const std::string& value) = 0;
    virtual bool DeleteTag(const std::string& experiment_id,
                         const std::string& key) = 0;
    
    // Notes
    virtual bool SetNotes(const std::string& experiment_id,
                          const std::string& notes) = 0;
    
    // Comparison
    virtual RunComparison CompareRuns(const std::string& run_id_1,
                                       const std::string& run_id_2) = 0;
    
    // Analysis
    virtual std::vector<Experiment> GetBestRuns(const std::string& project_id,
                                                    const std::string& metric_key,
                                                    uint32_t top_k = 10,
                                                    bool maximize = true) = 0;
    virtual std::unordered_map<std::string, MetricValue> GetLatestMetrics(
        const std::string& experiment_id) = 0;
    virtual std::vector<Metric> GetMetricHistory(const std::string& experiment_id,
                                                   const std::string& metric_key) = 0;
    
    // Export
    virtual bool ExportExperiment(const std::string& experiment_id,
                                   const std::string& format,
                                   const std::string& output_path) = 0;
};

// Local experiment tracker
class LocalExperimentTracker : public IExperimentTracker {
public:
    LocalExperimentTracker();
    ~LocalExperimentTracker() override;
    
    bool Initialize(const std::string& storage_path) override;
    void Shutdown() override;
    
    std::string CreateProject(const std::string& name, 
                             const std::string& description,
                             const std::string& owner) override;
    bool DeleteProject(const std::string& project_id) override;
    std::optional<Project> GetProject(const std::string& project_id) override;
    std::vector<Project> ListProjects(const std::string& user_id = "") override;
    bool UpdateProject(const std::string& project_id, const Project& project) override;
    
    std::string CreateExperiment(const std::string& project_id,
                                  const std::string& name,
                                  const std::vector<Parameter>& parameters = {}) override;
    bool StartExperiment(const std::string& experiment_id) override;
    bool EndExperiment(const std::string& experiment_id, 
                       bool success = true,
                       const std::string& error_message = "") override;
    bool AbortExperiment(const std::string& experiment_id, 
                         const std::string& reason) override;
    bool PauseExperiment(const std::string& experiment_id) override;
    bool ResumeExperiment(const std::string& experiment_id) override;
    
    std::optional<Experiment> GetExperiment(const std::string& experiment_id) override;
    std::vector<Experiment> ListExperiments(const std::string& project_id = "",
                                               ExperimentStatus status = ExperimentStatus::PENDING,
                                               uint32_t limit = 100) override;
    std::vector<Experiment> SearchExperiments(const std::string& query,
                                                const std::string& project_id = "") override;
    
    bool LogMetric(const std::string& experiment_id,
                   const std::string& key,
                   MetricValue value,
                   uint64_t step = 0,
                   const std::unordered_map<std::string, std::string>& context = {}) override;
    bool LogMetrics(const std::string& experiment_id,
                    const std::unordered_map<std::string, MetricValue>& metrics,
                    uint64_t step = 0) override;
    bool LogBatchMetrics(const std::string& experiment_id,
                         const std::vector<Metric>& metrics) override;
    
    bool LogParameter(const std::string& experiment_id,
                    const std::string& key,
                    MetricValue value,
                    const std::string& description = "") override;
    bool LogParameters(const std::string& experiment_id,
                       const std::vector<Parameter>& parameters) override;
    
    bool LogArtifact(const std::string& experiment_id,
                     const ExperimentArtifact& artifact) override;
    std::vector<ExperimentArtifact> GetArtifacts(const std::string& experiment_id,
                                                       const std::string& type = "") override;
    
    bool SetTag(const std::string& experiment_id,
                const std::string& key,
                const std::string& value) override;
    bool DeleteTag(const std::string& experiment_id,
                   const std::string& key) override;
    
    bool SetNotes(const std::string& experiment_id,
                  const std::string& notes) override;
    
    RunComparison CompareRuns(const std::string& run_id_1,
                               const std::string& run_id_2) override;
    
    std::vector<Experiment> GetBestRuns(const std::string& project_id,
                                            const std::string& metric_key,
                                            uint32_t top_k = 10,
                                            bool maximize = true) override;
    std::unordered_map<std::string, MetricValue> GetLatestMetrics(
        const std::string& experiment_id) override;
    std::vector<Metric> GetMetricHistory(const std::string& experiment_id,
                                           const std::string& metric_key) override;
    
    bool ExportExperiment(const std::string& experiment_id,
                          const std::string& format,
                          const std::string& output_path) override;
    
private:
    std::string storage_path_;
    std::unordered_map<std::string, Project> projects_;
    std::unordered_map<std::string, Experiment> experiments_;
    bool initialized_ = false;
    
    bool SaveProject(const Project& project);
    bool LoadProject(const std::string& project_id, Project& project);
    bool SaveExperiment(const Experiment& experiment);
    bool LoadExperiment(const std::string& experiment_id, Experiment& experiment);
};

// Experiment context for automatic tracking
class ExperimentContext {
public:
    explicit ExperimentContext(const std::string& experiment_id);
    ~ExperimentContext();
    
    void LogMetric(const std::string& key, MetricValue value, uint64_t step = 0);
    void LogParameter(const std::string& key, MetricValue value);
    void LogArtifact(const ExperimentArtifact& artifact);
    void SetTag(const std::string& key, const std::string& value);
    
private:
    std::string experiment_id_;
};

// Auto-experiment tracking (RAII)
class AutoExperiment {
public:
    AutoExperiment(const std::string& project_id,
                   const std::string& name,
                   const std::vector<Parameter>& parameters = {});
    ~AutoExperiment();
    
    void Success();
    void Fail(const std::string& error_message);
    
    std::string GetExperimentId() const { return experiment_id_; }
    
private:
    std::string experiment_id_;
    bool ended_ = false;
};

// Global experiment tracker
extern std::unique_ptr<IExperimentTracker> g_experiment_tracker;

// Initialize experiment tracking
bool InitializeExperimentTracking(const std::string& config);
void ShutdownExperimentTracking();
bool IsExperimentTrackingEnabled();

// Convenience macros
#define RAWRXD_EXPERIMENT(project_id, name, ...) \
    RawrXD::ML::AutoExperiment _experiment(project_id, name, ##__VA_ARGS__)

#define RAWRXD_LOG_METRIC(key, value) \
    do { if (RawrXD::ML::g_experiment_tracker) { \
        RawrXD::ML::g_experiment_tracker->LogMetric(_experiment.GetExperimentId(), key, value); \
    } } while(0)

#define RAWRXD_LOG_PARAM(key, value) \
    do { if (RawrXD::ML::g_experiment_tracker) { \
        RawrXD::ML::g_experiment_tracker->LogParameter(_experiment.GetExperimentId(), key, value); \
    } } while(0)

} // namespace ML
} // namespace RawrXD
