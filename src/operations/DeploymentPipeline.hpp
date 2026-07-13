// Phase X.1/5: Production Deployment Pipeline
// RawrXD Deployment Pipeline - Automated build, test, and deployment orchestration

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>
#include <variant>

namespace RawrXD {
namespace Operations {

// Deployment environment types
enum class DeploymentEnvironment {
    DEVELOPMENT,
    STAGING,
    PRODUCTION,
    CANARY,
    BLUE_GREEN
};

// Deployment stage
enum class DeploymentStage {
    PENDING,
    BUILDING,
    TESTING,
    PACKAGING,
    DEPLOYING,
    VERIFYING,
    ROLLING_BACK,
    COMPLETED,
    FAILED
};

// Artifact type
enum class ArtifactType {
    EXECUTABLE,
    LIBRARY,
    HEADER,
    DOCUMENTATION,
    CONFIGURATION,
    CONTAINER_IMAGE,
    PACKAGE
};

// Build configuration
struct BuildConfiguration {
    std::string config_id;
    std::string name;
    
    // Compiler settings
    std::string compiler;
    std::string compiler_version;
    std::vector<std::string> compiler_flags;
    std::vector<std::string> defines;
    
    // Build options
    bool enable_optimizations;
    bool enable_debug_info;
    bool enable_profiling;
    bool enable_asan;
    bool enable_tsan;
    
    // Target
    std::string target_architecture;  // x64, arm64, etc.
    std::string target_platform;      // windows, linux, macos
    
    // Output
    std::string output_directory;
    std::string artifact_prefix;
};

// Build artifact
struct BuildArtifact {
    std::string artifact_id;
    std::string name;
    ArtifactType type;
    std::string path;
    std::string checksum;
    size_t size_bytes;
    
    // Metadata
    std::chrono::system_clock::time_point created_at;
    std::string build_configuration_id;
    std::string git_commit_hash;
    std::string git_branch;
    
    // Dependencies
    std::vector<std::string> dependencies;
};

// Test suite configuration
struct TestSuiteConfiguration {
    std::string suite_id;
    std::string name;
    std::string description;
    
    // Test categories
    bool run_unit_tests;
    bool run_integration_tests;
    bool run_benchmarks;
    bool run_stress_tests;
    bool run_security_tests;
    
    // Execution
    uint32_t parallel_jobs;
    std::chrono::seconds timeout;
    std::vector<std::string> test_filters;
    std::vector<std::string> exclude_filters;
    
    // Coverage
    bool enable_coverage;
    double minimum_coverage_percent;
};

// Deployment target
struct DeploymentTarget {
    std::string target_id;
    std::string name;
    DeploymentEnvironment environment;
    
    // Connection
    std::string host;
    uint32_t port;
    std::string credentials_id;
    
    // Configuration
    std::string install_path;
    std::string config_path;
    std::string data_path;
    std::string log_path;
    
    // Resources
    uint32_t max_memory_mb;
    uint32_t max_cpu_percent;
    uint32_t max_disk_gb;
    
    // Health check
    std::string health_check_url;
    std::chrono::seconds health_check_interval;
};

// Deployment pipeline
struct DeploymentPipeline {
    std::string pipeline_id;
    std::string name;
    std::string description;
    
    // Stages
    std::vector<std::string> stage_order;
    std::unordered_map<std::string, BuildConfiguration> build_configs;
    std::unordered_map<std::string, TestSuiteConfiguration> test_configs;
    
    // Deployment
    std::vector<DeploymentTarget> targets;
    
    // Triggers
    bool trigger_on_commit;
    bool trigger_on_tag;
    std::vector<std::string> trigger_branches;
    std::vector<std::string> trigger_tags;
    
    // Notifications
    std::vector<std::string> notify_on_success;
    std::vector<std::string> notify_on_failure;
};

// Pipeline execution
struct PipelineExecution {
    std::string execution_id;
    std::string pipeline_id;
    std::string triggered_by;
    std::chrono::system_clock::time_point started_at;
    
    // Current state
    DeploymentStage current_stage;
    std::string current_stage_details;
    
    // Results
    std::vector<BuildArtifact> artifacts;
    std::unordered_map<std::string, bool> test_results;
    std::unordered_map<std::string, bool> deployment_results;
    
    // Status
    bool is_complete;
    bool is_successful;
    std::string error_message;
    std::chrono::system_clock::time_point completed_at;
};

// Deployment pipeline interface
class IDeploymentPipeline {
public:
    virtual ~IDeploymentPipeline() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Pipeline management
    virtual std::string CreatePipeline(const DeploymentPipeline& pipeline) = 0;
    virtual bool UpdatePipeline(const DeploymentPipeline& pipeline) = 0;
    virtual bool DeletePipeline(const std::string& pipeline_id) = 0;
    virtual std::optional<DeploymentPipeline> GetPipeline(const std::string& pipeline_id) = 0;
    virtual std::vector<DeploymentPipeline> ListPipelines() = 0;
    
    // Build configuration
    virtual std::string AddBuildConfiguration(const std::string& pipeline_id, 
                                               const BuildConfiguration& config) = 0;
    virtual bool UpdateBuildConfiguration(const BuildConfiguration& config) = 0;
    virtual bool RemoveBuildConfiguration(const std::string& config_id) = 0;
    
    // Test configuration
    virtual std::string AddTestConfiguration(const std::string& pipeline_id,
                                              const TestSuiteConfiguration& config) = 0;
    virtual bool UpdateTestConfiguration(const TestSuiteConfiguration& config) = 0;
    virtual bool RemoveTestConfiguration(const std::string& config_id) = 0;
    
    // Deployment targets
    virtual std::string AddDeploymentTarget(const std::string& pipeline_id,
                                               const DeploymentTarget& target) = 0;
    virtual bool UpdateDeploymentTarget(const DeploymentTarget& target) = 0;
    virtual bool RemoveDeploymentTarget(const std::string& target_id) = 0;
    
    // Execution
    virtual std::string ExecutePipeline(const std::string& pipeline_id,
                                         const std::string& git_ref = "") = 0;
    virtual std::optional<PipelineExecution> GetExecution(const std::string& execution_id) = 0;
    virtual std::vector<PipelineExecution> GetExecutions(const std::string& pipeline_id = "") = 0;
    virtual bool CancelExecution(const std::string& execution_id) = 0;
    virtual bool RetryExecution(const std::string& execution_id) = 0;
    
    // Stage control
    virtual bool PromoteToStage(const std::string& execution_id, 
                                 DeploymentStage stage) = 0;
    virtual bool RollbackExecution(const std::string& execution_id) = 0;
    
    // Artifacts
    virtual std::vector<BuildArtifact> GetArtifacts(const std::string& execution_id) = 0;
    virtual std::optional<BuildArtifact> GetArtifact(const std::string& artifact_id) = 0;
    virtual bool DownloadArtifact(const std::string& artifact_id, 
                                   const std::string& destination) = 0;
    
    // Health checks
    virtual bool RunHealthCheck(const std::string& target_id) = 0;
    virtual std::unordered_map<std::string, bool> GetTargetHealth() = 0;
    
    // Statistics
    virtual struct PipelineStatistics {
        uint32_t total_pipelines;
        uint32_t active_executions;
        uint32_t successful_deployments_24h;
        uint32_t failed_deployments_24h;
        double average_build_time_minutes;
        double average_deployment_time_minutes;
        double success_rate_percent;
    } GetStatistics() = 0;
};

// Local deployment pipeline implementation
class LocalDeploymentPipeline : public IDeploymentPipeline {
public:
    LocalDeploymentPipeline();
    ~LocalDeploymentPipeline() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string CreatePipeline(const DeploymentPipeline& pipeline) override;
    bool UpdatePipeline(const DeploymentPipeline& pipeline) override;
    bool DeletePipeline(const std::string& pipeline_id) override;
    std::optional<DeploymentPipeline> GetPipeline(const std::string& pipeline_id) override;
    std::vector<DeploymentPipeline> ListPipelines() override;
    
    std::string AddBuildConfiguration(const std::string& pipeline_id, 
                                       const BuildConfiguration& config) override;
    bool UpdateBuildConfiguration(const BuildConfiguration& config) override;
    bool RemoveBuildConfiguration(const std::string& config_id) override;
    
    std::string AddTestConfiguration(const std::string& pipeline_id,
                                      const TestSuiteConfiguration& config) override;
    bool UpdateTestConfiguration(const TestSuiteConfiguration& config) override;
    bool RemoveTestConfiguration(const std::string& config_id) override;
    
    std::string AddDeploymentTarget(const std::string& pipeline_id,
                                     const DeploymentTarget& target) override;
    bool UpdateDeploymentTarget(const DeploymentTarget& target) override;
    bool RemoveDeploymentTarget(const std::string& target_id) override;
    
    std::string ExecutePipeline(const std::string& pipeline_id,
                                 const std::string& git_ref = "") override;
    std::optional<PipelineExecution> GetExecution(const std::string& execution_id) override;
    std::vector<PipelineExecution> GetExecutions(const std::string& pipeline_id = "") override;
    bool CancelExecution(const std::string& execution_id) override;
    bool RetryExecution(const std::string& execution_id) override;
    
    bool PromoteToStage(const std::string& execution_id, 
                         DeploymentStage stage) override;
    bool RollbackExecution(const std::string& execution_id) override;
    
    std::vector<BuildArtifact> GetArtifacts(const std::string& execution_id) override;
    std::optional<BuildArtifact> GetArtifact(const std::string& artifact_id) override;
    bool DownloadArtifact(const std::string& artifact_id, 
                           const std::string& destination) override;
    
    bool RunHealthCheck(const std::string& target_id) override;
    std::unordered_map<std::string, bool> GetTargetHealth() override;
    
    PipelineStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, DeploymentPipeline> pipelines_;
    std::unordered_map<std::string, PipelineExecution> executions_;
    std::unordered_map<std::string, BuildArtifact> artifacts_;
    bool initialized_ = false;
    
    bool ExecuteBuildStage(PipelineExecution& execution, const BuildConfiguration& config);
    bool ExecuteTestStage(PipelineExecution& execution, const TestSuiteConfiguration& config);
    bool ExecuteDeployStage(PipelineExecution& execution, const DeploymentTarget& target);
    bool ExecuteVerifyStage(PipelineExecution& execution, const DeploymentTarget& target);
    std::string GenerateExecutionId();
    std::string GenerateArtifactId();
};

// Global deployment pipeline
extern std::unique_ptr<IDeploymentPipeline> g_deployment_pipeline;

// Initialize deployment pipeline
bool InitializeDeploymentPipeline(const std::string& config_path);
void ShutdownDeploymentPipeline();
bool IsDeploymentPipelineEnabled();

// Environment helpers
std::string DeploymentEnvironmentToString(DeploymentEnvironment env);
DeploymentEnvironment DeploymentEnvironmentFromString(const std::string& str);
std::string DeploymentStageToString(DeploymentStage stage);
DeploymentStage DeploymentStageFromString(const std::string& str);

} // namespace Operations
} // namespace RawrXD
