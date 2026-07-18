// Phase D.13 Batch 4/5: Model Registry
// Version and manage model artifacts
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

// Forward declarations
struct ModelMetadata;

// ============================================================================
// Model Registry Types
// ============================================================================

enum class ModelStage {
    NONE = 0,
    STAGING = 1,
    PRODUCTION = 2,
    ARCHIVED = 3
};

enum class ModelVersionStatus {
    PENDING = 0,
    READY = 1,
    DEPLOYED = 2,
    DEPRECATED = 3
};

struct ModelVersion {
    std::string version;
    std::string model_id;
    std::string description;
    std::string source_run_id;
    ModelVersionStatus status;
    ModelStage stage;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::string created_by;
    std::map<std::string, std::any> tags;
    std::map<std::string, double> metrics;
    std::string artifact_path;
    std::string signature;
    std::map<std::string, std::any> model_signature;
};

struct RegisteredModel {
    std::string name;
    std::string description;
    std::vector<ModelVersion> versions;
    std::string latest_version;
    std::string production_version;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point updated_at;
    std::map<std::string, std::string> tags;
};

// ============================================================================
// Model Registry
// ============================================================================

class ModelRegistry {
public:
    struct Config {
        std::string registry_uri;
        std::string artifact_store_path;
        bool enable_versioning = true;
        bool require_approval = true;
    };
    
    explicit ModelRegistry(const Config& config);
    ~ModelRegistry();
    
    bool Initialize();
    void Shutdown();
    
    // Model registration
    std::string CreateRegisteredModel(const std::string& name,
                                       const std::string& description = "");
    bool DeleteRegisteredModel(const std::string& name);
    bool RenameRegisteredModel(const std::string& old_name, 
                                const std::string& new_name);
    RegisteredModel GetRegisteredModel(const std::string& name) const;
    std::vector<RegisteredModel> GetAllRegisteredModels() const;
    std::vector<RegisteredModel> SearchRegisteredModels(const std::string& query) const;
    
    // Model tags
    bool SetModelTag(const std::string& name, 
                     const std::string& key, 
                     const std::string& value);
    std::map<std::string, std::string> GetModelTags(const std::string& name) const;
    bool DeleteModelTag(const std::string& name, const std::string& key);
    
private:
    Config config_;
    std::map<std::string, RegisteredModel> models_;
    mutable std::mutex models_mutex_;
};

// ============================================================================
// Model Version Manager
// ============================================================================

class ModelVersionManager {
public:
    struct Config {
        std::string versioning_scheme = "semantic";  // semantic, timestamp, incremental
        bool auto_increment = true;
        int max_versions = 100;
    };
    
    explicit ModelVersionManager(const Config& config);
    
    // Version lifecycle
    std::string CreateVersion(const std::string& model_name,
                               const std::string& source_run_id,
                               const std::string& description = "");
    bool DeleteVersion(const std::string& model_name, const std::string& version);
    
    // Version queries
    ModelVersion GetVersion(const std::string& model_name, 
                            const std::string& version) const;
    std::vector<ModelVersion> GetAllVersions(const std::string& model_name) const;
    ModelVersion GetLatestVersion(const std::string& model_name) const;
    ModelVersion GetProductionVersion(const std::string& model_name) const;
    
    // Stage management
    bool TransitionVersion(const std::string& model_name,
                           const std::string& version,
                           ModelStage new_stage);
    bool SetProductionVersion(const std::string& model_name,
                               const std::string& version);
    bool ArchiveVersion(const std::string& model_name,
                        const std::string& version);
    
    // Version comparison
    std::vector<std::string> CompareVersions(const std::string& model_name,
                                             const std::string& version1,
                                             const std::string& version2) const;
    
    // Version tags
    bool SetVersionTag(const std::string& model_name,
                       const std::string& version,
                       const std::string& key,
                       const std::any& value);
    
private:
    Config config_;
    
    std::string GenerateVersion(const std::string& model_name);
    std::string GenerateSemanticVersion(const std::string& model_name);
    std::string GenerateTimestampVersion();
    std::string GenerateIncrementalVersion(const std::string& model_name);
};

// ============================================================================
// Model Approval Workflow
// ============================================================================

class ModelApprovalWorkflow {
public:
    struct ApprovalRequest {
        std::string request_id;
        std::string model_name;
        std::string version;
        std::string requested_by;
        std::string target_stage;
        std::string justification;
        std::chrono::steady_clock::time_point requested_at;
        std::vector<std::string> approvers;
        std::map<std::string, std::string> approvals;  // approver -> status
        std::string status;  // pending, approved, rejected
    };
    
    struct Config {
        int min_approvers = 2;
        std::chrono::hours approval_timeout{48};
        bool require_tests = true;
        double min_accuracy = 0.8;
    };
    
    explicit ModelApprovalWorkflow(const Config& config);
    
    // Request approval
    std::string RequestApproval(const std::string& model_name,
                                 const std::string& version,
                                 const std::string& target_stage,
                                 const std::string& justification);
    
    // Approval actions
    bool Approve(const std::string& request_id, 
                  const std::string& approver,
                  const std::string& comments = "");
    bool Reject(const std::string& request_id,
                 const std::string& approver,
                 const std::string& reason);
    
    // Queries
    ApprovalRequest GetRequest(const std::string& request_id) const;
    std::vector<ApprovalRequest> GetPendingRequests() const;
    std::vector<ApprovalRequest> GetRequestsForApprover(const std::string& approver) const;
    
    // Validation
    bool ValidateForProduction(const std::string& model_name,
                                  const std::string& version);
    
private:
    Config config_;
    std::map<std::string, ApprovalRequest> requests_;
    mutable std::mutex requests_mutex_;
};

// ============================================================================
// Model Lineage
// ============================================================================

class ModelLineage {
public:
    struct LineageNode {
        std::string id;
        std::string type;  // model, dataset, run, experiment
        std::string name;
        std::map<std::string, std::string> metadata;
    };
    
    struct LineageEdge {
        std::string from_id;
        std::string to_id;
        std::string relationship;  // trained_on, derived_from, deployed_to
    };
    
    // Lineage tracking
    void RecordTraining(const std::string& model_name,
                        const std::string& version,
                        const std::string& run_id,
                        const std::vector<std::string>& dataset_ids);
    
    void RecordDeployment(const std::string& model_name,
                          const std::string& version,
                          const std::string& deployment_id);
    
    void RecordTransformation(const std::string& source_model,
                               const std::string& source_version,
                               const std::string& target_model,
                               const std::string& target_version);
    
    // Lineage queries
    std::vector<LineageNode> GetUpstream(const std::string& model_name,
                                           const std::string& version) const;
    std::vector<LineageNode> GetDownstream(const std::string& model_name,
                                           const std::string& version) const;
    std::vector<LineageNode> GetFullLineage(const std::string& model_name,
                                           const std::string& version) const;
    
    // Visualization
    std::string ExportToDOT(const std::string& model_name,
                            const std::string& version) const;
    std::string ExportToJSON(const std::string& model_name,
                             const std::string& version) const;
    
private:
    std::map<std::string, LineageNode> nodes_;
    std::vector<LineageEdge> edges_;
    mutable std::mutex lineage_mutex_;
};

// ============================================================================
// Model Registry Runtime
// ============================================================================

class ModelRegistryRuntime {
public:
    struct Config {
        ModelRegistry::Config registry;
        ModelVersionManager::Config versions;
        ModelApprovalWorkflow::Config approval;
    };
    
    explicit ModelRegistryRuntime(const Config& config);
    ~ModelRegistryRuntime();
    
    bool Initialize();
    void Shutdown();
    
    // Subsystem access
    ModelRegistry* GetRegistry();
    ModelVersionManager* GetVersionManager();
    ModelApprovalWorkflow* GetApprovalWorkflow();
    ModelLineage* GetLineage();
    
    // High-level operations
    std::string RegisterModelFromRun(const std::string& run_id,
                                       const std::string& model_name,
                                       const std::string& description = "");
    bool PromoteToProduction(const std::string& model_name,
                              const std::string& version);
    bool ArchiveModel(const std::string& model_name);
    
private:
    Config config_;
    std::atomic<bool> initialized_{false};
    
    std::unique_ptr<ModelRegistry> registry_;
    std::unique_ptr<ModelVersionManager> version_manager_;
    std::unique_ptr<ModelApprovalWorkflow> approval_workflow_;
    std::unique_ptr<ModelLineage> lineage_;
};

} // namespace AIML
} // namespace Sovereign
