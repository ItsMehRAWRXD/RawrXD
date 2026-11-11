/**
 * ModelRegistry.hpp
 *
 * Phase L Batch 1/5: Model Registry & Versioning
 *
 * Centralized model registry with versioning, metadata tracking,
 * and lifecycle management for ML models.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <chrono>

namespace AI_ML {

// ============================================================================
// Forward Declarations
// ============================================================================

class ModelVersion;
class ModelArtifact;
class ModelRegistry;
class ModelLifecycleManager;

// ============================================================================
// Model Framework
// ============================================================================

enum class ModelFramework {
    PYTORCH,
    TENSORFLOW,
    ONNX,
    TENSORRT,
    OPENVINO,
    GGML,
    GGUF,
    SAFETENSORS,
    JAX,
    MXNET,
    CAFFE,
    CUSTOM
};

std::string ModelFrameworkToString(ModelFramework framework);
ModelFramework ModelFrameworkFromString(const std::string& str);

// ============================================================================
// Model Format
// ============================================================================

enum class ModelFormat {
    PYTORCH_NATIVE,
    TENSORFLOW_SAVEDMODEL,
    ONNX,
    TENSORRT_ENGINE,
    OPENVINO_IR,
    GGML_BIN,
    GGUF,
    SAFETENSORS,
    H5,
    PB,
    PICKLE,
    CUSTOM
};

// ============================================================================
// Model Status
// ============================================================================

enum class ModelStatus {
    REGISTERED,
    VALIDATING,
    VALIDATED,
    STAGING,
    PRODUCTION,
    DEPRECATED,
    ARCHIVED,
    FAILED
};

// ============================================================================
// Model Signature
// ============================================================================

/**
 * Model input/output signature.
 */
struct ModelSignature {
    struct TensorSpec {
        std::string name;
        std::vector<int64_t> shape;
        std::string dtype;
        std::optional<std::string> description;
    };
    
    std::vector<TensorSpec> inputs;
    std::vector<TensorSpec> outputs;
    std::map<std::string, std::string> metadata;
    
    std::string ToJson() const;
    static ModelSignature FromJson(const std::string& json);
};

// ============================================================================
// Model Metrics
// ============================================================================

/**
 * Model performance metrics.
 */
struct ModelMetrics {
    // Training metrics
    double trainingLoss;
    double validationLoss;
    double trainingAccuracy;
    double validationAccuracy;
    uint64_t trainingSteps;
    uint64_t epochs;
    std::chrono::seconds trainingDuration;
    
    // Evaluation metrics
    double accuracy;
    double precision;
    double recall;
    double f1Score;
    double auc;
    std::map<std::string, double> customMetrics;
    
    // Inference metrics
    double averageLatencyMs;
    double p50LatencyMs;
    double p95LatencyMs;
    double p99LatencyMs;
    double throughputQps;
    double gpuUtilization;
    double memoryUsageGb;
    
    // Model characteristics
    uint64_t parameterCount;
    uint64_t modelSizeBytes;
    uint64_t flops;
    std::string quantization;
    std::string precision;
    
    std::string ToJson() const;
};

// ============================================================================
// Model Artifact
// ============================================================================

/**
 * Model artifact (file or blob).
 */
class ModelArtifact {
public:
    struct Config {
        std::string name;
        std::string version;
        std::string storagePath;
        std::string checksum;
        uint64_t sizeBytes;
        ModelFormat format;
        std::map<std::string, std::string> metadata;
    };
    
    explicit ModelArtifact(const Config& config);
    
    // Storage
    bool Upload(const std::string& sourcePath);
    bool Download(const std::string& destinationPath);
    bool Delete();
    bool Exists() const;
    
    // Validation
    bool ValidateChecksum();
    bool ValidateFormat();
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetUri() const;
    
private:
    Config config_;
};

// ============================================================================
// Model Version
// ============================================================================

/**
 * Model version with full metadata.
 */
class ModelVersion {
public:
    struct Config {
        std::string modelName;
        std::string version;
        std::string description;
        ModelFramework framework;
        ModelFormat format;
        ModelStatus status;
        
        // Source
        std::string sourceCodeUrl;
        std::string trainingDataUrl;
        std::string experimentId;
        std::string runId;
        
        // Artifacts
        std::vector<std::string> artifactPaths;
        std::string primaryArtifact;
        
        // Metadata
        ModelSignature signature;
        ModelMetrics metrics;
        std::map<std::string, std::string> tags;
        std::map<std::string, std::string> hyperparameters;
        std::map<std::string, std::string> dependencies;
        
        // Lifecycle
        std::string createdBy;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> stagedAt;
        std::optional<std::chrono::system_clock::time_point> productionAt;
        std::optional<std::chrono::system_clock::time_point> deprecatedAt;
        std::optional<std::string> replacedBy;
    };
    
    explicit ModelVersion(const Config& config);
    
    // Artifacts
    void AddArtifact(std::shared_ptr<ModelArtifact> artifact);
    void RemoveArtifact(const std::string& name);
    std::vector<std::shared_ptr<ModelArtifact>> GetArtifacts() const;
    std::shared_ptr<ModelArtifact> GetPrimaryArtifact() const;
    
    // Status transitions
    bool Stage();
    bool PromoteToProduction();
    bool Deprecate(const std::string& replacementVersion = "");
    bool Archive();
    
    // Validation
    bool Validate();
    std::vector<std::string> GetValidationErrors() const;
    
    // Comparison
    struct Comparison {
        std::string metric;
        double baselineValue;
        double candidateValue;
        double difference;
        double percentChange;
        bool significant;
    };
    std::vector<Comparison> CompareTo(const ModelVersion& other) const;
    
    // Accessors
    const Config& GetConfig() const { return config_; }
    std::string GetFullName() const;
    ModelStatus GetStatus() const { return config_.status; }
    
    // Export
    std::string ToJson() const;
    std::string ToYaml() const;
    std::string ToMlflowFormat() const;
    std::string ToKfservingFormat() const;
    
private:
    Config config_;
    std::vector<std::shared_ptr<ModelArtifact>> artifacts_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Model Registry
// ============================================================================

/**
 * Centralized model registry.
 */
class ModelRegistry {
public:
    struct Config {
        std::string storageBackend;  // s3, gcs, azure, local
        std::string storagePath;
        std::string databaseUrl;
        bool enableVersioning;
        bool enableLineageTracking;
        uint32_t maxVersionsPerModel;
        uint64_t maxArtifactSize;
    };
    
    struct SearchCriteria {
        std::optional<std::string> name;
        std::optional<ModelFramework> framework;
        std::optional<ModelStatus> status;
        std::optional<std::string> tag;
        std::optional<std::string> createdBy;
        std::optional<std::chrono::system_clock::time_point> createdAfter;
        std::optional<std::chrono::system_clock::time_point> createdBefore;
        std::map<std::string, std::string> metadataFilters;
    };
    
    explicit ModelRegistry(const Config& config);
    ~ModelRegistry();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Model registration
    std::string RegisterModel(const std::string& name,
                                 const std::string& description = "");
    bool UnregisterModel(const std::string& name);
    
    // Version management
    std::string RegisterVersion(const ModelVersion::Config& config);
    bool UpdateVersion(const std::string& modelName, const std::string& version,
                       const ModelVersion::Config& config);
    bool DeleteVersion(const std::string& modelName, const std::string& version);
    std::optional<std::shared_ptr<ModelVersion>> GetVersion(
        const std::string& modelName, const std::string& version) const;
    
    // Version aliases
    bool SetAlias(const std::string& modelName, const std::string& alias,
                  const std::string& version);
    std::optional<std::string> ResolveAlias(const std::string& modelName,
                                             const std::string& alias) const;
    std::vector<std::pair<std::string, std::string>> GetAliases(
        const std::string& modelName) const;
    
    // Queries
    std::vector<std::string> ListModels() const;
    std::vector<std::shared_ptr<ModelVersion>> ListVersions(
        const std::string& modelName) const;
    std::vector<std::shared_ptr<ModelVersion>> Search(
        const SearchCriteria>& criteria) const;
    
    // Latest versions
    std::optional<std::shared_ptr<ModelVersion>> GetLatestVersion(
        const std::string& modelName) const;
    std::optional<std::shared_ptr<ModelVersion>> GetProductionVersion(
        const std::string& modelName) const;
    std::optional<std::shared_ptr<ModelVersion>> GetStagingVersion(
        const std::string& modelName) const;
    
    // Lineage
    struct LineageNode {
        std::string modelName;
        std::string version;
        std::string operation;  // training, fine-tuning, conversion
        std::vector<LineageNode> parents;
        std::vector<LineageNode> children;
    };
    LineageNode GetLineage(const std::string& modelName,
                           const std::string& version) const;
    void RecordLineage(const std::string& modelName, const std::string& version,
                       const std::vector<std::string>& parentVersions);
    
    // Comparison
    struct VersionComparison {
        std::string baselineVersion;
        std::string candidateVersion;
        std::vector<ModelVersion::Comparison> metricComparisons;
        bool isBetter;
        std::string recommendation;
    };
    VersionComparison CompareVersions(const std::string& modelName,
                                        const std::string& version1,
                                        const std::string& version2) const;
    
    // Import/Export
    bool ImportFromMlflow(const std::string& trackingUri,
                          const std::string& experimentId);
    bool ImportFromHuggingFace(const std::string& modelId);
    bool ExportToOnnx(const std::string& modelName, const std::string& version,
                      const std::string& outputPath);
    
    // Statistics
    struct RegistryStats {
        uint32_t totalModels;
        uint32_t totalVersions;
        uint32_t productionVersions;
        uint64_t totalStorageUsed;
        std::map<ModelFramework, uint32_t> modelsByFramework;
        std::map<ModelStatus, uint32_t> versionsByStatus;
    };
    RegistryStats GetStats() const;
    
private:
    Config config_;
    std::map<std::string, std::vector<std::shared_ptr<ModelVersion>>> models_;
    std::map<std::string, std::map<std::string, std::string>> aliases_;
    mutable std::mutex mutex_;
    
    std::string GenerateVersionId();
    bool PersistVersion(const ModelVersion& version);
    bool LoadVersion(const std::string& modelName, const std::string& version);
};

// ============================================================================
// Model Lifecycle Manager
// ============================================================================

/**
 * Manages model lifecycle transitions and policies.
 */
class ModelLifecycleManager {
public:
    struct Policy {
        uint32_t minVersionsToKeep;
        uint32_t maxVersionsToKeep;
        uint32_t daysInStagingBeforeProduction;
        uint32_t daysInProductionBeforeArchive;
        bool requireApprovalForProduction;
        bool requireValidationBeforeStaging;
        std::vector<std::string> requiredTags;
        std::map<std::string, double> minMetricsThresholds;
    };
    
    struct Transition {
        ModelStatus from;
        ModelStatus to;
        std::string approvedBy;
        std::chrono::system_clock::time_point timestamp;
        std::string reason;
    };
    
    explicit ModelLifecycleManager(std::shared_ptr<ModelRegistry> registry);
    
    // Policy management
    void SetPolicy(const Policy& policy);
    Policy GetPolicy() const;
    
    // Transitions
    bool CanTransition(const std::string& modelName, const std::string& version,
                       ModelStatus toStatus) const;
    bool RequestTransition(const std::string& modelName, const std::string& version,
                           ModelStatus toStatus, const std::string& requester);
    bool ApproveTransition(const std::string& modelName, const std::string& version,
                           ModelStatus toStatus, const std::string& approver);
    bool RejectTransition(const std::string& modelName, const std::string& version,
                          const std::string& reason);
    
    // Automated transitions
    void EnableAutoTransitions(bool enable);
    void ProcessAutoTransitions();
    
    // Cleanup
    std::vector<std::string> FindVersionsToArchive(const std::string& modelName);
    std::vector<std::string> FindVersionsToDelete(const std::string& modelName);
    bool ArchiveOldVersions(const std::string& modelName);
    bool CleanupDeletedVersions(const std::string& modelName);
    
    // History
    std::vector<Transition> GetTransitionHistory(const std::string& modelName,
                                                    const std::string& version) const;
    
    // Notifications
    void SetNotificationCallback(std::function<void(const Transition&)> callback);
    
private:
    std::shared_ptr<ModelRegistry> registry_;
    Policy policy_;
    bool autoTransitions_;
    std::function<void(const Transition&)> notificationCallback_;
    mutable std::mutex mutex_;
    
    bool ValidateTransition(const ModelVersion& version, ModelStatus toStatus);
    void ExecuteTransition(const std::string& modelName, const std::string& version,
                           ModelStatus toStatus);
};

// ============================================================================
// Model Validator
// ============================================================================

/**
 * Validates models before registration.
 */
class ModelValidator {
public:
    struct ValidationResult {
        bool passed;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
        std::map<std::string, std::string> metadata;
    };
    
    struct ValidationConfig {
        bool validateChecksum;
        bool validateFormat;
        bool validateSignature;
        bool runSanityCheck;
        bool checkSecurity;
        std::map<std::string, std::string> customValidators;
    };
    
    explicit ModelValidator(const ValidationConfig& config);
    
    // Validation
    ValidationResult Validate(const ModelVersion& version);
    ValidationResult ValidateArtifact(const ModelArtifact& artifact);
    
    // Specific validations
    bool ValidateChecksum(const ModelArtifact& artifact);
    bool ValidateFormat(const ModelArtifact& artifact);
    bool ValidateSignature(const ModelVersion& version);
    ValidationResult RunSanityCheck(const ModelVersion& version);
    ValidationResult SecurityCheck(const ModelVersion& version);
    
private:
    ValidationConfig config_;
    
    bool CheckFileIntegrity(const std::string& path, const std::string& expectedChecksum);
    bool VerifyModelFormat(const std::string& path, ModelFormat format);
};

} // namespace AI_ML
