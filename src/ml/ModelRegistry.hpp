// Phase O.1/5: Model Registry
// RawrXD Model Registry - Versioned model management

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <chrono>
#include <optional>

namespace RawrXD {
namespace ML {

// Model version following semantic versioning
struct ModelVersion {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    std::string prerelease;  // e.g., "alpha", "beta.1"
    std::string build_metadata;
    
    std::string ToString() const;
    static std::optional<ModelVersion> FromString(const std::string& version);
    bool operator==(const ModelVersion& other) const;
    bool operator<(const ModelVersion& other) const;
};

// Model artifact types
enum class ArtifactType {
    MODEL_WEIGHTS,      // Binary model weights
    CONFIGURATION,      // Model configuration JSON
    TOKENIZER,          // Tokenizer files
    VOCABULARY,         // Vocabulary files
    METADATA,           // Model metadata
    SAMPLE_DATA,        // Sample inputs/outputs
    DOCUMENTATION,      // Model documentation
    LICENSE_FILE        // License information
};

// Model artifact
struct ModelArtifact {
    std::string id;
    std::string name;
    ArtifactType type;
    std::string format;     // e.g., "gguf", "safetensors", "onnx"
    uint64_t size_bytes;
    std::string checksum;   // SHA-256
    std::string storage_path;
    std::string download_url;
    std::unordered_map<std::string, std::string> metadata;
    std::chrono::system_clock::time_point uploaded_at;
    std::string uploaded_by;
};

// Model stage in lifecycle
enum class ModelStage {
    DEVELOPMENT,    // Experimental, not ready for use
    STAGING,        // Testing, validation in progress
    PRODUCTION,     // Approved for production use
    DEPRECATED,     // Still available but not recommended
    ARCHIVED        // Retained for compliance but not usable
};

// Model definition
struct ModelDefinition {
    std::string id;                     // Unique model ID
    std::string name;                   // Human-readable name
    std::string description;
    std::string owner;                  // Team or individual
    std::vector<std::string> tags;
    
    // Versioning
    ModelVersion version;
    std::string base_model;             // Parent model if fine-tuned
    std::vector<std::string> aliases;  // e.g., "latest", "stable"
    
    // Artifacts
    std::vector<ModelArtifact> artifacts;
    ModelArtifact* GetArtifact(ArtifactType type);
    
    // Metadata
    struct ModelMetadata {
        std::string architecture;       // e.g., "llama", "gpt", "mistral"
        uint64_t parameter_count;
        std::string quantization;       // e.g., "Q4_K_M", "Q8_0"
        uint32_t context_length;
        std::vector<std::string> supported_languages;
        std::unordered_map<std::string, std::string> capabilities;
    } metadata;
    
    // Lifecycle
    ModelStage stage;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
    std::chrono::system_clock::time_point deprecated_at;
    
    // Usage
    uint64_t download_count;
    uint64_t inference_count;
    float average_rating;
    
    // Compliance
    std::string license;
    std::vector<std::string> approved_for;
    std::vector<std::string> restricted_for;
};

// Model lineage (training history)
struct ModelLineage {
    std::string model_id;
    std::string parent_model_id;
    std::vector<std::string> child_model_ids;
    std::string training_dataset;
    std::string training_config;
    std::vector<std::string> training_metrics;
    std::chrono::system_clock::time_point training_started;
    std::chrono::system_clock::time_point training_completed;
    std::string trained_by;
    float training_cost;
    std::unordered_map<std::string, std::string> hyperparameters;
};

// Model registry interface
class IModelRegistry {
public:
    virtual ~IModelRegistry() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& storage_path) = 0;
    virtual void Shutdown() = 0;
    
    // Model registration
    virtual bool RegisterModel(const ModelDefinition& model) = 0;
    virtual bool UpdateModel(const std::string& model_id, const ModelDefinition& model) = 0;
    virtual bool DeleteModel(const std::string& model_id) = 0;
    
    // Model retrieval
    virtual std::optional<ModelDefinition> GetModel(const std::string& model_id) = 0;
    virtual std::optional<ModelDefinition> GetModelByVersion(const std::string& name, 
                                                              const ModelVersion& version) = 0;
    virtual std::optional<ModelDefinition> GetModelByAlias(const std::string& name,
                                                            const std::string& alias) = 0;
    
    // Listing and search
    virtual std::vector<ModelDefinition> ListModels(const std::string& filter = "") = 0;
    virtual std::vector<ModelDefinition> ListModelsByStage(ModelStage stage) = 0;
    virtual std::vector<ModelDefinition> ListModelsByTag(const std::string& tag) = 0;
    virtual std::vector<ModelDefinition> SearchModels(const std::string& query) = 0;
    
    // Version management
    virtual std::vector<ModelVersion> GetModelVersions(const std::string& name) = 0;
    virtual bool SetModelAlias(const std::string& model_id, const std::string& alias) = 0;
    virtual bool PromoteModel(const std::string& model_id, ModelStage new_stage) = 0;
    
    // Artifact management
    virtual bool UploadArtifact(const std::string& model_id, const ModelArtifact& artifact) = 0;
    virtual bool DeleteArtifact(const std::string& model_id, const std::string& artifact_id) = 0;
    virtual std::optional<ModelArtifact> GetArtifact(const std::string& artifact_id) = 0;
    
    // Lineage tracking
    virtual bool RecordLineage(const ModelLineage& lineage) = 0;
    virtual std::optional<ModelLineage> GetLineage(const std::string& model_id) = 0;
    virtual std::vector<ModelLineage> GetModelFamily(const std::string& model_id) = 0;
    
    // Usage tracking
    virtual void RecordDownload(const std::string& model_id) = 0;
    virtual void RecordInference(const std::string& model_id) = 0;
    virtual void RecordRating(const std::string& model_id, float rating) = 0;
};

// Local file-based registry
class LocalModelRegistry : public IModelRegistry {
public:
    LocalModelRegistry();
    ~LocalModelRegistry() override;
    
    bool Initialize(const std::string& storage_path) override;
    void Shutdown() override;
    
    bool RegisterModel(const ModelDefinition& model) override;
    bool UpdateModel(const std::string& model_id, const ModelDefinition& model) override;
    bool DeleteModel(const std::string& model_id) override;
    
    std::optional<ModelDefinition> GetModel(const std::string& model_id) override;
    std::optional<ModelDefinition> GetModelByVersion(const std::string& name, 
                                                      const ModelVersion& version) override;
    std::optional<ModelDefinition> GetModelByAlias(const std::string& name,
                                                    const std::string& alias) override;
    
    std::vector<ModelDefinition> ListModels(const std::string& filter = "") override;
    std::vector<ModelDefinition> ListModelsByStage(ModelStage stage) override;
    std::vector<ModelDefinition> ListModelsByTag(const std::string& tag) override;
    std::vector<ModelDefinition> SearchModels(const std::string& query) override;
    
    std::vector<ModelVersion> GetModelVersions(const std::string& name) override;
    bool SetModelAlias(const std::string& model_id, const std::string& alias) override;
    bool PromoteModel(const std::string& model_id, ModelStage new_stage) override;
    
    bool UploadArtifact(const std::string& model_id, const ModelArtifact& artifact) override;
    bool DeleteArtifact(const std::string& model_id, const std::string& artifact_id) override;
    std::optional<ModelArtifact> GetArtifact(const std::string& artifact_id) override;
    
    bool RecordLineage(const ModelLineage& lineage) override;
    std::optional<ModelLineage> GetLineage(const std::string& model_id) override;
    std::vector<ModelLineage> GetModelFamily(const std::string& model_id) override;
    
    void RecordDownload(const std::string& model_id) override;
    void RecordInference(const std::string& model_id) override;
    void RecordRating(const std::string& model_id, float rating) override;
    
private:
    std::string storage_path_;
    std::unordered_map<std::string, ModelDefinition> models_;
    std::unordered_map<std::string, ModelLineage> lineages_;
    std::unordered_map<std::string, std::string> alias_map_;  // alias -> model_id
    bool initialized_ = false;
    
    bool SaveModel(const ModelDefinition& model);
    bool LoadModel(const std::string& model_id, ModelDefinition& model);
    std::string GetModelPath(const std::string& model_id);
};

// Remote registry (MLflow-style)
class RemoteModelRegistry : public IModelRegistry {
public:
    RemoteModelRegistry();
    ~RemoteModelRegistry() override;
    
    bool Initialize(const std::string& endpoint) override;
    void Shutdown() override;
    
    bool RegisterModel(const ModelDefinition& model) override;
    bool UpdateModel(const std::string& model_id, const ModelDefinition& model) override;
    bool DeleteModel(const std::string& model_id) override;
    
    std::optional<ModelDefinition> GetModel(const std::string& model_id) override;
    std::optional<ModelDefinition> GetModelByVersion(const std::string& name, 
                                                      const ModelVersion& version) override;
    std::optional<ModelDefinition> GetModelByAlias(const std::string& name,
                                                    const std::string& alias) override;
    
    std::vector<ModelDefinition> ListModels(const std::string& filter = "") override;
    std::vector<ModelDefinition> ListModelsByStage(ModelStage stage) override;
    std::vector<ModelDefinition> ListModelsByTag(const std::string& tag) override;
    std::vector<ModelDefinition> SearchModels(const std::string& query) override;
    
    std::vector<ModelVersion> GetModelVersions(const std::string& name) override;
    bool SetModelAlias(const std::string& model_id, const std::string& alias) override;
    bool PromoteModel(const std::string& model_id, ModelStage new_stage) override;
    
    bool UploadArtifact(const std::string& model_id, const ModelArtifact& artifact) override;
    bool DeleteArtifact(const std::string& model_id, const std::string& artifact_id) override;
    std::optional<ModelArtifact> GetArtifact(const std::string& artifact_id) override;
    
    bool RecordLineage(const ModelLineage& lineage) override;
    std::optional<ModelLineage> GetLineage(const std::string& model_id) override;
    std::vector<ModelLineage> GetModelFamily(const std::string& model_id) override;
    
    void RecordDownload(const std::string& model_id) override;
    void RecordInference(const std::string& model_id) override;
    void RecordRating(const std::string& model_id, float rating) override;
    
private:
    std::string endpoint_;
    std::string api_key_;
    bool initialized_ = false;
};

// Model validation
class ModelValidator {
public:
    struct ValidationResult {
        bool valid;
        std::vector<std::string> errors;
        std::vector<std::string> warnings;
    };
    
    static ValidationResult ValidateModel(const ModelDefinition& model);
    static ValidationResult ValidateArtifact(const ModelArtifact& artifact);
    static bool VerifyChecksum(const std::string& file_path, const std::string& expected_checksum);
    
    // Security checks
    static ValidationResult SecurityScan(const std::string& model_path);
    static bool CheckForMaliciousCode(const std::string& model_path);
};

// Global model registry
extern std::unique_ptr<IModelRegistry> g_model_registry;

// Initialize model registry
bool InitializeModelRegistry(const std::string& config);
void ShutdownModelRegistry();
bool IsModelRegistryEnabled();

} // namespace ML
} // namespace RawrXD
