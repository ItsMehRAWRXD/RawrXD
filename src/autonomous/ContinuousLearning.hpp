// Phase R.2/5: Continuous Learning System
// RawrXD Continuous Learning - Self-improving through experience

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Autonomous {

// Learning data types
enum class LearningDataType {
    METRIC_TIME_SERIES,     // Historical metrics
    DECISION_OUTCOME,       // Decision results
    USER_FEEDBACK,          // Human feedback
    SYSTEM_EVENT,           // System events
    PERFORMANCE_TRACE,      // Performance data
    ERROR_PATTERN,          // Error patterns
    USAGE_PATTERN,          // Usage patterns
    EXTERNAL_DATA           // External sources
};

// Learning objective
enum class LearningObjective {
    IMPROVE_ACCURACY,       // Better predictions
    REDUCE_LATENCY,         // Faster responses
    OPTIMIZE_RESOURCES,     // Resource efficiency
    ENHANCE_RELIABILITY,    // Fewer failures
    MINIMIZE_COSTS,         // Cost reduction
    IMPROVE_USER_EXPERIENCE, // Better UX
    INCREASE_AUTONOMY,      // More autonomous
    CUSTOM_OBJECTIVE        // Custom goal
};

// Experience record
struct ExperienceRecord {
    std::string id;
    std::chrono::system_clock::time_point timestamp;
    
    // Context
    LearningDataType data_type;
    std::unordered_map<std::string, std::string> context;
    std::unordered_map<std::string, double> metrics;
    
    // Observation
    std::vector<double> features;
    std::string observation;
    
    // Outcome
    std::string action_taken;
    double reward;
    bool was_successful;
    std::vector<std::string> outcomes;
    
    // Feedback
    std::string user_feedback;
    double user_rating;
    
    // Metadata
    std::string source_system;
    std::string related_decision_id;
    std::vector<std::string> tags;
};

// Model version
struct ModelVersion {
    std::string id;
    std::string name;
    std::string description;
    
    // Version info
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t patch_version;
    std::string git_commit;
    
    // Training
    std::chrono::system_clock::time_point trained_at;
    std::chrono::system_clock::time_point deployed_at;
    uint64_t training_samples;
    std::chrono::seconds training_duration;
    
    // Performance
    double accuracy;
    double precision;
    double recall;
    double f1_score;
    double latency_ms;
    
    // Status
    enum class Status {
        TRAINING,
        VALIDATING,
        READY,
        DEPLOYED,
        ROLLED_BACK,
        DEPRECATED
    } status;
    
    // Comparison to previous
    double accuracy_improvement;
    double latency_improvement;
};

// Learning pipeline
struct LearningPipeline {
    std::string id;
    std::string name;
    std::string description;
    
    // Data sources
    std::vector<std::string> data_source_ids;
    std::string data_query;
    std::chrono::seconds lookback_period;
    
    // Preprocessing
    std::vector<std::string> preprocessing_steps;
    std::unordered_map<std::string, std::string> preprocessing_config;
    
    // Model
    std::string model_type;  // e.g., "neural_network", "random_forest"
    std::unordered_map<std::string, std::string> model_hyperparameters;
    
    // Training
    LearningObjective objective;
    std::chrono::seconds training_frequency;
    uint64_t min_samples_required;
    double min_improvement_threshold;
    
    // Validation
    double validation_split;
    std::vector<std::string> validation_metrics;
    double min_acceptable_score;
    
    // Deployment
    bool auto_deploy;
    bool shadow_mode_first;
    std::chrono::seconds shadow_mode_duration;
    double deployment_threshold;
    
    // State
    bool enabled;
    std::string current_model_id;
    std::string candidate_model_id;
    std::chrono::system_clock::time_point last_trained;
    uint32_t training_count;
    uint32_t deployment_count;
};

// Knowledge graph node
struct KnowledgeNode {
    std::string id;
    std::string type;
    std::string name;
    std::unordered_map<std::string, std::string> properties;
    std::vector<std::string> related_nodes;
    double confidence;
    std::chrono::system_clock::time_point learned_at;
    uint32_t verification_count;
};

// Pattern discovery result
struct DiscoveredPattern {
    std::string id;
    std::string name;
    std::string description;
    
    // Pattern definition
    std::vector<std::string> conditions;
    std::string implication;
    double confidence;
    
    // Evidence
    uint64_t occurrence_count;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    std::vector<std::string> example_instances;
    
    // Utility
    bool is_actionable;
    std::vector<std::string> recommended_actions;
    double expected_value;
};

// Continuous learning manager interface
class IContinuousLearningManager {
public:
    virtual ~IContinuousLearningManager() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Experience recording
    virtual std::string RecordExperience(const ExperienceRecord& record) = 0;
    virtual std::vector<ExperienceRecord> GetExperiences(
        const std::string& filter = "",
        std::chrono::hours lookback = std::chrono::hours(168)) = 0;
    virtual bool UpdateExperience(const ExperienceRecord& record) = 0;
    
    // Pipeline management
    virtual std::string CreatePipeline(const LearningPipeline& pipeline) = 0;
    virtual bool UpdatePipeline(const LearningPipeline& pipeline) = 0;
    virtual bool DeletePipeline(const std::string& pipeline_id) = 0;
    virtual std::optional<LearningPipeline> GetPipeline(const std::string& pipeline_id) = 0;
    virtual std::vector<LearningPipeline> ListPipelines() = 0;
    virtual bool EnablePipeline(const std::string& pipeline_id) = 0;
    virtual bool DisablePipeline(const std::string& pipeline_id) = 0;
    
    // Training
    virtual std::string TriggerTraining(const std::string& pipeline_id) = 0;
    virtual bool CancelTraining(const std::string& training_id) = 0;
    virtual std::optional<ModelVersion> GetTrainingStatus(const std::string& training_id) = 0;
    
    // Model management
    virtual std::vector<ModelVersion> ListModels(const std::string& pipeline_id = "") = 0;
    virtual std::optional<ModelVersion> GetCurrentModel(const std::string& pipeline_id) = 0;
    virtual bool DeployModel(const std::string& model_id) = 0;
    virtual bool RollbackModel(const std::string& pipeline_id) = 0;
    virtual bool PromoteFromShadow(const std::string& model_id) = 0;
    
    // Knowledge graph
    virtual std::string AddKnowledgeNode(const KnowledgeNode& node) = 0;
    virtual std::vector<KnowledgeNode> QueryKnowledge(const std::string& query) = 0;
    virtual std::vector<KnowledgeNode> FindRelated(const std::string& node_id) = 0;
    virtual bool VerifyKnowledge(const std::string& node_id, bool is_correct) = 0;
    
    // Pattern discovery
    virtual std::vector<DiscoveredPattern> DiscoverPatterns(
        const std::string& data_source = "",
        std::chrono::hours lookback = std::chrono::hours(168)) = 0;
    virtual bool AcceptPattern(const std::string& pattern_id) = 0;
    virtual bool RejectPattern(const std::string& pattern_id) = 0;
    virtual std::vector<DiscoveredPattern> GetActivePatterns() = 0;
    
    // Feedback integration
    virtual bool SubmitFeedback(const std::string& decision_id,
                                 double rating,
                                 const std::string& feedback) = 0;
    virtual bool SubmitCorrection(const std::string& decision_id,
                                   const std::string& correct_action) = 0;
    
    // Statistics
    virtual struct LearningStatistics {
        uint64_t total_experiences;
        uint64_t experiences_last_24h;
        uint32_t active_pipelines;
        uint32_t models_trained;
        uint32_t models_deployed;
        double average_model_accuracy;
        uint32_t patterns_discovered;
        uint32_t patterns_accepted;
        uint64_t knowledge_nodes;
        double learning_rate;
    } GetStatistics() = 0;
};

// Local continuous learning manager
class LocalContinuousLearningManager : public IContinuousLearningManager {
public:
    LocalContinuousLearningManager();
    ~LocalContinuousLearningManager() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string RecordExperience(const ExperienceRecord& record) override;
    std::vector<ExperienceRecord> GetExperiences(
        const std::string& filter = "",
        std::chrono::hours lookback = std::chrono::hours(168)) override;
    bool UpdateExperience(const ExperienceRecord& record) override;
    
    std::string CreatePipeline(const LearningPipeline& pipeline) override;
    bool UpdatePipeline(const LearningPipeline& pipeline) override;
    bool DeletePipeline(const std::string& pipeline_id) override;
    std::optional<LearningPipeline> GetPipeline(const std::string& pipeline_id) override;
    std::vector<LearningPipeline> ListPipelines() override;
    bool EnablePipeline(const std::string& pipeline_id) override;
    bool DisablePipeline(const std::string& pipeline_id) override;
    
    std::string TriggerTraining(const std::string& pipeline_id) override;
    bool CancelTraining(const std::string& training_id) override;
    std::optional<ModelVersion> GetTrainingStatus(const std::string& training_id) override;
    
    std::vector<ModelVersion> ListModels(const std::string& pipeline_id = "") override;
    std::optional<ModelVersion> GetCurrentModel(const std::string& pipeline_id) override;
    bool DeployModel(const std::string& model_id) override;
    bool RollbackModel(const std::string& pipeline_id) override;
    bool PromoteFromShadow(const std::string& model_id) override;
    
    std::string AddKnowledgeNode(const KnowledgeNode& node) override;
    std::vector<KnowledgeNode> QueryKnowledge(const std::string& query) override;
    std::vector<KnowledgeNode> FindRelated(const std::string& node_id) override;
    bool VerifyKnowledge(const std::string& node_id, bool is_correct) override;
    
    std::vector<DiscoveredPattern> DiscoverPatterns(
        const std::string& data_source = "",
        std::chrono::hours lookback = std::chrono::hours(168)) override;
    bool AcceptPattern(const std::string& pattern_id) override;
    bool RejectPattern(const std::string& pattern_id) override;
    std::vector<DiscoveredPattern> GetActivePatterns() override;
    
    bool SubmitFeedback(const std::string& decision_id,
                        double rating,
                        const std::string& feedback) override;
    bool SubmitCorrection(const std::string& decision_id,
                           const std::string& correct_action) override;
    
    LearningStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, ExperienceRecord> experiences_;
    std::unordered_map<std::string, LearningPipeline> pipelines_;
    std::unordered_map<std::string, ModelVersion> models_;
    std::unordered_map<std::string, KnowledgeNode> knowledge_nodes_;
    std::unordered_map<std::string, DiscoveredPattern> patterns_;
    bool initialized_ = false;
    
    bool PreprocessData(const std::vector<ExperienceRecord>& data,
                        std::vector<std::vector<double>>& features,
                        std::vector<double>& labels);
    bool TrainModel(const LearningPipeline& pipeline,
                    const std::vector<std::vector<double>>& features,
                    const std::vector<double>& labels,
                    ModelVersion& model);
    bool ValidateModel(const ModelVersion& model);
    std::vector<DiscoveredPattern> MinePatterns(const std::vector<ExperienceRecord>& data);
};

// Experience replay buffer
class ExperienceReplayBuffer {
public:
    void AddExperience(const ExperienceRecord& record);
    std::vector<ExperienceRecord> Sample(uint32_t batch_size);
    void Clear();
    size_t Size() const;
    
    // Prioritized replay
    void SetPriority(const std::string& record_id, double priority);
    std::vector<ExperienceRecord> SamplePrioritized(uint32_t batch_size);
    
private:
    std::vector<ExperienceRecord> buffer_;
    std::unordered_map<std::string, double> priorities_;
    size_t max_size_ = 100000;
};

// Feature extractor
class FeatureExtractor {
public:
    struct FeatureSet {
        std::vector<double> numerical;
        std::vector<std::string> categorical;
        std::unordered_map<std::string, double> engineered;
    };
    
    FeatureSet Extract(const ExperienceRecord& record);
    std::vector<double> Vectorize(const FeatureSet& features);
    
    // Feature engineering
    void AddFeatureEngineeringRule(const std::string& name,
                                      std::function<double(const ExperienceRecord&)> rule);
    void RemoveFeatureEngineeringRule(const std::string& name);
    
private:
    std::unordered_map<std::string, std::function<double(const ExperienceRecord&)>> engineering_rules_;
};

// Global learning manager
extern std::unique_ptr<IContinuousLearningManager> g_continuous_learning_manager;

// Initialize continuous learning
bool InitializeContinuousLearning(const std::string& config_path);
void ShutdownContinuousLearning();
bool IsContinuousLearningEnabled();

} // namespace Autonomous
} // namespace RawrXD
