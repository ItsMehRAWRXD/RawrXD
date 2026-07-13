// Phase T.2/5: Collective Intelligence
// RawrXD Collective Intelligence - Emergent intelligence from distributed instances

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace Meta {

// Knowledge contribution from an instance
struct KnowledgeContribution {
    std::string contribution_id;
    std::string instance_id;
    std::chrono::system_clock::time_point timestamp;
    
    // Content
    std::string knowledge_type;  // "pattern", "insight", "solution", "prediction"
    std::string content;
    std::unordered_map<std::string, std::string> metadata;
    
    // Evidence
    std::vector<std::string> supporting_data;
    double confidence;
    uint32_t verification_count;
    
    // Validation
    bool is_validated;
    std::vector<std::string> validating_instances;
    double collective_confidence;
};

// Shared learning model
struct SharedModel {
    std::string model_id;
    std::string name;
    std::string model_type;
    
    // Contributors
    std::vector<std::string> contributing_instances;
    std::unordered_map<std::string, double> contribution_weights;
    
    // Performance
    double accuracy;
    double precision;
    double recall;
    double f1_score;
    
    // Distribution
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_updated;
    uint32_t distribution_count;
    std::vector<std::string> distributed_to;
    
    // Status
    enum class Status {
        TRAINING,
        VALIDATING,
        ACTIVE,
        DEPRECATED
    } status;
};

// Collective decision
struct CollectiveDecision {
    std::string decision_id;
    std::string decision_type;
    std::string context;
    
    // Proposals from instances
    struct Proposal {
        std::string instance_id;
        std::string proposed_action;
        double confidence;
        std::string rationale;
    };
    std::vector<Proposal> proposals;
    
    // Aggregation
    std::string final_decision;
    double collective_confidence;
    std::vector<std::string> supporting_instances;
    std::vector<std::string> dissenting_instances;
    
    // Consensus
    double consensus_level;  // 0.0 to 1.0
    bool is_unanimous;
    
    // Execution
    std::chrono::system_clock::time_point decided_at;
    bool executed;
    std::chrono::system_clock::time_point executed_at;
    bool outcome_successful;
};

// Emergent pattern
struct EmergentPattern {
    std::string pattern_id;
    std::string name;
    std::string description;
    
    // Discovery
    std::chrono::system_clock::time_point discovered_at;
    std::vector<std::string> discovering_instances;
    
    // Pattern data
    std::string pattern_type;
    std::unordered_map<std::string, std::string> pattern_data;
    std::vector<std::string> examples;
    
    // Validation
    uint32_t occurrence_count;
    double confidence;
    bool is_validated;
    std::vector<std::string> validating_instances;
    
    // Utility
    bool is_actionable;
    std::vector<std::string> recommended_actions;
    double expected_value;
};

// Collective intelligence manager
class ICollectiveIntelligence {
public:
    virtual ~ICollectiveIntelligence() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Knowledge sharing
    virtual std::string ContributeKnowledge(const KnowledgeContribution& contribution) = 0;
    virtual std::vector<KnowledgeContribution> QueryKnowledge(const std::string& query) = 0;
    virtual bool ValidateKnowledge(const std::string& contribution_id, const std::string& instance_id) = 0;
    virtual std::vector<KnowledgeContribution> GetValidatedKnowledge() = 0;
    
    // Shared learning
    virtual std::string SubmitModelUpdate(const std::string& instance_id,
                                           const std::string& model_id,
                                           const std::vector<uint8_t>& model_delta) = 0;
    virtual bool AggregateModels(const std::string& base_model_id) = 0;
    virtual std::optional<SharedModel> GetSharedModel(const std::string& model_id) = 0;
    virtual std::vector<SharedModel> ListSharedModels() = 0;
    virtual bool DistributeModel(const std::string& model_id,
                                    const std::vector<std::string>& target_instances) = 0;
    
    // Collective decision making
    virtual std::string ProposeDecision(const std::string& instance_id,
                                         const std::string& decision_type,
                                         const std::string& proposed_action,
                                         double confidence) = 0;
    virtual bool VoteOnDecision(const std::string& decision_id,
                                 const std::string& instance_id,
                                 const std::string& vote,
                                 double confidence) = 0;
    virtual std::optional<CollectiveDecision> GetDecision(const std::string& decision_id) = 0;
    virtual std::optional<CollectiveDecision> GetCollectiveDecision(const std::string& context) = 0;
    virtual std::vector<CollectiveDecision> GetDecisionHistory() = 0;
    
    // Emergent pattern discovery
    virtual std::vector<EmergentPattern> DiscoverPatterns() = 0;
    virtual std::string ReportPattern(const std::string& instance_id,
                                         const EmergentPattern& pattern) = 0;
    virtual bool ValidatePattern(const std::string& pattern_id,
                                  const std::string& instance_id) = 0;
    virtual std::vector<EmergentPattern> GetActivePatterns() = 0;
    
    // Intelligence metrics
    virtual struct IntelligenceMetrics {
        uint32_t knowledge_contributions;
        uint32_t validated_knowledge;
        uint32_t shared_models;
        uint32_t collective_decisions;
        uint32_t emergent_patterns;
        double average_consensus_level;
        double collective_accuracy;
        uint32_t active_contributors;
    } GetMetrics() = 0;
};

// Local collective intelligence
class LocalCollectiveIntelligence : public ICollectiveIntelligence {
public:
    LocalCollectiveIntelligence();
    ~LocalCollectiveIntelligence() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string ContributeKnowledge(const KnowledgeContribution& contribution) override;
    std::vector<KnowledgeContribution> QueryKnowledge(const std::string& query) override;
    bool ValidateKnowledge(const std::string& contribution_id, const std::string& instance_id) override;
    std::vector<KnowledgeContribution> GetValidatedKnowledge() override;
    
    std::string SubmitModelUpdate(const std::string& instance_id,
                                   const std::string& model_id,
                                   const std::vector<uint8_t>& model_delta) override;
    bool AggregateModels(const std::string& base_model_id) override;
    std::optional<SharedModel> GetSharedModel(const std::string& model_id) override;
    std::vector<SharedModel> ListSharedModels() override;
    bool DistributeModel(const std::string& model_id,
                          const std::vector<std::string>& target_instances) override;
    
    std::string ProposeDecision(const std::string& instance_id,
                                 const std::string& decision_type,
                                 const std::string& proposed_action,
                                 double confidence) override;
    bool VoteOnDecision(const std::string& decision_id,
                         const std::string& instance_id,
                         const std::string& vote,
                         double confidence) override;
    std::optional<CollectiveDecision> GetDecision(const std::string& decision_id) override;
    std::optional<CollectiveDecision> GetCollectiveDecision(const std::string& context) override;
    std::vector<CollectiveDecision> GetDecisionHistory() override;
    
    std::vector<EmergentPattern> DiscoverPatterns() override;
    std::string ReportPattern(const std::string& instance_id,
                               const EmergentPattern& pattern) override;
    bool ValidatePattern(const std::string& pattern_id,
                          const std::string& instance_id) override;
    std::vector<EmergentPattern> GetActivePatterns() override;
    
    IntelligenceMetrics GetMetrics() override;
    
private:
    std::unordered_map<std::string, KnowledgeContribution> knowledge_;
    std::unordered_map<std::string, SharedModel> models_;
    std::unordered_map<std::string, CollectiveDecision> decisions_;
    std::unordered_map<std::string, EmergentPattern> patterns_;
    bool initialized_ = false;
    
    double CalculateConsensus(const CollectiveDecision& decision);
    std::string AggregateProposals(const std::vector<CollectiveDecision::Proposal>& proposals);
    bool ValidatePatternData(const EmergentPattern& pattern);
};

// Global collective intelligence
extern std::unique_ptr<ICollectiveIntelligence> g_collective_intelligence;

// Initialize collective intelligence
bool InitializeCollectiveIntelligence(const std::string& config_path);
void ShutdownCollectiveIntelligence();
bool IsCollectiveIntelligenceEnabled();

} // namespace Meta
} // namespace RawrXD
