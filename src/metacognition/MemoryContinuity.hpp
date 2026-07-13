// Phase V.3/5: Persistent Cognitive Memory
// RawrXD Memory Continuity - Long-term knowledge and experience storage

#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <optional>
#include <unordered_map>

namespace RawrXD {
namespace MetaCognition {

// Memory tier types
enum class MemoryTier {
    SHORT_TERM,     // Working memory, seconds to minutes
    WORKING,        // Active context, minutes to hours
    LONG_TERM,      // Persistent knowledge, days to years
    EPISODIC        // Event-based experiences
};

// Memory entry
struct MemoryEntry {
    std::string memory_id;
    MemoryTier tier;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_accessed;
    std::chrono::system_clock::time_point expires_at;
    
    // Content
    std::string content_type;  // "fact", "experience", "strategy", "decision"
    std::string content;
    std::vector<uint8_t> embedding;
    
    // Context
    std::unordered_map<std::string, std::string> context;
    std::vector<std::string> tags;
    std::vector<std::string> related_memories;
    
    // Provenance
    std::string source;
    std::string agent_id;
    std::string task_id;
    double confidence;
    uint32_t verification_count;
    
    // Access patterns
    uint32_t access_count;
    double importance_score;
    bool is_consolidated;
};

// Experience record
struct Experience {
    std::string experience_id;
    std::string experience_type;  // "success", "failure", "learning", "observation"
    
    // Situation
    std::string situation_description;
    std::unordered_map<std::string, std::string> initial_state;
    
    // Action
    std::string action_taken;
    std::string reasoning;
    std::vector<std::string> alternatives_considered;
    
    // Outcome
    std::string outcome;
    bool was_successful;
    double outcome_value;
    std::chrono::milliseconds time_to_outcome;
    
    // Learning
    std::vector<std::string> lessons_learned;
    std::vector<std::string> what_worked;
    std::vector<std::string> what_failed;
    
    // Temporal
    std::chrono::system_clock::time_point experienced_at;
    std::chrono::system_clock::time_point consolidated_at;
};

// Strategy memory
struct Strategy {
    std::string strategy_id;
    std::string name;
    std::string description;
    
    // Applicability
    std::vector<std::string> applicable_situations;
    std::vector<std::string> required_capabilities;
    std::unordered_map<std::string, std::string> preconditions;
    
    // Execution
    std::string execution_plan;
    std::vector<std::string> steps;
    
    // Performance
    uint32_t times_applied;
    uint32_t times_successful;
    double success_rate;
    double average_execution_time_ms;
    
    // Evolution
    std::string parent_strategy_id;
    std::vector<std::string> child_strategy_ids;
    uint32_t generation;
    bool is_deprecated;
};

// Decision record
struct DecisionRecord {
    std::string decision_id;
    std::chrono::system_clock::time_point decided_at;
    
    // Context
    std::string situation;
    std::vector<std::string> available_options;
    std::unordered_map<std::string, double> option_scores;
    
    // Decision
    std::string chosen_option;
    std::string reasoning;
    double confidence;
    
    // Outcome
    std::string actual_outcome;
    bool outcome_matches_expectation;
    double outcome_quality;
    
    // Reflection
    bool would_choose_differently;
    std::string better_option;
    std::string lessons;
};

// Memory continuity interface
class IMemoryContinuity {
public:
    virtual ~IMemoryContinuity() = default;
    
    // Initialization
    virtual bool Initialize(const std::string& config_path) = 0;
    virtual void Shutdown() = 0;
    
    // Memory storage
    virtual std::string StoreMemory(const MemoryEntry& entry) = 0;
    virtual bool UpdateMemory(const MemoryEntry& entry) = 0;
    virtual bool DeleteMemory(const std::string& memory_id) = 0;
    virtual std::optional<MemoryEntry> RetrieveMemory(const std::string& memory_id) = 0;
    
    // Tier management
    virtual bool PromoteToLongTerm(const std::string& memory_id) = 0;
    virtual bool DemoteToShortTerm(const std::string& memory_id) = 0;
    virtual std::vector<MemoryEntry> GetMemoriesByTier(MemoryTier tier) = 0;
    virtual bool ConsolidateMemory(const std::string& memory_id) = 0;
    
    // Experience storage
    virtual std::string RecordExperience(const Experience& experience) = 0;
    virtual std::vector<Experience> GetSimilarExperiences(const std::string& situation) = 0;
    virtual std::vector<Experience> GetSuccessfulStrategies(const std::string& situation_type) = 0;
    
    // Strategy management
    virtual std::string StoreStrategy(const Strategy& strategy) = 0;
    virtual bool UpdateStrategy(const Strategy& strategy) = 0;
    virtual std::optional<Strategy> GetStrategy(const std::string& strategy_id) = 0;
    virtual std::vector<Strategy> FindApplicableStrategies(const std::string& situation) = 0;
    virtual bool MarkStrategySuccess(const std::string& strategy_id) = 0;
    virtual bool MarkStrategyFailure(const std::string& strategy_id) = 0;
    virtual std::string EvolveStrategy(const std::string& strategy_id, const std::string& modification) = 0;
    
    // Decision tracking
    virtual std::string RecordDecision(const DecisionRecord& decision) = 0;
    virtual std::vector<DecisionRecord> GetDecisionHistory(const std::string& situation_type = "") = 0;
    virtual std::optional<DecisionRecord> GetBestDecision(const std::string& situation) = 0;
    
    // Retrieval
    virtual std::vector<MemoryEntry> QueryMemories(const std::string& query, MemoryTier tier = MemoryTier::LONG_TERM) = 0;
    virtual std::vector<MemoryEntry> RetrieveByContext(const std::unordered_map<std::string, std::string>& context) = 0;
    virtual std::vector<MemoryEntry> RetrieveByTags(const std::vector<std::string>& tags) = 0;
    
    // Forgetting
    virtual bool SetExpiration(const std::string& memory_id, std::chrono::system_clock::time_point expires_at) = 0;
    virtual bool ForgetExpiredMemories() = 0;
    virtual bool ForgetLowImportanceMemories(double threshold) = 0;
    
    // Statistics
    virtual struct MemoryStatistics {
        uint64_t total_memories;
        uint64_t short_term_memories;
        uint64_t long_term_memories;
        uint64_t experiences_recorded;
        uint64_t strategies_stored;
        uint64_t decisions_recorded;
        double average_retrieval_time_ms;
        double memory_consolidation_rate;
    } GetStatistics() = 0;
};

// Local memory continuity
class LocalMemoryContinuity : public IMemoryContinuity {
public:
    LocalMemoryContinuity();
    ~LocalMemoryContinuity() override;
    
    bool Initialize(const std::string& config_path) override;
    void Shutdown() override;
    
    std::string StoreMemory(const MemoryEntry& entry) override;
    bool UpdateMemory(const MemoryEntry& entry) override;
    bool DeleteMemory(const std::string& memory_id) override;
    std::optional<MemoryEntry> RetrieveMemory(const std::string& memory_id) override;
    
    bool PromoteToLongTerm(const std::string& memory_id) override;
    bool DemoteToShortTerm(const std::string& memory_id) override;
    std::vector<MemoryEntry> GetMemoriesByTier(MemoryTier tier) override;
    bool ConsolidateMemory(const std::string& memory_id) override;
    
    std::string RecordExperience(const Experience& experience) override;
    std::vector<Experience> GetSimilarExperiences(const std::string& situation) override;
    std::vector<Experience> GetSuccessfulStrategies(const std::string& situation_type) override;
    
    std::string StoreStrategy(const Strategy& strategy) override;
    bool UpdateStrategy(const Strategy& strategy) override;
    std::optional<Strategy> GetStrategy(const std::string& strategy_id) override;
    std::vector<Strategy> FindApplicableStrategies(const std::string& situation) override;
    bool MarkStrategySuccess(const std::string& strategy_id) override;
    bool MarkStrategyFailure(const std::string& strategy_id) override;
    std::string EvolveStrategy(const std::string& strategy_id, const std::string& modification) override;
    
    std::string RecordDecision(const DecisionRecord& decision) override;
    std::vector<DecisionRecord> GetDecisionHistory(const std::string& situation_type = "") override;
    std::optional<DecisionRecord> GetBestDecision(const std::string& situation) override;
    
    std::vector<MemoryEntry> QueryMemories(const std::string& query, MemoryTier tier = MemoryTier::LONG_TERM) override;
    std::vector<MemoryEntry> RetrieveByContext(const std::unordered_map<std::string, std::string>& context) override;
    std::vector<MemoryEntry> RetrieveByTags(const std::vector<std::string>& tags) override;
    
    bool SetExpiration(const std::string& memory_id, std::chrono::system_clock::time_point expires_at) override;
    bool ForgetExpiredMemories() override;
    bool ForgetLowImportanceMemories(double threshold) override;
    
    MemoryStatistics GetStatistics() override;
    
private:
    std::unordered_map<std::string, MemoryEntry> memories_;
    std::unordered_map<std::string, Experience> experiences_;
    std::unordered_map<std::string, Strategy> strategies_;
    std::unordered_map<std::string, DecisionRecord> decisions_;
    bool initialized_ = false;
    
    double CalculateSimilarity(const MemoryEntry& m1, const MemoryEntry& m2);
    double CalculateImportance(const MemoryEntry& entry);
    bool ShouldConsolidate(const MemoryEntry& entry);
    void UpdateStrategyPerformance(Strategy& strategy, bool success);
};

// Global memory continuity
extern std::unique_ptr<IMemoryContinuity> g_memory_continuity;

// Initialize memory continuity
bool InitializeMemoryContinuity(const std::string& config_path);
void ShutdownMemoryContinuity();
bool IsMemoryContinuityEnabled();

// Memory tier helpers
std::string MemoryTierToString(MemoryTier tier);
MemoryTier MemoryTierFromString(const std::string& str);

} // namespace MetaCognition
} // namespace RawrXD
