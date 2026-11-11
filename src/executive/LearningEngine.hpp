// ============================================================
// LearningEngine.hpp - Experience-Driven Improvement
// Every mission improves future missions
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <atomic>

namespace RawrXD::Executive {

class ExecutiveDirector;
class CognitiveMemory;

// ============================================================
// Learned Pattern
// ============================================================
struct LearnedPattern {
    uint64_t patternId;
    std::string patternType;
    std::string description;
    std::string domain;
    
    std::string triggerCondition;
    std::string action;
    std::string expectedOutcome;
    
    int successCount = 0;
    int failureCount = 0;
    float confidence = 0.0f;
    std::vector<uint64_t> sourceEpisodeIds;
    
    uint64_t learnedAtMs = 0;
    uint64_t lastAppliedMs = 0;
    int timesApplied = 0;
};

// ============================================================
// Workflow Improvement
// ============================================================
struct WorkflowImprovement {
    uint64_t originalWorkflowId;
    uint64_t improvedWorkflowId;
    std::string improvementType;
    std::string changeDescription;
    float estimatedSpeedup = 0.0f;
    float estimatedReliabilityImprovement = 0.0f;
    
    bool isValidated = false;
    int validationSuccesses = 0;
    int validationFailures = 0;
};

// ============================================================
// Performance Model
// ============================================================
struct PerformanceModel {
    uint64_t targetId;
    std::string targetType;
    
    float predictedSuccessRate = 0.5f;
    double predictedExecutionTimeMs = 0.0;
    float predictedResourceUsage = 1.0f;
    
    float modelConfidence = 0.0f;
    int dataPoints = 0;
};

// ============================================================
// Learning Engine
// ============================================================
class LearningEngine {
public:
    LearningEngine() = default;
    ~LearningEngine() = default;

    bool initialize(ExecutiveDirector* director, CognitiveMemory* memory);
    void shutdown();
    
    void learnFromMission(uint64_t missionId);
    std::vector<LearnedPattern> extractPatterns(uint64_t missionId);
    void validatePattern(uint64_t patternId);
    void applyPattern(uint64_t patternId);
    
    WorkflowImprovement suggestImprovement(uint64_t workflowId);
    bool validateImprovement(uint64_t improvementId);
    void deployImprovement(uint64_t improvementId);
    
    void updatePerformanceModel(uint64_t targetId, bool success, double executionTimeMs);
    PerformanceModel getPerformanceModel(uint64_t targetId);
    float predictSuccessProbability(uint64_t targetId, 
                                    const std::unordered_map<std::string, std::string>& context);
    
    void generalizeFromSpecific(uint64_t specificEpisodeId);
    void transferKnowledge(const std::string& fromDomain, const std::string& toDomain);
    std::vector<std::string> identifyKnowledgeGaps();
    std::string suggestExplorationTask();
    
    struct Stats {
        size_t patternsLearned = 0;
        size_t patternsValidated = 0;
        size_t workflowsImproved = 0;
        size_t performanceModels = 0;
    };
    Stats getStats() const;

private:
    ExecutiveDirector* director_ = nullptr;
    CognitiveMemory* memory_ = nullptr;
    
    std::unordered_map<uint64_t, LearnedPattern> patterns_;
    std::unordered_map<uint64_t, WorkflowImprovement> improvements_;
    std::unordered_map<uint64_t, PerformanceModel> models_;
    
    std::atomic<uint64_t> nextPatternId_{1};
    std::atomic<uint64_t> nextImprovementId_{1};
    
    mutable std::mutex mutex_;
    
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
