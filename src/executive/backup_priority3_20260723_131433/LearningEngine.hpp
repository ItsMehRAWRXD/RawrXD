// ============================================================================
// LearningEngine.hpp - Experience-Driven Improvement
// Every mission improves future missions
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Executive {

// Forward declarations
class ExecutiveDirector;
class CognitiveMemory;

// ============================================================================
// Pattern Extraction
// ============================================================================
struct LearnedPattern {
    std::string patternId;
    std::string patternType;       // "workflow", "heuristic", "anti_pattern"
    std::string description;
    std::string domain;
    
    // The pattern itself
    std::string triggerCondition;    // When to apply
    std::string action;            // What to do
    std::string expectedOutcome;
    
    // Evidence
    int successCount = 0;
    int failureCount = 0;
    float confidence = 0.0f;
    std::vector<std::string> sourceEpisodeIds;
    
    // Temporal
    std::chrono::system_clock::time_point learnedAt;
    std::chrono::system_clock::time_point lastApplied;
    int timesApplied = 0;
};

// ============================================================================
// Workflow Improvement
// ============================================================================
struct WorkflowImprovement {
    std::string originalWorkflowId;
    std::string improvedWorkflowId;
    std::string improvementType;     // "optimization", "bug_fix", "generalization"
    
    // What changed
    std::string changeDescription;
    float estimatedSpeedup = 0.0f;
    float estimatedReliabilityImprovement = 0.0f;
    
    // Validation
    bool isValidated = false;
    int validationSuccesses = 0;
    int validationFailures = 0;
};

// ============================================================================
// Performance Model
// ============================================================================
struct PerformanceModel {
    std::string targetId;            // Agent, tool, or workflow
    std::string targetType;
    
    // Predicted performance characteristics
    float predictedSuccessRate = 0.5f;
    double predictedExecutionTimeMs = 0.0;
    float predictedResourceUsage = 1.0f;
    
    // Confidence in prediction
    float modelConfidence = 0.0f;
    int dataPoints = 0;
};

// ============================================================================
// Learning Engine - Continuous Improvement System
// ============================================================================
class LearningEngine {
public:
    LearningEngine();
    ~LearningEngine();

    bool Initialize(ExecutiveDirector* director, CognitiveMemory* memory);
    void Shutdown();
    
    // Pattern learning
    void LearnFromMission(const std::string& missionId);
    std::vector<LearnedPattern> ExtractPatterns(const std::string& missionId);
    void ValidatePattern(const std::string& patternId);
    void ApplyPattern(const std::string& patternId);
    
    // Workflow improvement
    WorkflowImprovement SuggestImprovement(const std::string& workflowId);
    bool ValidateImprovement(const std::string& improvementId);
    void DeployImprovement(const std::string& improvementId);
    
    // Performance modeling
    void UpdatePerformanceModel(const std::string& targetId, bool success, double executionTimeMs);
    PerformanceModel GetPerformanceModel(const std::string& targetId);
    float PredictSuccessProbability(const std::string& targetId, const std::unordered_map<std::string, std::string>& context);
    
    // Knowledge transfer
    void GeneralizeFromSpecific(const std::string& specificEpisodeId);
    void TransferKnowledge(const std::string& fromDomain, const std::string& toDomain);
    
    // Active learning
    std::vector<std::string> IdentifyKnowledgeGaps();
    std::string SuggestExplorationTask();
    
    // Statistics
    struct Stats {
        size_t patternsLearned = 0;
        size_t patternsValidated = 0;
        size_t workflowsImproved = 0;
        size_t performanceModels = 0;
        double averageLearningTimeMs = 0.0;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
