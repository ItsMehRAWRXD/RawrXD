// ============================================================
// LearningEngine.cpp - Experience-Driven Improvement
// ============================================================

#include "LearningEngine.hpp"
#include "CognitiveMemory.hpp"
#include "ExecutiveDirector.hpp"
#include <chrono>
#include <algorithm>

namespace RawrXD::Executive {

// ============================================================
// Lifecycle
// ============================================================
bool LearningEngine::initialize(ExecutiveDirector* director, CognitiveMemory* memory) {
    director_ = director;
    memory_ = memory;
    return true;
}

void LearningEngine::shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    patterns_.clear();
    improvements_.clear();
    models_.clear();
}

// ============================================================
// Pattern Learning
// ============================================================
void LearningEngine::learnFromMission(uint64_t missionId) {
    auto patterns = extractPatterns(missionId);
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& pattern : patterns) {
        patterns_[pattern.patternId] = pattern;
    }
}

std::vector<LearnedPattern> LearningEngine::extractPatterns(uint64_t missionId) {
    (void)missionId;
    std::vector<LearnedPattern> result;
    
    LearnedPattern pattern;
    pattern.patternId = nextPatternId_.fetch_add(1);
    pattern.patternType = "mission_completion";
    pattern.description = "Extracted from mission " + std::to_string(missionId);
    pattern.domain = "general";
    pattern.learnedAtMs = currentTimeMs();
    pattern.confidence = 0.5f;
    result.push_back(pattern);
    
    return result;
}

void LearningEngine::validatePattern(uint64_t patternId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = patterns_.find(patternId);
    if (it != patterns_.end()) {
        it->second.confidence = std::min(1.0f, it->second.confidence + 0.1f);
    }
}

void LearningEngine::applyPattern(uint64_t patternId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = patterns_.find(patternId);
    if (it != patterns_.end()) {
        it->second.timesApplied++;
        it->second.lastAppliedMs = currentTimeMs();
    }
}

// ============================================================
// Workflow Improvement
// ============================================================
WorkflowImprovement LearningEngine::suggestImprovement(uint64_t workflowId) {
    WorkflowImprovement improvement;
    improvement.originalWorkflowId = workflowId;
    improvement.improvedWorkflowId = nextImprovementId_.fetch_add(1);
    improvement.improvementType = "optimization";
    improvement.changeDescription = "Suggested improvement for workflow " + std::to_string(workflowId);
    improvement.estimatedSpeedup = 0.1f;
    improvement.estimatedReliabilityImprovement = 0.05f;
    
    std::lock_guard<std::mutex> lock(mutex_);
    improvements_[improvement.improvedWorkflowId] = improvement;
    return improvement;
}

bool LearningEngine::validateImprovement(uint64_t improvementId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = improvements_.find(improvementId);
    if (it != improvements_.end()) {
        it->second.isValidated = true;
        return true;
    }
    return false;
}

void LearningEngine::deployImprovement(uint64_t improvementId) {
    (void)improvementId;
}

// ============================================================
// Performance Modeling
// ============================================================
void LearningEngine::updatePerformanceModel(uint64_t targetId, bool success, double executionTimeMs) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& model = models_[targetId];
    model.targetId = targetId;
    model.dataPoints++;
    
    float alpha = 0.1f;
    if (success) {
        model.predictedSuccessRate = model.predictedSuccessRate * (1.0f - alpha) + alpha;
    } else {
        model.predictedSuccessRate = model.predictedSuccessRate * (1.0f - alpha);
    }
    
    model.predictedExecutionTimeMs = model.predictedExecutionTimeMs * (1.0f - alpha) + executionTimeMs * alpha;
    model.modelConfidence = std::min(1.0f, static_cast<float>(model.dataPoints) / 100.0f);
}

PerformanceModel LearningEngine::getPerformanceModel(uint64_t targetId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = models_.find(targetId);
    if (it != models_.end()) {
        return it->second;
    }
    return PerformanceModel{targetId, "unknown", 0.5f, 0.0, 1.0f, 0.0f, 0};
}

float LearningEngine::predictSuccessProbability(uint64_t targetId,
                                                 const std::unordered_map<std::string, std::string>& context) {
    (void)context;
    auto model = getPerformanceModel(targetId);
    return model.predictedSuccessRate * model.modelConfidence + 0.5f * (1.0f - model.modelConfidence);
}

// ============================================================
// Knowledge Transfer
// ============================================================
void LearningEngine::generalizeFromSpecific(uint64_t specificEpisodeId) {
    (void)specificEpisodeId;
}

void LearningEngine::transferKnowledge(const std::string& fromDomain, const std::string& toDomain) {
    (void)fromDomain;
    (void)toDomain;
}

std::vector<std::string> LearningEngine::identifyKnowledgeGaps() {
    return std::vector<std::string>{"No knowledge gaps identified"};
}

std::string LearningEngine::suggestExplorationTask() {
    return "Explore new capability domains";
}

// ============================================================
// Stats
// ============================================================
LearningEngine::Stats LearningEngine::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return Stats{
        patterns_.size(),
        std::count_if(patterns_.begin(), patterns_.end(),
                      [](const auto& p) { return p.second.confidence > 0.7f; }),
        improvements_.size(),
        models_.size()
    };
}

// ============================================================
// Helpers
// ============================================================
uint64_t LearningEngine::currentTimeMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace RawrXD::Executive
