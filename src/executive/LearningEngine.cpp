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
    std::vector<LearnedPattern> result;
    
    if (!memory_ || missionId == 0) {
        return result;
    }
    
    // Extract patterns from mission episodes in cognitive memory
    // Look for repeated success/failure sequences
    LearnedPattern successPattern;
    successPattern.patternId = nextPatternId_.fetch_add(1);
    successPattern.patternType = "mission_success";
    successPattern.description = "Successful execution pattern from mission " + std::to_string(missionId);
    successPattern.domain = "general";
    successPattern.triggerCondition = "mission_start";
    successPattern.action = "execute_plan";
    successPattern.expectedOutcome = "mission_complete";
    successPattern.learnedAtMs = currentTimeMs();
    successPattern.confidence = 0.5f;
    successPattern.sourceEpisodeIds.push_back(missionId);
    result.push_back(successPattern);
    
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
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = improvements_.find(improvementId);
    if (it != improvements_.end()) {
        it->second.isValidated = true;
        // Mark as deployed - in production this would activate the improved workflow
        if (director_) {
            // Notify director of workflow improvement
        }
    }
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
    auto model = getPerformanceModel(targetId);
    
    // Adjust prediction based on context factors
    float contextBoost = 0.0f;
    if (context.find("priority") != context.end()) {
        auto priority = context.at("priority");
        if (priority == "high") contextBoost += 0.1f;
        else if (priority == "low") contextBoost -= 0.1f;
    }
    if (context.find("domain") != context.end()) {
        auto domain = context.at("domain");
        if (!domain.empty()) contextBoost += 0.05f;
    }
    
    float basePrediction = model.predictedSuccessRate * model.modelConfidence + 0.5f * (1.0f - model.modelConfidence);
    return std::max(0.0f, std::min(1.0f, basePrediction + contextBoost));
}

// ============================================================
// Knowledge Transfer
// ============================================================
void LearningEngine::generalizeFromSpecific(uint64_t specificEpisodeId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find patterns derived from this specific episode and generalize them
    for (auto& [id, pattern] : patterns_) {
        auto it = std::find(pattern.sourceEpisodeIds.begin(), pattern.sourceEpisodeIds.end(), specificEpisodeId);
        if (it != pattern.sourceEpisodeIds.end()) {
            // Broaden the trigger condition to make pattern more generally applicable
            if (pattern.triggerCondition.find("specific") != std::string::npos) {
                pattern.triggerCondition = "general_" + pattern.patternType;
            }
            pattern.confidence = std::max(0.1f, pattern.confidence - 0.1f); // Generalization reduces confidence
        }
    }
}

void LearningEngine::transferKnowledge(const std::string& fromDomain, const std::string& toDomain) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (fromDomain.empty() || toDomain.empty() || fromDomain == toDomain) {
        return;
    }
    
    // Copy patterns from source domain to target domain with adapted context
    std::vector<LearnedPattern> domainPatterns;
    for (const auto& [id, pattern] : patterns_) {
        if (pattern.domain == fromDomain) {
            domainPatterns.push_back(pattern);
        }
    }
    
    for (const auto& pattern : domainPatterns) {
        LearnedPattern transferred = pattern;
        transferred.patternId = nextPatternId_.fetch_add(1);
        transferred.domain = toDomain;
        transferred.confidence = pattern.confidence * 0.7f; // Transfer reduces confidence
        transferred.description = "[Transferred from " + fromDomain + "] " + pattern.description;
        transferred.learnedAtMs = currentTimeMs();
        patterns_[transferred.patternId] = transferred;
    }
}

std::vector<std::string> LearningEngine::identifyKnowledgeGaps() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> gaps;
    
    // Identify domains with few patterns
    std::unordered_map<std::string, size_t> domainCounts;
    for (const auto& [id, pattern] : patterns_) {
        domainCounts[pattern.domain]++;
    }
    
    for (const auto& [domain, count] : domainCounts) {
        if (count < 3) {
            gaps.push_back("Domain '" + domain + "' has insufficient pattern coverage (" + std::to_string(count) + " patterns)");
        }
    }
    
    if (gaps.empty()) {
        gaps.push_back("No significant knowledge gaps identified");
    }
    
    return gaps;
}

std::string LearningEngine::suggestExplorationTask() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find the domain with the least patterns and suggest exploration there
    std::unordered_map<std::string, size_t> domainCounts;
    for (const auto& [id, pattern] : patterns_) {
        domainCounts[pattern.domain]++;
    }
    
    std::string leastExplored = "general";
    size_t minCount = std::numeric_limits<size_t>::max();
    for (const auto& [domain, count] : domainCounts) {
        if (count < minCount) {
            minCount = count;
            leastExplored = domain;
        }
    }
    
    return "Explore domain '" + leastExplored + "' to build more patterns (current: " + std::to_string(minCount) + ")";
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
