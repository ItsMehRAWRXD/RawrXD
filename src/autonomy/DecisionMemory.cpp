/**
 * DecisionMemory.cpp
 *
 * Phase C.3 Batch 3/5: Autonomous Learning Memory
 */

#include "DecisionMemory.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <random>
#include <chrono>
#include <fstream>

namespace Autonomy {

// ============================================================================
// LearningEntry Implementation
// ============================================================================

std::string LearningEntry::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"entryId\":\"" << entryId << "\",";
    json << "\"decisionId\":\"" << decisionId << "\",";
    json << "\"decisionType\":" << static_cast<int>(decisionType) << ",";
    json << "\"contextAtDecision\":" << contextAtDecision.ToJson() << ",";
    json << "\"predictedUtility\":" << predictedUtility << ",";
    json << "\"predictedRisk\":" << predictedRisk << ",";
    json << "\"outcome\":" << outcome.ToJson() << ",";
    json << "\"actualReward\":" << actualReward << ",";
    json << "\"decisionTimestampMs\":" << decisionTimestampMs << ",";
    json << "\"timeToOutcomeMs\":" << timeToOutcomeMs << ",";
    json << "\"predictionError\":" << predictionError << ",";
    json << "\"wasSurprising\":" << (wasSurprising ? "true" : "false");
    json << "}";
    return json.str();
}

void LearningEntry::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           LEARNING ENTRY                                         ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Entry ID:    " << std::left << std::setw(48) << entryId << " ║\n";
    std::cout << "║  Decision:    " << std::setw(48) << DecisionTypeToString(decisionType) << " ║\n";
    std::cout << "║  Predicted:    " << std::setw(10) << std::fixed << std::setprecision(3) << predictedUtility << std::string(38, ' ') << "║\n";
    std::cout << "║  Actual:       " << std::setw(10) << actualReward << std::string(38, ' ') << "║\n";
    std::cout << "║  Error:        " << std::setw(10) << predictionError << std::string(38, ' ') << "║\n";
    std::cout << "║  Surprising:   " << std::setw(48) << (wasSurprising ? "YES" : "NO") << " ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// DecisionEffectiveness Implementation
// ============================================================================

void DecisionEffectiveness::RecordOutcome(const LearningEntry& entry) {
    totalAttempts++;
    if (entry.outcome.success) {
        successfulAttempts++;
    }
    
    // Update averages
    double n = static_cast<double>(totalAttempts);
    averageReward = (averageReward * (n - 1) + entry.actualReward) / n;
    averagePredictionError = (averagePredictionError * (n - 1) + entry.predictionError) / n;
    
    // Update confidence using learning rate
    double targetConfidence = entry.outcome.success ? 1.0 : 0.0;
    currentConfidence += 0.1 * (targetConfidence - currentConfidence);
    currentConfidence = std::max(0.0, std::min(1.0, currentConfidence));
}

double DecisionEffectiveness::GetSuccessRate() const {
    if (totalAttempts == 0) return 0.5;
    return static_cast<double>(successfulAttempts) / totalAttempts;
}

std::string DecisionEffectiveness::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"type\":\"" << DecisionTypeToString(type) << "\",";
    json << "\"totalAttempts\":" << totalAttempts << ",";
    json << "\"successfulAttempts\":" << successfulAttempts << ",";
    json << "\"averageReward\":" << averageReward << ",";
    json << "\"averagePredictionError\":" << averagePredictionError << ",";
    json << "\"currentConfidence\":" << currentConfidence << ",";
    json << "\"successRate\":" << GetSuccessRate();
    json << "}";
    return json.str();
}

// ============================================================================
// DecisionMemoryConfig Implementation
// ============================================================================

std::string DecisionMemoryConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxEntries\":" << maxEntries << ",";
    json << "\"similarityThreshold\":" << similarityThreshold << ",";
    json << "\"learningRate\":" << learningRate << ",";
    json << "\"discountFactor\":" << discountFactor << ",";
    json << "\"enableForgetting\":" << (enableForgetting ? "true" : "false") << ",";
    json << "\"forgettingAgeMs\":" << forgettingAgeMs;
    json << "}";
    return json.str();
}

// ============================================================================
// DecisionMemory Implementation
// ============================================================================

DecisionMemory::DecisionMemory() = default;
DecisionMemory::~DecisionMemory() = default;

DecisionMemory::DecisionMemory(DecisionMemory&&) noexcept = default;
DecisionMemory& DecisionMemory::operator=(DecisionMemory&&) noexcept = default;

bool DecisionMemory::Initialize(const DecisionMemoryConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    initialized_ = true;
    std::cout << "[DecisionMemory] Initialized with capacity for " << config.maxEntries << " entries\n";
    return true;
}

void DecisionMemory::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    decisionIdToIndex_.clear();
    effectiveness_.clear();
    initialized_ = false;
    std::cout << "[DecisionMemory] Shutdown complete\n";
}

void DecisionMemory::RecordDecision(const Decision& decision) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) return;
    
    LearningEntry entry;
    entry.entryId = GenerateEntryId();
    entry.decisionId = decision.decisionId;
    entry.decisionType = decision.type;
    entry.contextAtDecision = decision.context;
    entry.actions = decision.actions;
    entry.predictedUtility = decision.expectedUtility;
    entry.predictedRisk = decision.riskScore;
    entry.decisionTimestampMs = decision.createdTimestampMs;
    
    // Store entry
    size_t index = entries_.size();
    entries_.push_back(entry);
    decisionIdToIndex_[decision.decisionId] = index;
    
    // Prune if needed
    if (entries_.size() > config_.maxEntries) {
        PruneOldEntries();
    }
}

void DecisionMemory::RecordOutcome(const std::string& decisionId, const DecisionOutcome& outcome) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = decisionIdToIndex_.find(decisionId);
    if (it == decisionIdToIndex_.end()) return;
    
    size_t index = it->second;
    if (index >= entries_.size()) return;
    
    LearningEntry& entry = entries_[index];
    entry.outcome = outcome;
    entry.outcomeTimestampMs = outcome.completedTimestampMs;
    entry.timeToOutcomeMs = outcome.completedTimestampMs - entry.decisionTimestampMs;
    entry.actualReward = CalculateReward(outcome);
    entry.predictionError = std::abs(entry.predictedUtility - entry.actualReward);
    entry.wasSurprising = entry.predictionError > 0.3;
    
    // Update effectiveness
    UpdateEffectiveness(entry);
}

std::vector<LearningEntry> DecisionMemory::FindSimilarDecisions(const DecisionContext& context, 
                                                                   int maxResults) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::pair<LearningEntry, double>> scoredEntries;
    
    for (const auto& entry : entries_) {
        ContextSimilarity sim = CalculateSimilarity(entry.contextAtDecision, context);
        if (sim.Overall() >= config_.similarityThreshold) {
            scoredEntries.push_back({entry, sim.Overall()});
        }
    }
    
    // Sort by similarity
    std::sort(scoredEntries.begin(), scoredEntries.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Return top results
    std::vector<LearningEntry> results;
    for (int i = 0; i < std::min(maxResults, static_cast<int>(scoredEntries.size())); ++i) {
        results.push_back(scoredEntries[i].first);
    }
    
    return results;
}

std::vector<LearningEntry> DecisionMemory::GetEntriesForType(DecisionType type, int maxResults) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<LearningEntry> results;
    for (const auto& entry : entries_) {
        if (entry.decisionType == type) {
            results.push_back(entry);
            if (results.size() >= static_cast<size_t>(maxResults)) break;
        }
    }
    
    return results;
}

DecisionEffectiveness DecisionMemory::GetEffectiveness(DecisionType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = effectiveness_.find(type);
    if (it != effectiveness_.end()) {
        return it->second;
    }
    
    DecisionEffectiveness eff;
    eff.type = type;
    return eff;
}

void DecisionMemory::UpdateConfidence(DecisionType type, double actualReward) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto& eff = effectiveness_[type];
    eff.type = type;
    
    // Simple Q-learning style update
    double target = actualReward > 0.5 ? 1.0 : 0.0;
    eff.currentConfidence += config_.learningRate * (target - eff.currentConfidence);
    eff.currentConfidence = std::max(0.0, std::min(1.0, eff.currentConfidence));
}

double DecisionMemory::PredictUtility(DecisionType type, const DecisionContext& context) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Find similar past decisions
    std::vector<LearningEntry> similar = FindSimilarDecisions(context, 10);
    
    // Filter by type
    double totalReward = 0.0;
    double totalWeight = 0.0;
    
    for (const auto& entry : similar) {
        if (entry.decisionType == type && entry.outcomeTimestampMs > 0) {
            ContextSimilarity sim = CalculateSimilarity(entry.contextAtDecision, context);
            double weight = sim.Overall();
            totalReward += entry.actualReward * weight;
            totalWeight += weight;
        }
    }
    
    if (totalWeight > 0) {
        return totalReward / totalWeight;
    }
    
    // Default prediction
    return 0.5;
}

double DecisionMemory::PredictSuccessProbability(DecisionType type, const DecisionContext& context) const {
    auto eff = GetEffectiveness(type);
    return eff.GetSuccessRate();
}

std::vector<DecisionType> DecisionMemory::GetRecommendedDecisions(const DecisionContext& context) const {
    std::vector<DecisionType> allTypes = {
        DecisionType::OPTIMIZE_PATH,
        DecisionType::SPAWN_WORKERS,
        DecisionType::MERGE_TASKS,
        DecisionType::REBALANCE_RESOURCES,
        DecisionType::FREEZE_UNSTABLE_COMPONENT
    };
    
    // Score each type
    std::vector<std::pair<DecisionType, double>> scored;
    for (auto type : allTypes) {
        double utility = PredictUtility(type, context);
        double successProb = PredictSuccessProbability(type, context);
        double score = utility * successProb;
        scored.push_back({type, score});
    }
    
    // Sort by score
    std::sort(scored.begin(), scored.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Return ordered types
    std::vector<DecisionType> recommended;
    for (const auto& [type, score] : scored) {
        if (score > 0.3) {
            recommended.push_back(type);
        }
    }
    
    return recommended;
}

std::vector<LearningEntry> DecisionMemory::SampleForReplay(int count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<LearningEntry> completed;
    for (const auto& entry : entries_) {
        if (entry.outcomeTimestampMs > 0) {
            completed.push_back(entry);
        }
    }
    
    // Random sample
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(completed.begin(), completed.end(), gen);
    
    if (completed.size() > static_cast<size_t>(count)) {
        completed.resize(count);
    }
    
    return completed;
}

DecisionMemory::Statistics DecisionMemory::GetStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Statistics stats;
    stats.totalEntries = entries_.size();
    
    double totalReward = 0.0;
    double totalError = 0.0;
    
    for (const auto& entry : entries_) {
        if (entry.outcomeTimestampMs > 0) {
            stats.entriesWithOutcomes++;
            totalReward += entry.actualReward;
            totalError += entry.predictionError;
        }
    }
    
    if (stats.entriesWithOutcomes > 0) {
        stats.averageReward = totalReward / stats.entriesWithOutcomes;
        stats.averagePredictionError = totalError / stats.entriesWithOutcomes;
    }
    
    stats.effectivenessByType = effectiveness_;
    
    return stats;
}

bool DecisionMemory::Save(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "{\n";
    file << "  \"config\": " << config_.ToJson() << ",\n";
    file << "  \"entries\": [\n";
    
    for (size_t i = 0; i < entries_.size(); ++i) {
        file << "    " << entries_[i].ToJson();
        if (i + 1 < entries_.size()) file << ",";
        file << "\n";
    }
    
    file << "  ],\n";
    file << "  \"effectiveness\": {\n";
    
    size_t effCount = 0;
    for (const auto& [type, eff] : effectiveness_) {
        file << "    \"" << DecisionTypeToString(type) << "\": " << eff.ToJson();
        if (++effCount < effectiveness_.size()) file << ",";
        file << "\n";
    }
    
    file << "  }\n";
    file << "}\n";
    
    return true;
}

bool DecisionMemory::Load(const std::string& path) {
    // Simplified load - would parse JSON
    return false;
}

void DecisionMemory::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    decisionIdToIndex_.clear();
    effectiveness_.clear();
}

void DecisionMemory::PrintStatus() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     DECISION MEMORY STATUS                                       ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:        " << std::setw(10) << (initialized_ ? "YES" : "NO") << std::string(26, ' ') << "║\n";
    std::cout << "║  Total Entries:       " << std::setw(10) << entries_.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  With Outcomes:      " << std::setw(10) << decisionIdToIndex_.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Effectiveness Models: " << std::setw(10) << effectiveness_.size() << std::string(26, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Helpers
// ============================================================================

ContextSimilarity DecisionMemory::CalculateSimilarity(const DecisionContext& a, 
                                                       const DecisionContext& b) const {
    ContextSimilarity sim;
    
    // Stability similarity
    sim.stabilitySimilarity = 1.0 - std::abs(a.systemStability - b.systemStability);
    
    // Load similarity
    double loadA = static_cast<double>(a.activeTasks) / std::max(1, a.activeTasks + a.pendingTasks);
    double loadB = static_cast<double>(b.activeTasks) / std::max(1, b.activeTasks + b.pendingTasks);
    sim.loadSimilarity = 1.0 - std::abs(loadA - loadB);
    
    // Pattern similarity (simplified)
    sim.patternSimilarity = 0.8; // Would compare actual patterns
    
    return sim;
}

double DecisionMemory::CalculateReward(const DecisionOutcome& outcome) const {
    if (!outcome.success) return -1.0;
    
    // Reward based on utility and speed
    double reward = outcome.actualUtility;
    
    // Bonus for fast execution
    if (outcome.executionTimeMs < 100.0) {
        reward += 0.1;
    }
    
    return std::min(1.0, reward);
}

void DecisionMemory::PruneOldEntries() {
    if (!config_.enableForgetting) return;
    
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Remove old entries
    auto it = entries_.begin();
    while (it != entries_.end()) {
        if (now - it->decisionTimestampMs > config_.forgettingAgeMs) {
            decisionIdToIndex_.erase(it->decisionId);
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

void DecisionMemory::UpdateEffectiveness(const LearningEntry& entry) {
    auto& eff = effectiveness_[entry.decisionType];
    eff.type = entry.decisionType;
    eff.RecordOutcome(entry);
}

std::string DecisionMemory::GenerateEntryId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "mem-" << ms << "-" << dis(gen);
    return id.str();
}

void DecisionMemory::Statistics::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           MEMORY STATISTICS                                      ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Total Entries:      " << std::setw(10) << totalEntries << std::string(26, ' ') << "║\n";
    std::cout << "║  With Outcomes:      " << std::setw(10) << entriesWithOutcomes << std::string(26, ' ') << "║\n";
    std::cout << "║  Average Reward:     " << std::setw(9) << std::fixed << std::setprecision(3) << averageReward << std::string(27, ' ') << "║\n";
    std::cout << "║  Avg Prediction Error: " << std::setw(9) << averagePredictionError << std::string(25, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Effectiveness by Type:                                          ║\n";
    for (const auto& [type, eff] : effectivenessByType) {
        std::cout << "║    " << std::left << std::setw(20) << DecisionTypeToString(type)
                  << " Success: " << std::setw(5) << std::fixed << std::setprecision(1) << (eff.GetSuccessRate() * 100) << "%"
                  << std::string(15, ' ') << "║\n";
    }
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

} // namespace Autonomy
