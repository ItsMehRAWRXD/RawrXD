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
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(path);
    if (!file.is_open()) return false;
    
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    file.close();
    
    // Parse config
    size_t configPos = content.find("\"config\"");
    if (configPos != std::string::npos) {
        size_t objStart = content.find('{', configPos);
        size_t objEnd = content.find('}', objStart);
        if (objStart != std::string::npos && objEnd != std::string::npos) {
            // Parse maxEntries
            size_t maxPos = content.find("\"maxEntries\":", objStart);
            if (maxPos != std::string::npos && maxPos < objEnd) {
                maxPos += 13;
                size_t maxEnd = content.find_first_of(",}", maxPos);
                if (maxEnd != std::string::npos) {
                    config_.maxEntries = std::stoull(content.substr(maxPos, maxEnd - maxPos));
                }
            }
            // Parse similarityThreshold
            size_t simPos = content.find("\"similarityThreshold\":", objStart);
            if (simPos != std::string::npos && simPos < objEnd) {
                simPos += 21;
                size_t simEnd = content.find_first_of(",}", simPos);
                if (simEnd != std::string::npos) {
                    config_.similarityThreshold = std::stod(content.substr(simPos, simEnd - simPos));
                }
            }
            // Parse learningRate
            size_t lrPos = content.find("\"learningRate\":", objStart);
            if (lrPos != std::string::npos && lrPos < objEnd) {
                lrPos += 14;
                size_t lrEnd = content.find_first_of(",}", lrPos);
                if (lrEnd != std::string::npos) {
                    config_.learningRate = std::stod(content.substr(lrPos, lrEnd - lrPos));
                }
            }
            // Parse discountFactor
            size_t dfPos = content.find("\"discountFactor\":", objStart);
            if (dfPos != std::string::npos && dfPos < objEnd) {
                dfPos += 17;
                size_t dfEnd = content.find_first_of(",}", dfPos);
                if (dfEnd != std::string::npos) {
                    config_.discountFactor = std::stod(content.substr(dfPos, dfEnd - dfPos));
                }
            }
            // Parse enableForgetting
            size_t efPos = content.find("\"enableForgetting\":", objStart);
            if (efPos != std::string::npos && efPos < objEnd) {
                efPos += 19;
                size_t efEnd = content.find_first_of(",}", efPos);
                if (efEnd != std::string::npos) {
                    std::string efStr = content.substr(efPos, efEnd - efPos);
                    config_.enableForgetting = (efStr == "true");
                }
            }
            // Parse forgettingAgeMs
            size_t faPos = content.find("\"forgettingAgeMs\":", objStart);
            if (faPos != std::string::npos && faPos < objEnd) {
                faPos += 18;
                size_t faEnd = content.find_first_of(",}", faPos);
                if (faEnd != std::string::npos) {
                    config_.forgettingAgeMs = std::stoull(content.substr(faPos, faEnd - faPos));
                }
            }
        }
    }
    
    // Parse entries array
    size_t entriesPos = content.find("\"entries\"");
    if (entriesPos != std::string::npos) {
        size_t arrStart = content.find('[', entriesPos);
        size_t arrEnd = content.find(']', arrStart);
        if (arrStart != std::string::npos && arrEnd != std::string::npos) {
            size_t pos = arrStart + 1;
            while (pos < arrEnd) {
                size_t objStart = content.find('{', pos);
                if (objStart == std::string::npos || objStart >= arrEnd) break;
                
                size_t objEnd = content.find('}', objStart);
                if (objEnd == std::string::npos || objEnd > arrEnd) break;
                
                LearningEntry entry;
                
                // Parse entryId
                size_t idPos = content.find("\"entryId\":\"", objStart);
                if (idPos != std::string::npos && idPos < objEnd) {
                    idPos += 11;
                    size_t idEnd = content.find('"', idPos);
                    if (idEnd != std::string::npos && idEnd < objEnd) {
                        entry.entryId = content.substr(idPos, idEnd - idPos);
                    }
                }
                
                // Parse decisionId
                size_t decPos = content.find("\"decisionId\":\"", objStart);
                if (decPos != std::string::npos && decPos < objEnd) {
                    decPos += 14;
                    size_t decEnd = content.find('"', decPos);
                    if (decEnd != std::string::npos && decEnd < objEnd) {
                        entry.decisionId = content.substr(decPos, decEnd - decPos);
                    }
                }
                
                // Parse decisionType
                size_t typePos = content.find("\"decisionType\":", objStart);
                if (typePos != std::string::npos && typePos < objEnd) {
                    typePos += 15;
                    size_t typeEnd = content.find_first_of(",}", typePos);
                    if (typeEnd != std::string::npos && typeEnd <= objEnd) {
                        int typeVal = std::stoi(content.substr(typePos, typeEnd - typePos));
                        entry.decisionType = static_cast<DecisionType>(typeVal);
                    }
                }
                
                // Parse predictedUtility
                size_t utilPos = content.find("\"predictedUtility\":", objStart);
                if (utilPos != std::string::npos && utilPos < objEnd) {
                    utilPos += 19;
                    size_t utilEnd = content.find_first_of(",}", utilPos);
                    if (utilEnd != std::string::npos && utilEnd <= objEnd) {
                        entry.predictedUtility = std::stod(content.substr(utilPos, utilEnd - utilPos));
                    }
                }
                
                // Parse predictedRisk
                size_t riskPos = content.find("\"predictedRisk\":", objStart);
                if (riskPos != std::string::npos && riskPos < objEnd) {
                    riskPos += 16;
                    size_t riskEnd = content.find_first_of(",}", riskPos);
                    if (riskEnd != std::string::npos && riskEnd <= objEnd) {
                        entry.predictedRisk = std::stod(content.substr(riskPos, riskEnd - riskPos));
                    }
                }
                
                // Parse actualReward
                size_t rewardPos = content.find("\"actualReward\":", objStart);
                if (rewardPos != std::string::npos && rewardPos < objEnd) {
                    rewardPos += 15;
                    size_t rewardEnd = content.find_first_of(",}", rewardPos);
                    if (rewardEnd != std::string::npos && rewardEnd <= objEnd) {
                        entry.actualReward = std::stod(content.substr(rewardPos, rewardEnd - rewardPos));
                    }
                }
                
                // Parse decisionTimestampMs
                size_t tsPos = content.find("\"decisionTimestampMs\":", objStart);
                if (tsPos != std::string::npos && tsPos < objEnd) {
                    tsPos += 22;
                    size_t tsEnd = content.find_first_of(",}", tsPos);
                    if (tsEnd != std::string::npos && tsEnd <= objEnd) {
                        entry.decisionTimestampMs = std::stoull(content.substr(tsPos, tsEnd - tsPos));
                    }
                }
                
                // Parse timeToOutcomeMs
                size_t toPos = content.find("\"timeToOutcomeMs\":", objStart);
                if (toPos != std::string::npos && toPos < objEnd) {
                    toPos += 18;
                    size_t toEnd = content.find_first_of(",}", toPos);
                    if (toEnd != std::string::npos && toEnd <= objEnd) {
                        entry.timeToOutcomeMs = std::stoull(content.substr(toPos, toEnd - toPos));
                    }
                }
                
                // Parse predictionError
                size_t errPos = content.find("\"predictionError\":", objStart);
                if (errPos != std::string::npos && errPos < objEnd) {
                    errPos += 17;
                    size_t errEnd = content.find_first_of(",}", errPos);
                    if (errEnd != std::string::npos && errEnd <= objEnd) {
                        entry.predictionError = std::stod(content.substr(errPos, errEnd - errPos));
                    }
                }
                
                // Parse wasSurprising
                size_t surpPos = content.find("\"wasSurprising\":", objStart);
                if (surpPos != std::string::npos && surpPos < objEnd) {
                    surpPos += 16;
                    size_t surpEnd = content.find_first_of(",}", surpPos);
                    if (surpEnd != std::string::npos && surpEnd <= objEnd) {
                        std::string surpStr = content.substr(surpPos, surpEnd - surpPos);
                        entry.wasSurprising = (surpStr == "true");
                    }
                }
                
                // Add entry if valid
                if (!entry.entryId.empty()) {
                    size_t index = entries_.size();
                    entries_.push_back(std::move(entry));
                    decisionIdToIndex_[entry.decisionId] = index;
                }
                
                pos = objEnd + 1;
            }
        }
    }
    
    // Parse effectiveness
    size_t effPos = content.find("\"effectiveness\"");
    if (effPos != std::string::npos) {
        size_t effStart = content.find('{', effPos);
        size_t effEnd = content.find('}', effStart);
        if (effStart != std::string::npos && effEnd != std::string::npos) {
            size_t pos = effStart + 1;
            while (pos < effEnd) {
                // Find type name
                size_t typeNamePos = content.find('"', pos);
                if (typeNamePos == std::string::npos || typeNamePos >= effEnd) break;
                
                size_t typeNameEnd = content.find('"', typeNamePos + 1);
                if (typeNameEnd == std::string::npos || typeNameEnd >= effEnd) break;
                
                std::string typeName = content.substr(typeNamePos + 1, typeNameEnd - typeNamePos - 1);
                
                // Find effectiveness object
                size_t objStart = content.find('{', typeNameEnd);
                if (objStart == std::string::npos || objStart >= effEnd) break;
                
                size_t objEnd = content.find('}', objStart);
                if (objEnd == std::string::npos || objEnd > effEnd) break;
                
                DecisionEffectiveness eff;
                // Parse type from string
                if (typeName == "OPTIMIZE_PATH") eff.type = DecisionType::OPTIMIZE_PATH;
                else if (typeName == "SPAWN_WORKERS") eff.type = DecisionType::SPAWN_WORKERS;
                else if (typeName == "MERGE_TASKS") eff.type = DecisionType::MERGE_TASKS;
                else if (typeName == "REBALANCE_RESOURCES") eff.type = DecisionType::REBALANCE_RESOURCES;
                else if (typeName == "FREEZE_UNSTABLE_COMPONENT") eff.type = DecisionType::FREEZE_UNSTABLE_COMPONENT;
                
                // Parse totalAttempts
                size_t taPos = content.find("\"totalAttempts\":", objStart);
                if (taPos != std::string::npos && taPos < objEnd) {
                    taPos += 16;
                    size_t taEnd = content.find_first_of(",}", taPos);
                    if (taEnd != std::string::npos) {
                        eff.totalAttempts = std::stoull(content.substr(taPos, taEnd - taPos));
                    }
                }
                
                // Parse successfulAttempts
                size_t saPos = content.find("\"successfulAttempts\":", objStart);
                if (saPos != std::string::npos && saPos < objEnd) {
                    saPos += 21;
                    size_t saEnd = content.find_first_of(",}", saPos);
                    if (saEnd != std::string::npos) {
                        eff.successfulAttempts = std::stoull(content.substr(saPos, saEnd - saPos));
                    }
                }
                
                // Parse averageReward
                size_t arPos = content.find("\"averageReward\":", objStart);
                if (arPos != std::string::npos && arPos < objEnd) {
                    arPos += 17;
                    size_t arEnd = content.find_first_of(",}", arPos);
                    if (arEnd != std::string::npos) {
                        eff.averageReward = std::stod(content.substr(arPos, arEnd - arPos));
                    }
                }
                
                // Parse averagePredictionError
                size_t apePos = content.find("\"averagePredictionError\":", objStart);
                if (apePos != std::string::npos && apePos < objEnd) {
                    apePos += 25;
                    size_t apeEnd = content.find_first_of(",}", apePos);
                    if (apeEnd != std::string::npos) {
                        eff.averagePredictionError = std::stod(content.substr(apePos, apeEnd - apePos));
                    }
                }
                
                // Parse currentConfidence
                size_t ccPos = content.find("\"currentConfidence\":", objStart);
                if (ccPos != std::string::npos && ccPos < objEnd) {
                    ccPos += 20;
                    size_t ccEnd = content.find_first_of(",}", ccPos);
                    if (ccEnd != std::string::npos) {
                        eff.currentConfidence = std::stod(content.substr(ccPos, ccEnd - ccPos));
                    }
                }
                
                effectiveness_[eff.type] = std::move(eff);
                
                pos = objEnd + 1;
            }
        }
    }
    
    initialized_ = true;
    return true;
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
