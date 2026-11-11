// AgenticMemorySystem Implementation (Core Functions)
#include "agentic_memory_system.h"
#include <iostream>
#include <algorithm>
#include <cmath>
#include <random>
#include <sstream>
#include <iomanip>
#include <cctype>

namespace {

// Simple UUID v4 generator
std::string generateUuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint16_t> dist(0, 0xffff);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 8; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 4; ++i) ss << dist(gen);
    ss << "-";
    ss << "4"; // version 4
    for (int i = 0; i < 3; ++i) ss << dist(gen) & 0x0fff;
    ss << "-";
    ss << (dist(gen) & 0x3fff | 0x8000); // variant 1
    for (int i = 0; i < 3; ++i) ss << dist(gen);
    ss << "-";
    for (int i = 0; i < 6; ++i) ss << dist(gen);
    return ss.str();
}

// Simple FNV-1a 64-bit hash (replaces QCryptographicHash::Sha256 for content hashing)
std::string hashString(const std::string& content) {
    const uint64_t fnv_prime = 1099511628211ull;
    uint64_t hash = 1469598103934ull;
    
    for (unsigned char c : content) {
        hash ^= c;
        hash *= fnv_prime;
    }
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

// Case-insensitive string contains
bool containsCI(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    if (haystack.size() < needle.size()) return false;
    
    for (size_t i = 0; i <= haystack.size() - needle.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(haystack[i + j]) != std::tolower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Split string by whitespace
std::vector<std::string> splitWhitespace(const std::string& str) {
    std::vector<std::string> words;
    std::istringstream iss(str);
    std::string word;
    while (iss >> word) {
        words.push_back(word);
    }
    return words;
}

} // namespace

AgenticMemorySystem::AgenticMemorySystem()
    : m_systemStartTime(std::chrono::system_clock::now())
{
    std::clog << "[AgenticMemorySystem] Initialized - Ready for memory management" << std::endl;
}

AgenticMemorySystem::~AgenticMemorySystem()
{
    std::clog << "[AgenticMemorySystem] Destroyed - Cleaned up"
              << m_memories.size() << "memories and"
              << m_experiences.size() << "experiences" << std::endl;
}

// ===== MEMORY STORAGE =====

std::string AgenticMemorySystem::storeMemory(
    MemoryType type,
    const std::string& content,
    const json& metadata)
{
    std::string memoryId = generateUuid();

    auto memory = std::make_unique<MemoryEntry>();
    memory->id = memoryId;
    memory->type = type;
    memory->content = content;
    memory->metadata = metadata;
    memory->timestamp = std::chrono::system_clock::now();
    memory->relevanceScore = 1.0f;
    memory->accessCount = 0;
    memory->isPinned = false;

    m_memories[memoryId] = std::move(memory);
    m_totalStored++;

    return memoryId;
}

void AgenticMemorySystem::updateMemory(const std::string& memoryId, const std::string& content)
{
    auto it = m_memories.find(memoryId);
    if (it != m_memories.end()) {
        it->second->content = content;
    }
}

void AgenticMemorySystem::deleteMemory(const std::string& memoryId)
{
    m_memories.erase(memoryId);
}

void AgenticMemorySystem::pinMemory(const std::string& memoryId, bool pinned)
{
    auto it = m_memories.find(memoryId);
    if (it != m_memories.end()) {
        it->second->isPinned = pinned;
    }
}

// ===== MEMORY RETRIEVAL =====

AgenticMemorySystem::MemoryEntry* AgenticMemorySystem::getMemory(const std::string& memoryId)
{
    auto it = m_memories.find(memoryId);
    if (it != m_memories.end()) {
        it->second->accessCount++;
        m_totalRetrieved++;
        return it->second.get();
    }
    return nullptr;
}

std::vector<AgenticMemorySystem::MemoryEntry*> AgenticMemorySystem::getMemoriesByType(
    MemoryType type)
{
    std::vector<MemoryEntry*> results;

    for (auto& pair : m_memories) {
        if (pair.second->type == type) {
            results.push_back(pair.second.get());
        }
    }

    return results;
}

std::vector<AgenticMemorySystem::MemoryEntry*> AgenticMemorySystem::getMemoriesByTag(
    const std::string& tag)
{
    std::vector<MemoryEntry*> results;

    for (auto& pair : m_memories) {
        if (pair.second->tags.find(tag) != std::string::npos) {
            results.push_back(pair.second.get());
        }
    }

    return results;
}

std::vector<AgenticMemorySystem::MemoryEntry*> AgenticMemorySystem::searchMemories(
    const std::string& query,
    int limit)
{
    std::vector<MemoryEntry*> results;

    for (auto& pair : m_memories) {
        if (containsCI(pair.second->content, query)) {
            results.push_back(pair.second.get());
        }
    }

    // Sort by relevance score
    std::sort(results.begin(), results.end(),
              [](MemoryEntry* a, MemoryEntry* b) {
                  return a->relevanceScore > b->relevanceScore;
              });

    if (limit > 0 && (int)results.size() > limit) {
        results.resize(limit);
    }

    return results;
}

std::vector<AgenticMemorySystem::MemoryEntry*> AgenticMemorySystem::getRelevantMemories(
    const std::string& context,
    int limit)
{
    std::vector<MemoryEntry*> results;

    for (auto& pair : m_memories) {
        float similarity = calculateSimilarity(pair.second->content, context);
        pair.second->relevanceScore = similarity;

        if (similarity > 0.5f) {
            results.push_back(pair.second.get());
        }
    }

    // Sort by relevance
    std::sort(results.begin(), results.end(),
              [](MemoryEntry* a, MemoryEntry* b) {
                  return a->relevanceScore > b->relevanceScore;
              });

    if (limit > 0 && (int)results.size() > limit) {
        results.resize(limit);
    }

    return results;
}

// ===== EXPERIENCE MANAGEMENT =====

std::string AgenticMemorySystem::recordExperience(
    const std::string& taskDescription,
    const json& goalState,
    const json& resultState,
    bool successful,
    const std::vector<std::string>& strategiesUsed)
{
    std::string experienceId = generateUuid();

    auto experience = std::make_unique<Experience>();
    experience->experienceId = experienceId;
    experience->taskDescription = taskDescription;
    experience->goalState = goalState;
    experience->resultState = resultState;
    experience->successful = successful;
    experience->successRate = successful ? 1.0f : 0.0f;
    experience->strategiesUsed = strategiesUsed;
    experience->timestamp = std::chrono::system_clock::now();
    experience->usageCount = 0;

    m_experiences[experienceId] = std::move(experience);

    return experienceId;
}

std::vector<AgenticMemorySystem::Experience> AgenticMemorySystem::findSimilarExperiences(
    const std::string& currentTask,
    float minSimilarity)
{
    std::vector<Experience> similar;

    for (auto& pair : m_experiences) {
        float similarity = calculateSimilarity(pair.second->taskDescription, currentTask);

        if (similarity >= minSimilarity) {
            pair.second->similarityToCurrentTask = similarity;
            similar.push_back(*pair.second);
        }
    }

    // Sort by similarity
    std::sort(similar.begin(), similar.end(),
              [](const Experience& a, const Experience& b) {
                  return a.similarityToCurrentTask > b.similarityToCurrentTask;
              });

    return similar;
}

AgenticMemorySystem::Experience* AgenticMemorySystem::getExperience(const std::string& experienceId)
{
    auto it = m_experiences.find(experienceId);
    if (it != m_experiences.end()) {
        return it->second.get();
    }
    return nullptr;
}

void AgenticMemorySystem::recordExperienceUsage(const std::string& experienceId)
{
    auto it = m_experiences.find(experienceId);
    if (it != m_experiences.end()) {
        it->second->usageCount++;
    }
}

std::vector<AgenticMemorySystem::Experience> AgenticMemorySystem::getMostSuccessfulExperiences(
    int limit)
{
    std::vector<Experience> successful;

    for (auto& pair : m_experiences) {
        if (pair.second->successful) {
            successful.push_back(*pair.second);
        }
    }

    // Sort by success rate
    std::sort(successful.begin(), successful.end(),
              [](const Experience& a, const Experience& b) {
                  return a.successRate > b.successRate;
              });

    if (limit > 0 && (int)successful.size() > limit) {
        successful.resize(limit);
    }

    return successful;
}

// ===== PATTERN RECOGNITION =====

std::string AgenticMemorySystem::recordPattern(
    const std::string& description,
    const std::string& category,
    const json& examples)
{
    std::string patternId = generateUuid();

    auto pattern = std::make_unique<Pattern>();
    pattern->patternId = patternId;
    pattern->description = description;
    pattern->category = category;
    pattern->examples = examples;
    pattern->confidence = 0.5f;
    pattern->occurrences = 1;
    pattern->firstObserved = std::chrono::system_clock::now();
    pattern->lastObserved = std::chrono::system_clock::now();

    m_patterns[patternId] = std::move(pattern);

    return patternId;
}

std::vector<AgenticMemorySystem::Pattern> AgenticMemorySystem::detectPatterns(
    const std::string& context)
{
    std::vector<Pattern> detected;

    for (auto& pair : m_patterns) {
        // Simple pattern matching on description
        if (containsCI(pair.second->description, context)) {
            detected.push_back(*pair.second);
        }
    }

    return detected;
}

std::vector<AgenticMemorySystem::Pattern> AgenticMemorySystem::getPatternsForCategory(
    const std::string& category)
{
    std::vector<Pattern> patterns;

    for (auto& pair : m_patterns) {
        if (pair.second->category == category) {
            patterns.push_back(*pair.second);
        }
    }

    return patterns;
}

AgenticMemorySystem::Pattern* AgenticMemorySystem::getPattern(const std::string& patternId)
{
    auto it = m_patterns.find(patternId);
    if (it != m_patterns.end()) {
        return it->second.get();
    }
    return nullptr;
}

float AgenticMemorySystem::getPatternConfidence(const std::string& patternId)
{
    auto it = m_patterns.find(patternId);
    if (it != m_patterns.end()) {
        return it->second->confidence;
    }
    return 0.0f;
}

// ===== LEARNING =====

void AgenticMemorySystem::recordSuccess(
    const std::string& taskDescription,
    const std::string& strategy,
    float effectiveness)
{
    // Record successful experience
    json goal;
    goal["task"] = taskDescription;
    goal["strategy"] = strategy;

    recordExperience(taskDescription, goal, goal, true, {strategy});
}

void AgenticMemorySystem::recordFailure(
    const std::string& taskDescription,
    const std::string& strategy,
    const std::string& failureReason)
{
    json goal;
    goal["task"] = taskDescription;
    goal["strategy"] = strategy;
    goal["failure_reason"] = failureReason;

    recordExperience(taskDescription, goal, goal, false, {strategy});
}

float AgenticMemorySystem::getStrategyEffectiveness(const std::string& strategy) const
{
    int successCount = 0;
    int totalCount = 0;

    for (const auto& pair : m_experiences) {
        for (const auto& usedStrategy : pair.second->strategiesUsed) {
            if (usedStrategy == strategy) {
                totalCount++;
                if (pair.second->successful) {
                    successCount++;
                }
            }
        }
    }

    if (totalCount == 0) return 0.0f;

    return (successCount * 100.0f) / totalCount;
}

std::vector<std::string> AgenticMemorySystem::getRankedStrategies(const std::string& taskType)
{
    std::vector<std::pair<std::string, float>> strategies;

    std::unordered_map<std::string, float> strategyScores;
    std::unordered_map<std::string, int> strategyCounts;

    for (const auto& pair : m_experiences) {
        for (const auto& strategy : pair.second->strategiesUsed) {
            strategyCounts[strategy]++;
            if (pair.second->successful) {
                strategyScores[strategy] += 1.0f;
            }
        }
    }

    for (const auto& pair : strategyScores) {
        float effectiveness = pair.second / strategyCounts[pair.first];
        strategies.push_back({pair.first, effectiveness});
    }

    std::sort(strategies.begin(), strategies.end(),
              [](const auto& a, const auto& b) {
                  return a.second > b.second;
              });

    std::vector<std::string> ranked;
    for (const auto& pair : strategies) {
        ranked.push_back(pair.first);
    }

    return ranked;
}

// ===== CONSOLIDATION =====

void AgenticMemorySystem::consolidateMemories()
{
    updateMemoryDecay();
}

void AgenticMemorySystem::pruneOldMemories(int ageInDays)
{
    auto now = std::chrono::system_clock::now();
    auto cutoff = now - std::chrono::hours(24 * ageInDays);
    int prunedCount = 0;

    for (auto it = m_memories.begin(); it != m_memories.end(); ) {
        if (it->second->timestamp < cutoff && !it->second->isPinned) {
            it = m_memories.erase(it);
            prunedCount++;
        } else {
            ++it;
        }
    }
}

void AgenticMemorySystem::forgetMemory(const std::string& memoryId)
{
    deleteMemory(memoryId);
}

float AgenticMemorySystem::getMemoryDecayFactor(const MemoryEntry& entry) const
{
    auto now = std::chrono::system_clock::now();
    auto daysSinceAccess = std::chrono::duration_cast<std::chrono::hours>(
        now - entry.timestamp).count() / 24.0;
    return std::pow(m_decayRate, daysSinceAccess);
}

// ===== STATISTICS =====

json AgenticMemorySystem::getMemoryStatistics() const
{
    json stats;

    stats["total_memories"] = static_cast<int>(m_memories.size());
    stats["total_experiences"] = static_cast<int>(m_experiences.size());
    stats["total_patterns"] = static_cast<int>(m_patterns.size());
    stats["total_stored"] = m_totalStored;
    stats["total_retrieved"] = m_totalRetrieved;
    stats["average_success_rate"] = getAverageSuccessRate();

    return stats;
}

float AgenticMemorySystem::getAverageSuccessRate() const
{
    if (m_experiences.empty()) return 0.0f;

    float total = 0.0f;
    for (const auto& pair : m_experiences) {
        total += pair.second->successRate;
    }

    return total / m_experiences.size();
}

std::string AgenticMemorySystem::getMostCommonSuccessStrategy() const
{
    std::unordered_map<std::string, int> strategyCount;

    for (const auto& pair : m_experiences) {
        if (pair.second->successful) {
            for (const auto& strategy : pair.second->strategiesUsed) {
                strategyCount[strategy]++;
            }
        }
    }

    if (strategyCount.empty()) return "";

    auto maxIt = std::max_element(strategyCount.begin(), strategyCount.end(),
                                  [](const auto& a, const auto& b) {
                                      return a.second < b.second;
                                  });

    return maxIt->first;
}

// ===== EXPORT/IMPORT =====

std::string AgenticMemorySystem::exportMemories() const
{
    json memories = json::array();

    for (const auto& pair : m_memories) {
        json memObj;
        memObj["id"] = pair.second->id;
        memObj["type"] = static_cast<int>(pair.second->type);
        memObj["content"] = pair.second->content;
        memObj["metadata"] = pair.second->metadata;
        
        auto t = std::chrono::system_clock::to_time_t(pair.second->timestamp);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        memObj["timestamp"] = ss.str();

        memories.push_back(memObj);
    }

    return memories.dump();
}

bool AgenticMemorySystem::importMemories(const std::string& jsonData)
{
    json doc = json::parse(jsonData, nullptr, false);
    if (doc.is_discarded() || !doc.is_array()) return false;

    for (const auto& item : doc) {
        storeMemory(
            static_cast<MemoryType>(item.value("type", 0)),
            item.value("content", ""),
            item.value("metadata", json::object())
        );
    }

    return true;
}

std::string AgenticMemorySystem::exportExperiences() const
{
    json experiences = json::array();

    for (const auto& pair : m_experiences) {
        json expObj;
        expObj["id"] = pair.second->experienceId;
        expObj["task"] = pair.second->taskDescription;
        expObj["successful"] = pair.second->successful;
        
        auto t = std::chrono::system_clock::to_time_t(pair.second->timestamp);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
        expObj["timestamp"] = ss.str();

        experiences.push_back(expObj);
    }

    return experiences.dump();
}

bool AgenticMemorySystem::importExperiences(const std::string& jsonData)
{
    json doc = json::parse(jsonData, nullptr, false);
    if (doc.is_discarded() || !doc.is_array()) return false;

    // Process experiences as needed
    return true;
}

// ===== CONFIGURATION =====

void AgenticMemorySystem::setRetentionPolicy(int maxMemories)
{
    m_maxMemories = maxMemories;
}

void AgenticMemorySystem::setDecayRate(float rate)
{
    m_decayRate = rate;
}

void AgenticMemorySystem::setAccessWeightFactor(float factor)
{
    m_accessWeightFactor = factor;
}

// ===== PRIVATE HELPERS =====

float AgenticMemorySystem::calculateSimilarity(const std::string& str1, const std::string& str2)
{
    // Simple word-based similarity
    auto words1 = splitWhitespace(str1);
    auto words2 = splitWhitespace(str2);

    int matches = 0;
    for (const auto& w1 : words1) {
        for (const auto& w2 : words2) {
            if (w1 == w2) { matches++; break; }
        }
    }

    int total = std::max(words1.size(), words2.size());
    return total > 0 ? (matches * 1.0f) / total : 0.0f;
}

void AgenticMemorySystem::updateMemoryDecay()
{
    for (auto& pair : m_memories) {
        float decayFactor = getMemoryDecayFactor(*pair.second);
        pair.second->relevanceScore *= decayFactor;
    }
}

float AgenticMemorySystem::calculateRelevanceScore(
    const MemoryEntry& entry,
    const std::string& context)
{
    float similarity = calculateSimilarity(entry.content, context);
    float recency = getMemoryDecayFactor(entry);
    float accessBoost = std::log(entry.accessCount + 1) * m_accessWeightFactor;

    return (similarity * 0.5f + recency * 0.3f + accessBoost * 0.2f);
}

std::string AgenticMemorySystem::hashContent(const std::string& content)
{
    return hashString(content);
}

void AgenticMemorySystem::extractPatterns()
{
    // Pattern extraction logic
}
