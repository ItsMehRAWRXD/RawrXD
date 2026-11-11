#pragma once

#include <string>
#include <memory>
#include <vector>
#include <unordered_map>
#include <deque>
#include <chrono>
#include <cstdint>

#include "nlohmann/json.hpp"

using json = nlohmann::json;

/**
 * @class AgenticMemorySystem
 * @brief Persistent memory for agents with learning, recall, and pattern recognition
 * 
 * Memory types:
 * 1. EPISODIC: Memories of specific interactions and outcomes
 * 2. SEMANTIC: General knowledge and patterns learned
 * 3. PROCEDURAL: Remembered processes and strategies that worked
 * 4. WORKING: Current task context and short-term goals
 * 
 * Features:
 * - Automatic retention and forgetting policies
 * - Pattern recognition and generalization
 * - Similarity-based retrieval
 * - Temporal decay of memories
 * - Experience scoring
 * - Strategy effectiveness tracking
 */
class AgenticMemorySystem {
public:
    enum class MemoryType {
        Episodic,   // Specific events and interactions
        Semantic,   // General knowledge and patterns
        Procedural, // Processes and strategies
        Working     // Current context
    };

    struct MemoryEntry {
        std::string id;
        MemoryType type;
        std::string content;
        json metadata;
        std::chrono::system_clock::time_point timestamp;
        float relevanceScore;
        int accessCount;
        std::string tags;
        bool isPinned;
    };

    struct Experience {
        std::string experienceId;
        std::string taskDescription;
        json goalState;
        json resultState;
        bool successful;
        float successRate;
        std::vector<std::string> strategiesUsed;
        int iterationsNeeded;
        float similarityToCurrentTask;
        int usageCount;
        std::chrono::system_clock::time_point timestamp;
    };

    struct Pattern {
        std::string patternId;
        std::string description;
        json examples;
        float confidence;
        std::string category;
        int occurrences;
        std::chrono::system_clock::time_point firstObserved;
        std::chrono::system_clock::time_point lastObserved;
    };

public:
    AgenticMemorySystem();
    ~AgenticMemorySystem();

    // ===== MEMORY STORAGE =====
    std::string storeMemory(
        MemoryType type,
        const std::string& content,
        const json& metadata = json::object()
    );
    void updateMemory(const std::string& memoryId, const std::string& content);
    void deleteMemory(const std::string& memoryId);
    void pinMemory(const std::string& memoryId, bool pinned);
    
    // ===== MEMORY RETRIEVAL =====
    MemoryEntry* getMemory(const std::string& memoryId);
    std::vector<MemoryEntry*> getMemoriesByType(MemoryType type);
    std::vector<MemoryEntry*> getMemoriesByTag(const std::string& tag);
    std::vector<MemoryEntry*> searchMemories(const std::string& query, int limit = 10);
    std::vector<MemoryEntry*> getRelevantMemories(const std::string& context, int limit = 5);
    
    // ===== EXPERIENCE MANAGEMENT =====
    std::string recordExperience(
        const std::string& taskDescription,
        const json& goalState,
        const json& resultState,
        bool successful,
        const std::vector<std::string>& strategiesUsed
    );
    std::vector<Experience> findSimilarExperiences(
        const std::string& currentTask,
        float minSimilarity = 0.6f
    );
    Experience* getExperience(const std::string& experienceId);
    void recordExperienceUsage(const std::string& experienceId);
    std::vector<Experience> getMostSuccessfulExperiences(int limit = 10);

    // ===== PATTERN RECOGNITION =====
    std::string recordPattern(
        const std::string& description,
        const std::string& category,
        const json& examples
    );
    std::vector<Pattern> detectPatterns(const std::string& context);
    std::vector<Pattern> getPatternsForCategory(const std::string& category);
    Pattern* getPattern(const std::string& patternId);
    float getPatternConfidence(const std::string& patternId);
    
    // ===== LEARNING AND ADAPTATION =====
    void recordSuccess(
        const std::string& taskDescription,
        const std::string& strategy,
        float effectiveness
    );
    void recordFailure(
        const std::string& taskDescription,
        const std::string& strategy,
        const std::string& failureReason
    );
    
    // Get strategy effectiveness
    float getStrategyEffectiveness(const std::string& strategy) const;
    std::vector<std::string> getRankedStrategies(const std::string& taskType);
    
    // ===== MEMORY CONSOLIDATION =====
    void consolidateMemories();
    void pruneOldMemories(int ageInDays = 30);
    void forgetMemory(const std::string& memoryId);
    float getMemoryDecayFactor(const MemoryEntry& entry) const;
    
    // ===== STATISTICAL ANALYSIS =====
    json getMemoryStatistics() const;
    int getTotalMemories() const { return (int)m_memories.size(); }
    int getExperienceCount() const { return (int)m_experiences.size(); }
    int getPatternCount() const { return (int)m_patterns.size(); }
    float getAverageSuccessRate() const;
    std::string getMostCommonSuccessStrategy() const;
    
    // ===== EXPORT/IMPORT =====
    std::string exportMemories() const;
    bool importMemories(const std::string& jsonData);
    std::string exportExperiences() const;
    bool importExperiences(const std::string& jsonData);
    
    // ===== CONFIGURATION =====
    void setRetentionPolicy(int maxMemories);
    void setDecayRate(float rate);
    void setAccessWeightFactor(float factor);

private:
    // Calculate similarity between strings
    float calculateSimilarity(const std::string& str1, const std::string& str2);
    
    // Decay calculation
    void updateMemoryDecay();
    float calculateRelevanceScore(
        const MemoryEntry& entry,
        const std::string& context
    );
    
    // Pattern extraction
    void extractPatterns();
    std::string hashContent(const std::string& content);

    // Memory stores
    std::unordered_map<std::string, std::unique_ptr<MemoryEntry>> m_memories;
    std::unordered_map<std::string, std::unique_ptr<Experience>> m_experiences;
    std::unordered_map<std::string, std::unique_ptr<Pattern>> m_patterns;
    std::deque<std::string> m_accessHistory;
    
    // Configuration
    int m_maxMemories = 1000;
    float m_decayRate = 0.99f;
    float m_accessWeightFactor = 1.5f;
    int m_contextWindowSize = 10;
    
    // Metrics
    std::chrono::system_clock::time_point m_systemStartTime;
    int m_totalStored = 0;
    int m_totalRetrieved = 0;
};
