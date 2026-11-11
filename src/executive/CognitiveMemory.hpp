// ============================================================
// CognitiveMemory.hpp - Episodic + Semantic + Working memory
// The "hippocampus" of the cognitive runtime
// ============================================================

#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <optional>
#include <algorithm>

namespace RawrXD::Executive {

// ============================================================
// Episodic Memory: What happened (event log)
// ============================================================

struct EpisodicEntry {
    uint64_t id;
    std::string type;            // "mission_created", "finding", "action", "error"
    std::string description;
    std::string source;          // "user", "swarm", "reflection", "auto"
    uint64_t timestampMs;
    float confidence;            // 0.0-1.0
    std::vector<std::string> tags;
    std::vector<std::string> references;  // Related entry IDs
    std::string context;        // Additional context
};

// ============================================================
// Semantic Memory: What we know (facts/knowledge)
// ============================================================

struct SemanticEntry {
    uint64_t id;
    std::string category;       // "vuln", "pattern", "xor", "injection", etc.
    std::string key;            // Short identifier
    std::string value;          // Detailed content
    std::string source;        // Who discovered this
    float confidence;          // 0.0-1.0
    uint64_t timestampMs;
    uint64_t lastAccessedMs;
    size_t accessCount;
    std::vector<std::string> references;
    bool verified;            // Verified by sentinel?
    bool deprecated;          // Outdated?
};

// ============================================================
// Working Memory: Current state (short-term)
// ============================================================

struct WorkingEntry {
    std::string key;
    std::string value;
    uint64_t timestampMs;
    float priority;           // Higher = more important to keep
};

// ============================================================
// Cognitive Memory
// ============================================================

class CognitiveMemory {
public:
    bool initialize();
    
    // ============================================================
    // Episodic Memory (events)
    // ============================================================
    
    uint64_t storeEpisode(const EpisodicEntry& entry);
    std::vector<EpisodicEntry> getEpisodes(
        const std::string& typeFilter = "",
        uint64_t sinceMs = 0,
        size_t maxCount = 100);
    
    // ============================================================
    // Semantic Memory (knowledge)
    // ============================================================
    
    uint64_t storeSemantic(const SemanticEntry& entry);
    std::optional<SemanticEntry> querySemantic(
        const std::string& category, const std::string& key);
    std::vector<SemanticEntry> queryByCategory(const std::string& category);
    std::vector<SemanticEntry> queryByAddress(const std::string& address);
    bool markVerified(uint64_t semanticId);
    bool deprecate(uint64_t semanticId);
    
    // ============================================================
    // Working Memory (current state)
    // ============================================================
    
    void setWorking(const std::string& key, const std::string& value, 
                    float priority = 0.5f);
    std::optional<std::string> getWorking(const std::string& key);
    void clearWorking();
    
    // ============================================================
    // Recall: Search across all memory types
    // ============================================================
    
    struct RecallResult {
        std::vector<EpisodicEntry> episodes;
        std::vector<SemanticEntry> semantics;
        std::vector<WorkingEntry> working;
    };
    
    RecallResult recall(const std::string& query);
    
    // ============================================================
    // Consolidation: Move working → semantic (learning)
    // ============================================================
    
    void consolidate();
    
    // ============================================================
    // Statistics
    // ============================================================
    
    size_t getEpisodicCount();
    size_t getSemanticCount();
    size_t getWorkingCount();

private:
    std::mutex mutex_;
    
    std::vector<EpisodicEntry> episodic_;
    std::atomic<uint64_t> nextEpisodicId_{1};
    
    std::unordered_map<uint64_t, SemanticEntry> semantic_;
    std::unordered_map<std::string, uint64_t> semanticIndex_;
    std::atomic<uint64_t> nextSemanticId_{1};
    
    std::unordered_map<std::string, WorkingEntry> working_;
    
    void loadFromDisk();
    uint64_t currentTimeMs();
};

} // namespace RawrXD::Executive
