// ============================================================================
// CognitiveMemory.hpp - Persistent Memory System
// Episodic (missions, experiences) + Semantic (knowledge, patterns)
// ============================================================================

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>
#include <chrono>
#include <mutex>
#include <optional>

namespace RawrXD {
namespace Executive {

// ============================================================================
// Memory Types
// ============================================================================
enum class MemoryType {
    EPISODIC,    // Time-bound experiences (missions, events)
    SEMANTIC,    // Timeless knowledge (facts, patterns, APIs)
    PROCEDURAL,  // How-to knowledge (workflows, skills)
    WORKING      // Temporary active memory
};

// ============================================================================
// Episode Memory Entry
// ============================================================================
struct Episode {
    std::string episodeId;
    std::string missionId;
    std::string description;
    std::string domain;           // "reverse_engineering", "code_analysis", etc.
    
    // Temporal
    std::chrono::system_clock::time_point startTime;
    std::chrono::system_clock::time_point endTime;
    
    // Outcome
    bool success = false;
    float confidence = 0.0f;
    std::string outcome;
    
    // Content
    std::vector<std::string> actionsTaken;
    std::vector<std::string> toolsUsed;
    std::vector<std::string> agentsInvolved;
    std::string keyInsight;       // What was learned
    std::string failureReason;    // If failed, why
    
    // Metrics
    double durationMs = 0.0;
    size_t tokensProcessed = 0;
    size_t patternsFound = 0;
    double memoryUsedMB = 0.0;
    
    // For retrieval
    std::vector<std::string> tags;
    std::unordered_map<std::string, float> embeddings;  // Semantic vector
};

// ============================================================================
// Semantic Memory Entry (Knowledge Graph Node)
// ============================================================================
struct SemanticNode {
    std::string nodeId;
    std::string concept;          // "Function", "API", "MalwareFamily", etc.
    std::string name;
    std::string description;
    
    // Belief system
    float confidence = 1.0f;      // How sure are we (0-1)
    std::vector<std::string> evidence;  // Supporting episodes
    std::vector<std::string> contradictions;  // Counter-evidence
    
    // Relations (edges)
    std::vector<std::pair<std::string, std::string>> relations;  // (relation, targetNodeId)
    // e.g., ("calls", "func_123"), ("is_type_of", "decryptor"), ("has_entropy", "high")
    
    // Properties
    std::unordered_map<std::string, std::string> properties;
    
    // Temporal
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point lastAccessed;
    int accessCount = 0;
    
    // Embeddings for similarity search
    std::vector<float> embedding;
};

// ============================================================================
// Procedural Memory (Learned Workflows)
// ============================================================================
struct ProceduralMemory {
    std::string workflowId;
    std::string name;
    std::string description;
    std::string domain;
    
    // The workflow itself (serialized)
    std::string workflowDefinition;
    
    // Performance metrics
    int timesUsed = 0;
    float successRate = 0.0f;
    double averageDurationMs = 0.0;
    
    // When applicable
    std::vector<std::string> applicablePatterns;  // When to use this workflow
    std::vector<std::string> preconditions;
    std::vector<std::string> postconditions;
};

// ============================================================================
// Memory Query
// ============================================================================
struct MemoryQuery {
    MemoryType type = MemoryType::EPISODIC;
    std::string domain;
    std::vector<std::string> tags;
    std::string textQuery;         // Semantic search
    float minConfidence = 0.0f;
    size_t maxResults = 10;
    
    // Temporal filters
    std::optional<std::chrono::system_clock::time_point> after;
    std::optional<std::chrono::system_clock::time_point> before;
    
    // Similarity search
    std::vector<float> embedding;
    float similarityThreshold = 0.7f;
};

// ============================================================================
// Cognitive Memory - The Long-Term Memory System
// ============================================================================
class CognitiveMemory {
public:
    CognitiveMemory();
    ~CognitiveMemory();

    // Initialization
    bool Initialize(size_t maxEpisodicSize = 10000, size_t maxSemanticSize = 100000);
    void Shutdown();
    
    // Episodic Memory Operations
    std::string StoreEpisode(const Episode& episode);
    std::optional<Episode> RetrieveEpisode(const std::string& episodeId);
    std::vector<Episode> QueryEpisodes(const MemoryQuery& query);
    std::vector<Episode> GetSimilarEpisodes(const std::string& episodeId, size_t count = 5);
    
    // Semantic Memory Operations
    std::string StoreSemanticNode(const SemanticNode& node);
    std::optional<SemanticNode> RetrieveSemanticNode(const std::string& nodeId);
    std::optional<SemanticNode> RetrieveSemanticNodeByName(const std::string& name);
    std::vector<SemanticNode> QuerySemanticNodes(const MemoryQuery& query);
    std::vector<SemanticNode> FindRelatedNodes(const std::string& nodeId, const std::string& relationType = "");
    
    // Update beliefs with evidence
    void UpdateBelief(const std::string& nodeId, float newConfidence, const std::string& evidence);
    void AddRelation(const std::string& fromNodeId, const std::string& relation, const std::string& toNodeId);
    
    // Procedural Memory
    std::string StoreWorkflow(const ProceduralMemory& workflow);
    std::vector<ProceduralMemory> FindApplicableWorkflows(const std::string& domain, const std::vector<std::string>& patterns);
    void RecordWorkflowUsage(const std::string& workflowId, bool success, double durationMs);
    
    // Consolidation (merge similar memories, prune old ones)
    void ConsolidateEpisodicMemory();
    void ConsolidateSemanticMemory();
    
    // Persistence
    bool SaveToDisk(const std::string& path);
    bool LoadFromDisk(const std::string& path);
    
    // Statistics
    struct Stats {
        size_t episodicCount = 0;
        size_t semanticCount = 0;
        size_t proceduralCount = 0;
        size_t totalQueries = 0;
        double averageQueryTimeMs = 0.0;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace Executive
} // namespace RawrXD
