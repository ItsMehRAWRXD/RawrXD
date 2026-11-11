// ============================================================================
// AgentMemory.hpp - Long-term Memory System for Agents
// Episodic + Semantic + Working Memory
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <chrono>
#include <mutex>
#include <optional>

namespace Sovereign {

// Memory types
enum class MemoryType {
    EPISODIC,      // Events, experiences
    SEMANTIC,      // Facts, knowledge
    PROCEDURAL,    // How-to, skills
    WORKING,       // Temporary context
    REFLECTION     // Insights, summaries
};

// Memory entry
struct Memory {
    uint64_t id;
    MemoryType type;
    std::string content;
    std::string summary;
    std::vector<std::string> tags;
    std::string source;
    uint64_t timestamp;
    uint64_t lastAccessed;
    int accessCount;
    float importance;
    std::vector<float> embedding;
    std::vector<uint64_t> relatedMemories;
};

// Memory query
struct MemoryQuery {
    std::string content;
    MemoryType typeFilter;
    std::vector<std::string> tags;
    uint64_t since;
    uint64_t until;
    float minImportance;
    size_t limit;
    bool includeRelated;
};

// Memory search result
struct MemoryResult {
    Memory memory;
    float relevance;
    float recency;
    float importance;
};

// Conversation turn
struct ConversationTurn {
    uint64_t id;
    std::string role; // user, assistant, system, tool
    std::string content;
    uint64_t timestamp;
    std::vector<std::string> toolCalls;
    std::vector<std::string> toolResults;
};

// Conversation thread
struct Conversation {
    uint64_t id;
    std::string title;
    std::vector<ConversationTurn> turns;
    uint64_t created;
    uint64_t updated;
    std::vector<std::string> tags;
    std::unordered_map<std::string, std::string> metadata;
};

// Agent Memory System
class AgentMemory {
public:
    AgentMemory(const std::string& dbPath = ".sovereign/memory");
    ~AgentMemory();

    // Store memories
    uint64_t Store(const Memory& memory);
    uint64_t StoreEpisodic(const std::string& event, const std::string& source);
    uint64_t StoreSemantic(const std::string& fact, const std::vector<std::string>& tags);
    uint64_t StoreProcedural(const std::string& skill, const std::string& howTo);
    uint64_t StoreWorking(const std::string& context);
    uint64_t StoreReflection(const std::string& insight, float importance);

    // Retrieve memories
    std::vector<MemoryResult> Retrieve(const MemoryQuery& query);
    std::vector<MemoryResult> RetrieveSimilar(const std::string& content, size_t topK = 5);
    std::optional<Memory> RetrieveById(uint64_t id);
    std::vector<Memory> RetrieveByType(MemoryType type, size_t limit = 10);
    std::vector<Memory> RetrieveByTags(const std::vector<std::string>& tags);

    // Working memory
    void SetWorkingMemory(const std::string& key, const std::string& value);
    std::optional<std::string> GetWorkingMemory(const std::string& key);
    void ClearWorkingMemory();
    void ClearWorkingMemory(const std::string& key);

    // Conversation management
    uint64_t CreateConversation(const std::string& title);
    void AddTurn(uint64_t conversationId, const ConversationTurn& turn);
    std::optional<Conversation> GetConversation(uint64_t id);
    std::vector<uint64_t> ListConversations();
    void SummarizeConversation(uint64_t id);

    // Memory maintenance
    void Consolidate(); // Merge similar memories
    void Forget(uint64_t id); // Soft delete
    void Prune(float threshold); // Remove low-importance memories
    void Archive(uint64_t before); // Move old memories to archive

    // Knowledge graph
    void LinkMemories(uint64_t from, uint64_t to, const std::string& relation);
    std::vector<Memory> GetRelated(uint64_t id);
    std::vector<std::vector<Memory>> GetChains(const std::string& start, const std::string& end);

    // Importance scoring
    void UpdateImportance(uint64_t id, float delta);
    void BoostRecent(uint64_t windowMs);

    // Statistics
    size_t GetMemoryCount() const;
    size_t GetConversationCount() const;
    size_t GetWorkingMemorySize() const;

    // Persistence
    void Save();
    void Load();
    void Export(const std::string& path);
    void Import(const std::string& path);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Memory-augmented prompt builder
class MemoryAugmentedPrompt {
public:
    static std::string Build(
        AgentMemory& memory,
        const std::string& currentTask,
        const std::string& recentContext,
        size_t maxTokens = 4096
    );

private:
    static std::string RetrieveRelevantMemories(
        AgentMemory& memory,
        const std::string& task,
        size_t tokenBudget
    );
};

} // namespace Sovereign
