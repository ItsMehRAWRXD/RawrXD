#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <queue>
#include <mutex>
#include <chrono>

namespace rawrxd {
namespace swarm {

// Token representation
struct Token {
    uint32_t id;
    std::string text;
    float embedding[768]; // DeepSeek V3 embedding dimension
    float importance{1.0f}; // For selective attention
    std::chrono::steady_clock::time_point timestamp;
};

// Context window segment
struct ContextSegment {
    std::vector<Token> tokens;
    std::string summary; // Compressed representation
    float relevanceScore{1.0f};
    std::string category; // "system", "user", "assistant", "tool", "memory"
    size_t priority{0};
    bool compressed{false};
};

// Attention weights for selective focus
struct AttentionWeights {
    std::vector<float> query;
    std::vector<float> key;
    std::vector<float> value;
    float temperature{1.0f};
    float topP{0.9f};
};

// Memory tier
enum class MemoryTier {
    ACTIVE,      // In current context window
    WORKING,     // Recently used, quick recall
    LONG_TERM,   // Compressed summaries
    ARCHIVE      // Disk-backed
};

// Context statistics
struct ContextStats {
    size_t totalTokens{0};
    size_t activeTokens{0};
    size_t compressedTokens{0};
    size_t cacheHits{0};
    size_t cacheMisses{0};
    float avgCompressionRatio{0.0f};
    std::chrono::milliseconds lastAccessTime;
};

// Deep Context Manager - 256K token context window with intelligent management
class DeepContextManager {
public:
    static constexpr size_t MAX_CONTEXT_TOKENS = 256000; // 256K tokens
    static constexpr size_t COMPRESSION_THRESHOLD = 64000; // 64K before compression
    
    DeepContextManager();
    ~DeepContextManager();
    
    // Token management
    void addTokens(const std::vector<Token>& tokens, const std::string& category);
    void addText(const std::string& text, const std::string& category);
    void addSystemPrompt(const std::string& prompt);
    void addUserMessage(const std::string& message);
    void addAssistantResponse(const std::string& response);
    void addToolResult(const std::string& toolName, const std::string& result);
    
    // Context retrieval
    std::vector<Token> getContextForInference(size_t maxTokens = 32768);
    std::vector<Token> getRelevantContext(const std::string& query, size_t maxTokens);
    std::string getContextAsText(size_t maxTokens = 8192);
    
    // Selective attention
    void setFocusTokens(const std::vector<std::string>& keywords);
    void boostTokenImportance(const std::vector<uint32_t>& tokenIds, float boost);
    void applySelectiveAttention(std::vector<Token>& tokens);
    
    // Compression and summarization
    void compressOldSegments();
    std::string summarizeSegment(const ContextSegment& segment);
    void mergeCompressedSegments();
    
    // Memory management
    void promoteToWorkingMemory(const std::vector<Token>& tokens);
    void archiveOldContext();
    void recallFromLongTerm(const std::string& query);
    
    // Sliding window with overlap
    void advanceWindow(size_t newTokens);
    void setWindowOverlap(size_t tokens);
    
    // Cache management
    void invalidateCache();
    void warmCache(const std::vector<std::string>& likelyQueries);
    
    // Statistics
    ContextStats getStats() const;
    size_t getTokenCount() const;
    size_t getAvailableSpace() const;
    float getUtilization() const;
    
    // Importance scoring
    float calculateTokenImportance(const Token& token);
    void updateImportanceScores();
    std::vector<Token> pruneLowImportanceTokens(size_t targetCount);
    
    // Context manipulation
    void clear();
    void clearCategory(const std::string& category);
    void rewind(size_t tokenCount);
    void forkContext(const std::string& branchName);
    void switchBranch(const std::string& branchName);
    
    // Serialization
    std::string serialize() const;
    void deserialize(const std::string& data);
    void saveToDisk(const std::string& path);
    void loadFromDisk(const std::string& path);
    
    // Multi-turn conversation handling
    void startNewTurn();
    void endTurn();
    size_t getTurnCount() const;
    std::vector<Token> getTurnTokens(size_t turnIndex) const;
    
    // Tool context integration
    void registerToolContext(const std::string& toolName, const std::string& contextSchema);
    void injectToolContext(const std::string& toolName);
    
private:
    std::vector<ContextSegment> segments_;
    std::map<std::string, std::vector<Token>> categoryIndex_;
    std::map<std::string, std::string> compressedMemories_;
    std::queue<Token> tokenQueue_;
    
    mutable std::mutex mutex_;
    
    ContextStats stats_;
    size_t windowOverlap_{1024};
    size_t currentTurn_{0};
    
    std::vector<std::string> focusKeywords_;
    std::map<uint32_t, float> importanceBoosts_;
    
    // Branching support
    std::map<std::string, std::vector<ContextSegment>> branches_;
    std::string currentBranch_{"main"};
    
    // Tool context registry
    std::map<std::string, std::string> toolContexts_;
    
    // Internal methods
    void maintainTokenLimit();
    void updateStats();
    std::vector<Token> flattenSegments(const std::vector<ContextSegment>& segs);
    float cosineSimilarity(const float* a, const float* b, size_t dim);
};

} // namespace swarm
} // namespace rawrxd
