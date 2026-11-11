// IntentCompression.hpp
// Coordination Primitive #6: Intent Compression Protocol
// Compress full conversation context to ~200 bytes for efficient routing

#pragma once
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <optional>
#include <chrono>
#include <functional>

namespace Sovereign {

// Compressed intent structure - ~200 bytes
struct CompressedIntent {
    uint8_t version;              // Protocol version
    uint8_t intent_type;          // Classification
    uint64_t timestamp;           // When created
    uint64_t context_hash;        // Hash of full context
    char goal_summary[64];        // Truncated goal
    char target_file[128];        // File being worked on
    uint32_t priority;            // Priority level
    uint32_t complexity;          // Estimated complexity
    uint16_t evidence_count;      // Number of evidence items
    uint16_t blocker_count;       // Number of blockers
    uint8_t flags;                // Various flags
    
    static constexpr size_t SIZE = 212;  // Total size
};

// Intent types for classification
enum class IntentType : uint8_t {
    UNKNOWN = 0,
    FILE_EDIT,           // Edit a file
    FILE_CREATE,         // Create new file
    FILE_DELETE,         // Delete file
    FILE_READ,           // Read/analyze file
    BUILD_REQUEST,       // Trigger build
    BUILD_CANCEL,        // Cancel build
    TERMINAL_COMMAND,    // Execute terminal command
    TERMINAL_KILL,       // Kill terminal process
    SEARCH_SYMBOL,       // Find symbol definition
    SEARCH_REFERENCES,   // Find all references
    REFACTOR_RENAME,     // Rename symbol
    REFACTOR_EXTRACT,    // Extract method/function
    DEBUG_START,         // Start debugging
    DEBUG_BREAKPOINT,    // Set breakpoint
    DEBUG_STEP,          // Step execution
    AGENT_SPAWN,         // Spawn sub-agent
    AGENT_KILL,          // Kill agent
    SYSTEM_CONFIG,       // Change configuration
    CHAT_MESSAGE,        // General chat
    CUSTOM = 255
};

// Evidence item - proof of context
struct EvidenceItem {
    std::string type;           // "file", "symbol", "error", "output"
    std::string reference;      // File path, symbol name, etc.
    std::string content_hash;   // Hash of content
    uint64_t timestamp;
    uint32_t relevance_score;   // 0-100, how relevant to intent
};

// Blocker - something preventing progress
struct Blocker {
    std::string type;           // "error", "dependency", "permission", "resource"
    std::string description;
    std::optional<std::string> blocking_file;
    std::optional<std::string> blocking_symbol;
    uint32_t severity;          // 1-10
};

// Full intent - uncompressed
struct FullIntent {
    std::string conversation_id;
    std::string agent_id;
    std::string original_prompt;
    std::string interpreted_goal;
    std::string target_file;
    std::string current_state;
    std::vector<EvidenceItem> evidence;
    std::vector<Blocker> blockers;
    std::string next_action;
    std::map<std::string, std::string> metadata;
    IntentType type;
    uint32_t priority;
    std::chrono::time_point<std::chrono::steady_clock> created;
};

// Intent compression engine
class IntentCompression {
public:
    static IntentCompression& Instance();
    
    // Compression
    CompressedIntent Compress(const FullIntent& intent);
    std::vector<uint8_t> Serialize(const CompressedIntent& compressed);
    
    // Decompression (partial - full context retrieved from store)
    FullIntent Decompress(const CompressedIntent& compressed);
    CompressedIntent Deserialize(const std::vector<uint8_t>& data);
    
    // Classification
    IntentType Classify(const std::string& prompt);
    std::vector<IntentType> ClassifyMulti(const std::string& prompt);
    
    // Evidence extraction
    std::vector<EvidenceItem> ExtractEvidence(const std::string& context);
    std::vector<Blocker> ExtractBlockers(const std::string& context);
    
    // Similarity matching
    float CalculateSimilarity(const CompressedIntent& a, const CompressedIntent& b);
    std::vector<FullIntent> FindSimilar(const CompressedIntent& query, size_t limit = 5);
    
    // Storage
    std::string StoreIntent(const FullIntent& intent);
    std::optional<FullIntent> RetrieveIntent(const std::string& intent_id);
    
    // Statistics
    struct CompressionStats {
        uint64_t total_compressed;
        uint64_t total_decompressed;
        double average_compression_ratio;
        double average_compression_time_ms;
        size_t storage_size_bytes;
        size_t intent_count;
    };
    CompressionStats GetStats() const;

private:
    IntentCompression();
    ~IntentCompression();
    
    IntentCompression(const IntentCompression&) = delete;
    IntentCompression& operator=(const IntentCompression&) = delete;
    
    uint64_t HashContext(const std::string& context);
    std::string Truncate(const std::string& str, size_t max_len);
    uint32_t EstimateComplexity(const FullIntent& intent);
    
    std::map<std::string, FullIntent> intent_store_;
    CompressionStats stats_;
};

// Intent router - routes compressed intents to appropriate handlers
class IntentRouter {
public:
    static IntentRouter& Instance();
    
    // Handler registration
    using IntentHandler = std::function<void(const CompressedIntent&, const FullIntent&)>;
    void RegisterHandler(IntentType type, IntentHandler handler);
    void RegisterDefaultHandler(IntentHandler handler);
    
    // Routing
    void Route(const CompressedIntent& compressed);
    void Route(const FullIntent& intent);
    
    // Batch routing
    void RouteBatch(const std::vector<CompressedIntent>& intents);
    
    // Query
    bool HasHandler(IntentType type) const;
    std::vector<IntentType> GetHandledTypes() const;

private:
    IntentRouter();
    ~IntentRouter();
    
    std::map<IntentType, IntentHandler> handlers_;
    IntentHandler default_handler_;
};

// Helper functions
const char* IntentTypeToString(IntentType type);
IntentType IntentTypeFromString(const std::string& str);

} // namespace Sovereign
