// ============================================================================
// ContextEngine.hpp - Intelligent Context Assembly for AI IDE
// Transforms editor state into optimized prompts for Deep2
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>

namespace RawrXD {
namespace Context {

// Forward declarations
namespace Intelligence { class CodebaseIntelligence; }

// ============================================================================
// Context Priority Levels
// ============================================================================
enum class ContextPriority {
    Critical,    // Must include (current file, cursor position)
    High,        // Strongly related (imports, same module)
    Medium,      // Moderately related (dependencies)
    Low,         // Weakly related (transitive deps)
    Exclude      // Skip (irrelevant)
};

// ============================================================================
// Context Item Types
// ============================================================================
enum class ContextItemType {
    CurrentFile,
    OpenFile,
    RecentEdit,
    Import,
    Symbol,
    Error,
    Test,
    Documentation,
    Conversation,
    RepositoryPattern
};

// ============================================================================
// Context Item
// ============================================================================
struct ContextItem {
    ContextItemType type;
    ContextPriority priority;
    std::string content;
    std::string source;      // File path or origin
    uint32_t tokens = 0;     // Estimated token count
    float relevance = 0.0f;  // Relevance score
    std::chrono::system_clock::time_point timestamp;
};

// ============================================================================
// Editor State
// ============================================================================
struct EditorState {
    std::string filePath;
    std::string language;
    std::string prefix;      // Text before cursor
    std::string suffix;      // Text after cursor (FIM)
    std::string selectedText;
    uint32_t lineNumber = 0;
    uint32_t columnNumber = 0;
    
    // Recent edits
    struct Edit {
        std::string file;
        uint32_t startLine;
        uint32_t endLine;
        std::string change;
        std::chrono::system_clock::time_point timestamp;
    };
    std::vector<Edit> recentEdits;
    
    // Open files
    std::vector<std::string> openFiles;
    
    // Diagnostics
    struct Diagnostic {
        std::string file;
        uint32_t line;
        std::string message;
        std::string severity;  // error, warning, info
    };
    std::vector<Diagnostic> diagnostics;
};

// ============================================================================
// Context Budget
// ============================================================================
struct ContextBudget {
    uint32_t maxTokens = 4096;
    uint32_t reservedForResponse = 1024;
    uint32_t usedTokens = 0;
    
    uint32_t Available() const {
        return maxTokens - reservedForResponse - usedTokens;
    }
    
    bool CanFit(uint32_t tokens) const {
        return tokens <= Available();
    }
};

// ============================================================================
// Assembled Context
// ============================================================================
struct AssembledContext {
    std::string prompt;
    std::vector<ContextItem> items;
    uint32_t totalTokens = 0;
    ContextBudget budget;
    
    // Metadata
    std::string primaryLanguage;
    std::vector<std::string> includedFiles;
    std::vector<std::string> includedSymbols;
};

// ============================================================================
// Context Strategy
// ============================================================================
enum class ContextStrategy {
    Completion,      // FIM-style for ghost text
    Chat,            // Conversational context
    AgentTask,       // Autonomous coding task
    Debug,           // Error analysis
    Refactor,        // Code transformation
    Architecture     // High-level design
};

// ============================================================================
// Context Engine
// The brain between IDE and Deep2
// ============================================================================
class ContextEngine {
public:
    ContextEngine();
    ~ContextEngine();
    
    // Initialize with codebase intelligence
    bool Initialize(Intelligence::CodebaseIntelligence* intelligence);
    
    // Main entry: Assemble context for a request
    AssembledContext Assemble(
        const EditorState& editor,
        ContextStrategy strategy,
        const std::string& userQuery = ""
    );
    
    // Strategy-specific assemblers
    AssembledContext AssembleForCompletion(const EditorState& editor);
    AssembledContext AssembleForChat(const EditorState& editor, const std::string& query);
    AssembledContext AssembleForAgent(const EditorState& editor, const std::string& task);
    AssembledContext AssembleForDebug(const EditorState& editor);
    
    // Configuration
    void SetBudget(uint32_t maxTokens);
    void SetStrategyWeights(ContextStrategy strategy, const std::map<ContextItemType, float>& weights);
    
    // Cache management
    void InvalidateCache(const std::string& filePath);
    void ClearCache();
    
    // Statistics
    struct Stats {
        uint64_t assembliesTotal = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        double avgAssemblyTimeMs = 0.0;
        double avgContextTokens = 0.0;
    };
    Stats GetStats() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Token Counter (approximation)
// ============================================================================
class TokenCounter {
public:
    static uint32_t Count(const std::string& text);
    static uint32_t Count(const std::vector<ContextItem>& items);
    
    // Language-specific adjustments
    static uint32_t CountCode(const std::string& code, const std::string& language);
};

// ============================================================================
// Context Ranker
// Ranks items by relevance
// ============================================================================
class ContextRanker {
public:
    static std::vector<ContextItem> Rank(
        const std::vector<ContextItem>& items,
        const EditorState& editor,
        ContextStrategy strategy
    );
    
private:
    static float CalculateRelevance(
        const ContextItem& item,
        const EditorState& editor,
        ContextStrategy strategy
    );
};

// ============================================================================
// Prompt Builder
// Constructs final prompt from ranked items
// ============================================================================
class PromptBuilder {
public:
    static std::string Build(
        const std::vector<ContextItem>& items,
        ContextStrategy strategy,
        const std::string& userQuery
    );
    
    static std::string BuildFIMPrompt(
        const std::string& prefix,
        const std::string& suffix,
        const std::vector<ContextItem>& context
    );
    
    static std::string BuildChatPrompt(
        const std::vector<ContextItem>& context,
        const std::string& query,
        const std::vector<std::pair<std::string, std::string>>& history
    );
    
    static std::string BuildAgentPrompt(
        const std::vector<ContextItem>& context,
        const std::string& task,
        const std::vector<std::string>& availableTools
    );
};

} // namespace Context
} // namespace RawrXD
