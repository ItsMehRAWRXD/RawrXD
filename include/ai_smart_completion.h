/**
 * ============================================================================
 * Smart Code Completion - Beyond IntelliSense
 * ============================================================================
 * 
 * Features:
 * - Whole-line completion (like GitHub Copilot)
 * - Multi-line completion
 * - Context-aware suggestions
 * - Learning from user patterns
 * - Fuzzy matching for symbols
 * - Type-aware completion
 * 
 * Reference: GitHub Copilot, Cursor Tab
 * ============================================================================
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <vector>
#include <optional>
#include <chrono>

namespace RawrXD {
namespace AI {

// Completion item types
enum class CompletionType {
    SingleToken,      // Single word/token
    WholeLine,        // Complete line
    MultiLine,        // Multiple lines
    Block,            // Code block
    Import,           // Import statement
    Function,         // Function call
    Class,            // Class definition
    Comment           // Documentation comment
};

// Completion suggestion
struct SmartCompletion {
    std::string text;
    std::string displayText;
    std::string detail;           // Type info, signature
    std::string documentation;
    CompletionType type;
    float confidence;
    int insertStart;              // Where to start insertion
    int insertEnd;                // Where to end insertion (for replacement)
    std::vector<std::string> alternatives;
    bool isSnippet;
    std::string snippetPlaceholder;  // ${1:placeholder}
};

// Context for completion
struct CompletionContext {
    std::string filePath;
    std::string language;
    std::string prefix;           // Text before cursor
    std::string suffix;           // Text after cursor
    std::string linePrefix;       // Current line before cursor
    std::string lineSuffix;       // Current line after cursor
    int line;
    int column;
    
    // Semantic context
    std::string scope;            // Current scope (class, function, etc.)
    std::string expectedType;     // Expected type at cursor
    std::vector<std::string> visibleSymbols;
    std::vector<std::string> importedModules;
    
    // Recent context
    std::vector<std::string> recentCompletions;
    std::chrono::steady_clock::time_point lastEditTime;
};

// User preference learning
struct CompletionPreferences {
    std::vector<std::string> frequentlyUsed;
    std::vector<std::string> rarelyAccepted;
    float averageAcceptanceTime;
    int totalCompletions;
    int acceptedCompletions;
};

class SmartCodeCompletion {
public:
    SmartCodeCompletion();
    ~SmartCodeCompletion();

    // Main completion API
    std::vector<SmartCompletion> getCompletions(
        const CompletionContext& context,
        int maxResults = 5
    );

    // Real-time completion (as user types)
    std::optional<SmartCompletion> getRealtimeCompletion(
        const CompletionContext& context
    );

    // Whole-line completion
    std::optional<SmartCompletion> getLineCompletion(
        const CompletionContext& context
    );

    // Multi-line block completion
    std::optional<SmartCompletion> getBlockCompletion(
        const CompletionContext& context
    );

    // Ghost text for inline preview
    std::optional<std::string> getGhostText(
        const CompletionContext& context
    );

    // Learning from user behavior
    void recordCompletionAccepted(const SmartCompletion& completion);
    void recordCompletionRejected(const SmartCompletion& completion);
    void recordCompletionModified(const SmartCompletion& completion, 
                                   const std::string& modifiedText);

    // Preference management
    CompletionPreferences getPreferences() const;
    void updatePreferences(const CompletionPreferences& prefs);

    // Configuration
    void setEnabled(bool enabled);
    void setDelay(int milliseconds);  // Debounce delay
    void setModel(const std::string& modelName);
    void setTemperature(float temp);

    // Performance
    bool isReady() const;
    float getLatencyMs() const;

private:
    std::string buildPrompt(const CompletionContext& context);
    std::vector<SmartCompletion> parseCompletions(const std::string& response);
    float calculateRelevance(const SmartCompletion& completion, 
                              const CompletionContext& context);
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// Global instance
SmartCodeCompletion& GetSmartCodeCompletion();

} // namespace AI
} // namespace RawrXD
