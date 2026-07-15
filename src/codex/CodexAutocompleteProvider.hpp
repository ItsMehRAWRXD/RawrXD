// ============================================================================
// RawrXD Codex Autocomplete Provider
// Integrates Codex AI completions with IDE autocomplete system
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include "CodexLSPBridge.hpp"
#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <atomic>

namespace RawrXD {
namespace Codex {

// Autocomplete item for IDE integration
struct AutocompleteItem {
    std::string label;           // Display text
    std::string insertText;      // Text to insert
    std::string detail;          // Additional info (type, etc.)
    std::string documentation;   // Full documentation
    std::string kind;            // "function", "variable", "class", etc.
    float confidence = 0.0f;     // AI confidence score
    std::string source;          // "codex", "lsp", "hybrid"
    int sortOrder = 0;           // Sort priority
};

// Completion context from IDE
struct AutocompleteContext {
    std::string filePath;
    std::string language;
    int line = 0;                // 0-based line
    int column = 0;              // 0-based column
    std::string prefix;          // Text before cursor
    std::string suffix;          // Text after cursor
    std::string lineText;        // Full line text
    std::string surrounding;     // ~20 lines of context
    bool isNewLine = false;      // Cursor at start of line
    bool afterDot = false;       // Cursor after '.' or '->'
    bool afterParen = false;     // Cursor after '('
};

// Codex Autocomplete Provider - integrates with IDE completion system
class CodexAutocompleteProvider {
public:
    CodexAutocompleteProvider();
    ~CodexAutocompleteProvider();

    // Initialize with CLI backend
    bool Initialize(std::shared_ptr<CodexCLI> cli);
    
    // Shutdown
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized.load(); }
    
    // --- Completion Provider Interface ---
    
    // Provide completions for context (main entry point)
    std::vector<AutocompleteItem> ProvideCompletions(
        const AutocompleteContext& context,
        int maxItems = 5
    );
    
    // Quick check if completions should be provided
    bool ShouldProvideCompletions(const AutocompleteContext& context);
    
    // Cancel pending completion
    void CancelPending();
    
    // --- Configuration ---
    
    // Enable/disable provider
    void SetEnabled(bool enabled) { m_enabled = enabled; }
    bool IsEnabled() const { return m_enabled; }
    
    // Set minimum confidence threshold (0.0 - 1.0)
    void SetConfidenceThreshold(float threshold) { 
        m_confidenceThreshold = std::max(0.0f, std::min(1.0f, threshold)); 
    }
    float GetConfidenceThreshold() const { return m_confidenceThreshold; }
    
    // Set max context lines
    void SetMaxContextLines(int lines) { m_maxContextLines = lines; }
    int GetMaxContextLines() const { return m_maxContextLines; }
    
    // Set trigger characters (when to auto-trigger)
    const std::vector<std::string>& GetTriggerCharacters() const { 
        return m_triggerChars; 
    }
    void AddTriggerCharacter(const std::string& ch) {
        m_triggerChars.push_back(ch);
    }
    
    // --- Hybrid Completion Support ---
    
    // Merge Codex completions with LSP completions
    std::vector<AutocompleteItem> MergeWithLSPCompletions(
        const std::vector<AutocompleteItem>& codexItems,
        const std::vector<AutocompleteItem>& lspItems,
        int maxTotal = 10
    );
    
    // Set callback for async completions
    using CompletionCallback = std::function<void(const std::vector<AutocompleteItem>&)>;
    void SetAsyncCallback(CompletionCallback callback) { m_asyncCallback = callback; }
    
    // Request async completion
    void RequestAsyncCompletion(const AutocompleteContext& context);

private:
    std::shared_ptr<CodexCLI> m_cli;
    std::shared_ptr<CodexLSPBridge> m_lspBridge;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_enabled{true};
    std::atomic<bool> m_cancelled{false};
    std::atomic<bool> m_asyncPending{false};
    
    // Configuration
    float m_confidenceThreshold = 0.6f;
    int m_maxContextLines = 20;
    std::vector<std::string> m_triggerChars = {".", "->", "::", "(", "[", " ", "\t"};
    
    // Async callback
    CompletionCallback m_asyncCallback;
    
    // Helper methods
    std::string BuildCompletionPrompt(const AutocompleteContext& ctx);
    std::vector<AutocompleteItem> ParseCompletionResponse(const std::string& response);
    float CalculateConfidence(const std::string& completion);
    bool IsTriggerCharacter(const std::string& prefix);
    std::string ExtractLanguage(const std::string& filePath);
    
    // Async worker
    void AsyncCompletionWorker(const AutocompleteContext& context);
};

} // namespace Codex
} // namespace RawrXD
