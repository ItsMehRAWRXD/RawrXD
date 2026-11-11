// ============================================================================
// RawrXD Codex LSP Bridge
// Integrates Codex AI completions with LSP infrastructure
// Provides inline completions, code actions, and hover info via Codex
// ============================================================================

#pragma once
#include "CodexCLI.hpp"
#include "CodexEventBus.hpp"
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>

namespace RawrXD {
namespace Codex {

// LSP-compatible position (0-based line, 0-based character)
struct Position {
    int line = 0;
    int character = 0;
};

// LSP-compatible range
struct Range {
    Position start;
    Position end;
};

// Inline completion item (LSP-compatible)
struct InlineCompletionItem {
    std::string insertText;
    Range range;           // Range to replace (optional)
    std::string text;      // Display text
    std::string tooltip;   // Hover tooltip
    float confidence = 0.0f;
    std::string model;     // Source model
    uint64_t timestamp = 0;
};

// Code action (quick fix, refactor, etc.)
struct CodexCodeAction {
    std::string title;
    std::string kind;      // "quickfix", "refactor", "explain", etc.
    std::string edit;      // Text edit to apply
    Range range;
    float confidence = 0.0f;
};

// Hover information
struct CodexHoverInfo {
    std::string contents;     // Markdown content
    Range range;
    bool valid = false;
};

// Context for completion requests
struct CompletionContext {
    std::string filePath;
    std::string language;
    Position cursor;
    std::string prefix;       // Text before cursor
    std::string suffix;       // Text after cursor
    std::string surrounding;  // ~50 lines of context
};

// Codex LSP Bridge - integrates Codex with IDE's LSP system
class CodexLSPBridge {
public:
    CodexLSPBridge();
    ~CodexLSPBridge();

    // Initialize with CLI backend
    bool Initialize(std::shared_ptr<CodexCLI> cli);
    
    // Shutdown
    void Shutdown();
    
    // Check if initialized
    bool IsInitialized() const { return m_initialized.load(); }
    
    // --- Inline Completions (LSP: textDocument/inlineCompletion) ---
    
    // Request inline completions at position
    std::vector<InlineCompletionItem> ProvideInlineCompletions(
        const CompletionContext& context,
        int maxItems = 3
    );
    
    // Request single completion (simplified)
    std::string CompleteAt(const CompletionContext& context);
    
    // Cancel pending completion
    void CancelPendingCompletion();
    
    // --- Code Actions (LSP: textDocument/codeAction) ---
    
    // Provide code actions for range
    std::vector<CodexCodeAction> ProvideCodeActions(
        const std::string& filePath,
        const Range& range,
        const std::string& selectedText,
        const std::string& language
    );
    
    // Explain code at range
    CodexCodeAction ExplainCode(
        const std::string& filePath,
        const Range& range,
        const std::string& selectedText
    );
    
    // Refactor code at range
    CodexCodeAction RefactorCode(
        const std::string& filePath,
        const Range& range,
        const std::string& selectedText,
        const std::string& instruction
    );
    
    // Generate tests for code
    CodexCodeAction GenerateTests(
        const std::string& filePath,
        const Range& range,
        const std::string& selectedText
    );
    
    // Fix errors in code
    CodexCodeAction FixErrors(
        const std::string& filePath,
        const Range& range,
        const std::string& selectedText,
        const std::string& errorMessage
    );
    
    // --- Hover (LSP: textDocument/hover) ---
    
    // Provide hover info for symbol
    CodexHoverInfo ProvideHover(
        const std::string& filePath,
        const Position& position,
        const std::string& symbol,
        const std::string& surroundingContext
    );
    
    // --- Event Streaming ---
    
    // Enable/disable streaming completions
    void SetStreamingEnabled(bool enabled) { m_streamingEnabled = enabled; }
    bool IsStreamingEnabled() const { return m_streamingEnabled; }
    
    // Set callback for streaming chunks
    using StreamCallback = std::function<void(const std::string& chunk, bool isFinal)>;
    void SetStreamCallback(StreamCallback callback) { m_streamCallback = callback; }

private:
    std::shared_ptr<CodexCLI> m_cli;
    std::shared_ptr<CodexEventBus> m_eventBus;
    std::atomic<bool> m_initialized{false};
    std::atomic<bool> m_cancelled{false};
    std::atomic<bool> m_streamingEnabled{true};
    StreamCallback m_streamCallback;
    
    // Helper methods
    std::string BuildCompletionPrompt(const CompletionContext& ctx);
    std::string BuildExplanationPrompt(const std::string& code, const std::string& language);
    std::string BuildRefactorPrompt(const std::string& code, const std::string& instruction);
    std::string BuildTestPrompt(const std::string& code, const std::string& language);
    std::string BuildFixPrompt(const std::string& code, const std::string& error);
    std::string BuildHoverPrompt(const std::string& symbol, const std::string& context);
    
    // Extract language from file path
    std::string DetectLanguage(const std::string& filePath);
    
    // Truncate text to token limit (approximate)
    std::string TruncateToContext(const std::string& text, size_t maxChars = 4000);
};

} // namespace Codex
} // namespace RawrXD
