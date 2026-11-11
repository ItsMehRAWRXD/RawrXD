/**
 * ============================================================================
 * AI Inline Editor - Cursor-style Cmd+K inline editing
 * ============================================================================
 * 
 * Features:
 * - Inline code generation/editing at cursor position
 * - Ghost text preview of AI suggestions
 * - Accept/reject diff view
 * - Multi-line edit support
 * - Context-aware prompt building
 * 
 * Reference: Cursor IDE's Cmd+K feature
 * ============================================================================
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <functional>
#include <optional>

namespace RawrXD {
namespace AI {

// Edit suggestion with diff information
struct InlineEditSuggestion {
    std::string originalCode;
    std::string suggestedCode;
    std::string explanation;
    int startLine;
    int endLine;
    float confidence;
    std::vector<std::string> alternatives;
};

// Context for inline editing
struct InlineEditContext {
    std::string filePath;
    std::string language;
    std::string selectedCode;
    std::string surroundingContext;  // 50 lines before/after
    std::string userInstruction;
    int cursorLine;
    int cursorColumn;
    std::vector<std::string> recentEdits;  // For continuity
};

// Ghost text preview
struct GhostTextPreview {
    std::string text;
    int insertLine;
    int insertColumn;
    bool isMultiLine;
    std::string highlightColor;  // "gray", "green", "red" for diff
};

class AIInlineEditor {
public:
    AIInlineEditor();
    ~AIInlineEditor();

    // Main entry: generate edit from instruction
    std::optional<InlineEditSuggestion> generateEdit(
        const InlineEditContext& context
    );

    // Generate ghost text preview
    std::optional<GhostTextPreview> generateGhostText(
        const InlineEditContext& context
    );

    // Quick actions (pre-defined prompts)
    std::optional<InlineEditSuggestion> explainCode(
        const InlineEditContext& context
    );
    
    std::optional<InlineEditSuggestion> refactorCode(
        const InlineEditContext& context,
        const std::string& refactorType  // "extract", "inline", "rename", "optimize"
    );
    
    std::optional<InlineEditSuggestion> generateDocumentation(
        const InlineEditContext& context
    );
    
    std::optional<InlineEditSuggestion> addErrorHandling(
        const InlineEditContext& context
    );
    
    std::optional<InlineEditSuggestion> addLogging(
        const InlineEditContext& context
    );
    
    std::optional<InlineEditSuggestion> optimizePerformance(
        const InlineEditContext& context
    );

    // Multi-file edit support
    struct MultiFileEdit {
        std::string filePath;
        std::vector<InlineEditSuggestion> edits;
    };
    
    std::vector<MultiFileEdit> generateMultiFileEdit(
        const std::vector<InlineEditContext>& contexts,
        const std::string& instruction
    );

    // Accept/reject handling
    void acceptEdit(const InlineEditSuggestion& suggestion);
    void rejectEdit(const InlineEditSuggestion& suggestion);
    void showDiffView(const InlineEditSuggestion& suggestion);

    // Configuration
    void setModel(const std::string& modelName);
    void setTemperature(float temp);
    void setMaxTokens(int tokens);

private:
    std::string buildPrompt(const InlineEditContext& context);
    std::string buildSystemPrompt();
    std::vector<std::string> parseAlternatives(const std::string& response);
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// Global instance for IDE integration
AIInlineEditor& GetAIInlineEditor();

} // namespace AI
} // namespace RawrXD
