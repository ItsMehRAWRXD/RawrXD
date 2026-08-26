/**
 * \file agentic_text_edit.h
 * \brief Agentic text editor with LSP completions and ghost text
 * \author RawrXD Team
 * \date 2025-12-07
 */

#pragma once

#include <string>
#include <vector>
#include <functional>

// Forward declarations
class LSPClient;
class AICompletionProvider;
class GhostTextRenderer;
struct CompletionItem;
struct AICompletion;

namespace RawrXD {

/**
 * \brief Enhanced text editor with LSP integration and ghost text
 * 
 * Features:
 * - Two-phase initialization (lightweight constructor + explicit initialize())
 * - LSP client integration for real-time completions
 * - Ghost text overlay for inline suggestions
 * - Tab to accept, Esc to dismiss
 * - Auto-trigger completions on typing pause (300ms debounce)
 * - Multi-language support (C++, Python, JavaScript, etc.)
 */
class AgenticTextEdit {
public:
    explicit AgenticTextEdit(void* parent = nullptr);
    ~AgenticTextEdit();

    // Two-phase initialization
    void initialize();

    // LSP client integration
    void setLSPClient(LSPClient* client);
    LSPClient* lspClient() const { return m_lspClient; }

    // AI completion provider integration
    void setAICompletionProvider(AICompletionProvider* provider);
    AICompletionProvider* aiCompletionProvider() const { return m_aiProvider; }
    void setAICompletionsEnabled(bool enabled);
    bool aiCompletionsEnabled() const { return m_aiCompletionsEnabled; }

    // Ghost text renderer
    GhostTextRenderer* ghostRenderer() const { return m_ghostRenderer; }
    void setGhostRenderer(GhostTextRenderer* renderer);

    // Document management
    void setDocumentUri(const std::string& uri);
    std::string documentUri() const { return m_documentUri; }

    // Text buffer operations
    void setText(const std::string& text);
    std::string text() const;
    void insertPlainText(const std::string& text);
    void setCursorPosition(int pos);
    int cursorPosition() const;

    // Auto-completion settings
    void setAutoCompletionsEnabled(bool enabled);
    bool autoCompletionsEnabled() const { return m_autoCompletionsEnabled; }
    void setCompletionDelay(int ms);

    // Ghost text actions
    void acceptGhostText();
    void dismissGhostText();

    // Callbacks
    std::function<void(const std::string&)> onTextChangedCallback;
    std::function<void(const std::string&)> onCompletionAccepted;
    std::function<void()> onCompletionDismissed;

    // Key handling
    void keyPressEvent(void* event);

private:
    void onTextChanged();
    void onCursorPositionChanged();
    void onCompletionTimeout();
    void onCompletionsReceived(const std::string& uri, int line, int character,
                                const std::vector<CompletionItem>& items);
    void onAICompletionsReceived(const std::vector<AICompletion>& completions);
    void onAICompletionError(const std::string& error);
    void onGhostTextAccepted(const std::string& text);
    void onGhostTextDismissed();

    void triggerCompletion();
    void syncDocumentToLSP();
    std::string getCurrentLineText() const;
    std::string getCompletionPrefix() const;
    std::string getCompletionSuffix() const;
    bool shouldTriggerCompletion(const std::string& lineText) const;
    std::vector<CompletionItem> filterCompletions(const std::vector<CompletionItem>& items) const;
    void offsetToLineChar(int offset, int& line, int& character) const;
    void startCompletionTimer();
    void stopCompletionTimer();

    void* m_parent;
    LSPClient* m_lspClient;
    AICompletionProvider* m_aiProvider;
    GhostTextRenderer* m_ghostRenderer;
    
    std::string m_buffer;
    std::string m_documentUri;
    std::string m_languageId;
    int m_cursorPos;
    int m_documentVersion;
    
    void* m_completionTimer;
    int m_completionDelay;
    bool m_autoCompletionsEnabled;
    bool m_aiCompletionsEnabled;
    bool m_documentOpened;
    bool m_pendingCompletions;
};

} // namespace RawrXD

