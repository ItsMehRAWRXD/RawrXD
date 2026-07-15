// ai_ui_integration.h - UI Integration Layer for AI Features
#pragma once

#include "ai_code_review.h"
#include "ai_debugger.h"
#include <windows.h>
#include <string>
#include <memory>

namespace RawrXD {
namespace AI {

// Control IDs for AI UI elements
#define IDC_AI_INLINE_INPUT     9001
#define IDC_AI_INLINE_ACCEPT    9002
#define IDC_AI_INLINE_REJECT    9003
#define IDC_AI_DEBUGGER_PANEL   9004
#define IDC_AI_REVIEW_PANEL     9005

// Custom messages for AI integration
#define WM_AI_INSERT_TEXT       (WM_USER + 1000)
#define WM_AI_SHOW_COMPLETION   (WM_USER + 1001)
#define WM_AI_HIDE_COMPLETION   (WM_USER + 1002)
#define WM_AI_SHOW_INLINE       (WM_USER + 1003)
#define WM_AI_UPDATE_DEBUGGER   (WM_USER + 1004)
#define WM_AI_UPDATE_REVIEW     (WM_USER + 1005)

// Window procedure declarations
LRESULT CALLBACK InlineEditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK CompletionWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

// Global keyboard hook procedure
LRESULT CALLBACK AIKeyProc(int nCode, WPARAM wParam, LPARAM lParam);

// AI UI Manager - Central coordinator for all AI UI elements
class AIUIManager {
public:
    static AIUIManager& GetInstance();
    
    // Initialization
    void Initialize(HWND hwndMain);
    void Shutdown();
    
    // Inline Editor (Cmd+K)
    void ShowInlineEditor();
    void AcceptInlineEdit();
    void RejectInlineEdit();
    
    // Smart Completion (Tab to accept)
    void ShowCompletion(const std::string& text);
    void AcceptCompletion();
    void DismissAll();
    bool HasActiveCompletion() const;
    std::string GetGhostText() const;
    
    // Debugger Panel
    void UpdateDebuggerPanel(const std::string& text);
    void ShowDebuggerPanel();
    void HideDebuggerPanel();
    
    // Code Review Panel
    void UpdateReviewPanel(const std::vector<ReviewComment>& comments);
    void ShowReviewPanel();
    void HideReviewPanel();
    
    // Context management
    void SetCurrentContext(const std::string& file, int line, int col);
    void SetSelectedText(const std::string& text);
    
    // AI Feature Triggers
    void TriggerInlineEdit(const std::string& instruction);
    void TriggerSmartCompletion();
    void TriggerCodeReview();
    void TriggerDebuggerAnalysis();
    void TriggerCodeExplanation();
    void TriggerRefactoring(const std::string& instruction);
    void TriggerTestGeneration();
    void TriggerDocumentationGeneration();
    
    // Event handlers for IDE integration
    void OnEditorTextChanged(const std::string& file, 
                              const std::string& text,
                              int cursorLine, int cursorCol);
    void OnEditorSelectionChanged(const std::string& file,
                                   const std::string& selectedText,
                                   int startLine, int startCol,
                                   int endLine, int endCol);
    void OnDebuggerBreakpointHit(const DebugSession& session);
    void OnDebuggerException(const DebugSession& session, 
                                const std::string& exception);
    void OnFileSaved(const std::string& file, const std::string& content);
    void OnFileOpened(const std::string& file, const std::string& content);
    
    // Configuration
    void SetInlineEditorEnabled(bool enabled);
    void SetSmartCompletionEnabled(bool enabled);
    void SetCodeReviewEnabled(bool enabled);
    void SetDebuggerAIEnabled(bool enabled);
    void SetGhostTextEnabled(bool enabled);
    
    bool IsInlineEditorEnabled() const;
    bool IsSmartCompletionEnabled() const;
    bool IsCodeReviewEnabled() const;
    bool IsDebuggerAIEnabled() const;
    bool IsGhostTextEnabled() const;

private:
    AIUIManager();
    ~AIUIManager();
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    // Prevent copy
    AIUIManager(const AIUIManager&) = delete;
    AIUIManager& operator=(const AIUIManager&) = delete;
};

// Helper functions for menu/command integration
void RegisterAICommands(HWND hwnd);
void CreateAIMenu(HMENU hMenu);
void CreateAIToolbar(HWND hwndParent);

// Status bar integration
void UpdateAIStatus(const std::string& status);
void ShowAIProgress(bool show);

// Notification helpers
void ShowAICompletionNotification(const std::string& message);
void ShowAIErrorNotification(const std::string& error);
void ShowAIInfoNotification(const std::string& info);

} // namespace AI
} // namespace RawrXD
