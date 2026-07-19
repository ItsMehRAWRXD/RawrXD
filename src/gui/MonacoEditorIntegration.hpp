#pragma once
// ============================================================================
// MonacoEditorIntegration.hpp - Full-Featured Editor with AI Integration
// Context menus, ghost text, explain/review/refactor, enterprise features
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>

// Forward declarations
namespace RawrXD {
    class EditorAgentIntegration;
    class GhostTextRenderer;
}

// Context menu item types
enum class EditorContextAction {
    // Standard editing
    Cut,
    Copy,
    Paste,
    SelectAll,
    Undo,
    Redo,
    
    // AI-powered features
    ExplainCode,
    ReviewCode,
    RefactorCode,
    GenerateDocs,
    GenerateTests,
    OptimizeCode,
    
    // Navigation
    GoToDefinition,
    FindReferences,
    PeekDefinition,
    
    // Refactoring
    RenameSymbol,
    ExtractMethod,
    ExtractVariable,
    InlineVariable,
    
    // Enterprise
    ShowHistory,
    ShowBlame,
    CreatePullRequest,
    StartCodeReview,
    ShareCodeSnippet,
    
    // Ghost text
    AcceptSuggestion,
    NextSuggestion,
    PreviousSuggestion,
    DismissSuggestion,
    
    // Diagnostics
    QuickFix,
    ShowErrorDetails,
    SuppressWarning,
    
    // Separator
    Separator
};

struct ContextMenuItem {
    std::wstring label;
    std::wstring shortcut;
    EditorContextAction action;
    bool enabled;
    bool checked;
    std::function<void()> customHandler;
};

// ============================================================================
// MonacoEditorIntegration - Main Editor Class
// ============================================================================
class MonacoEditorIntegration {
public:
    MonacoEditorIntegration(HWND hwndParent);
    ~MonacoEditorIntegration();

    // Initialization
    bool Initialize();
    void Shutdown();
    
    // Window management
    HWND GetHwnd() const { return m_hwndEditor; }
    void Resize(int x, int y, int width, int height);
    void Focus();
    
    // Text operations
    void SetText(const std::wstring& text);
    std::wstring GetText() const;
    std::wstring GetSelectedText() const;
    void InsertText(const std::wstring& text, int line, int column);
    void ReplaceSelection(const std::wstring& text);
    void DeleteSelection();
    
    // Clipboard
    void Cut();
    void Copy();
    void Paste();
    void SelectAll();
    bool CanUndo() const;
    bool CanRedo() const;
    void Undo();
    void Redo();
    
    // Cursor and selection
    void GetCursorPosition(int& line, int& column) const;
    void SetCursorPosition(int line, int column);
    void GetSelection(int& startLine, int& startCol, int& endLine, int& endCol) const;
    bool HasSelection() const;
    void ClearSelection();
    
    // Context menu
    void ShowContextMenu(int x, int y);
    void RegisterContextMenuHandler(EditorContextAction action, std::function<void()> handler);
    
    // AI Features - Ghost Text
    void EnableGhostText(bool enable);
    bool IsGhostTextEnabled() const;
    void TriggerSuggestion();
    void AcceptSuggestion();
    void DismissSuggestion();
    void NextSuggestion();
    void PreviousSuggestion();
    bool HasActiveSuggestion() const;
    
    // AI Features - Code Actions
    void ExplainCode();
    void ReviewCode();
    void RefactorCode(const std::string& refactoringType = "general");
    void GenerateDocumentation();
    void GenerateTests();
    void OptimizeCode();
    
    // Navigation
    void GoToDefinition();
    void FindReferences();
    void PeekDefinition();
    
    // Refactoring
    void RenameSymbol(const std::wstring& newName);
    void ExtractMethod(const std::wstring& methodName);
    void ExtractVariable(const std::wstring& varName);
    void InlineVariable();
    
    // Enterprise Features
    void ShowGitHistory();
    void ShowGitBlame();
    void CreatePullRequest();
    void StartCodeReview();
    void ShareCodeSnippet();
    
    // Diagnostics
    void ShowDiagnosticTooltip(int line);
    void QuickFixDiagnostic(int line);
    void SuppressDiagnostic(int line);
    
    // File operations
    void SetFilePath(const std::wstring& path);
    std::wstring GetFilePath() const;
    bool IsModified() const;
    void MarkModified(bool modified);
    
    // Status
    void UpdateStatusBar();
    
    // Event callbacks
    std::function<void()> OnTextChanged;
    std::function<void()> OnCursorMoved;
    std::function<void()> OnSelectionChanged;
    std::function<void()> OnFileModified;
    std::function<void(const std::wstring&)> OnGhostTextAccepted;
    std::function<void(const std::wstring&)> OnCodeActionCompleted;
    
private:
    // Window procedure
    static LRESULT CALLBACK EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // Context menu
    void BuildContextMenu(HMENU hMenu, bool hasSelection);
    void ExecuteContextAction(EditorContextAction action);
    void ShowAIActionsSubmenu(HMENU hMenu);
    void ShowRefactoringSubmenu(HMENU hMenu);
    void ShowNavigationSubmenu(HMENU hMenu);
    void ShowEnterpriseSubmenu(HMENU hMenu);
    
    // Ghost text integration
    void InitializeGhostText();
    void PaintGhostText(HDC hdc);
    void UpdateGhostTextPosition();
    
    // AI integration
    void CallExplainAPI(const std::wstring& code);
    void CallReviewAPI(const std::wstring& code);
    void CallRefactorAPI(const std::wstring& code, const std::string& type);
    void CallGenerateDocsAPI(const std::wstring& code);
    void CallGenerateTestsAPI(const std::wstring& code);
    void CallOptimizeAPI(const std::wstring& code);
    
    // Rendering
    void OnPaint();
    void OnResize(int width, int height);
    void OnKeyDown(WPARAM key);
    void OnChar(WPARAM ch);
    void OnMouseClick(int x, int y, bool rightClick);
    void OnMouseDoubleClick(int x, int y);
    void OnScroll(int delta);
    
    // Member variables
    HWND m_hwndEditor;
    HWND m_hwndParent;
    HWND m_hwndStatusBar;
    HWND m_hwndGhostOverlay;
    
    // Editor state
    std::wstring m_filePath;
    bool m_isModified;
    bool m_hasSelection;
    int m_cursorLine;
    int m_cursorColumn;
    int m_selectionStartLine;
    int m_selectionStartCol;
    int m_selectionEndLine;
    int m_selectionEndCol;
    
    // Ghost text
    bool m_ghostTextEnabled;
    bool m_hasActiveSuggestion;
    std::wstring m_currentSuggestion;
    std::vector<std::wstring> m_suggestionQueue;
    size_t m_currentSuggestionIndex;
    
    // Context menu handlers
    std::unordered_map<EditorContextAction, std::function<void()>> m_contextHandlers;
    
    // AI integration
    std::unique_ptr<RawrXD::EditorAgentIntegration> m_agentIntegration;
    
    // Fonts and rendering
    HFONT m_hFont;
    HFONT m_hFontGhost;
    HBRUSH m_hBrushBackground;
    HBRUSH m_hBrushSelection;
    
    // Line data
    struct LineInfo {
        std::wstring text;
        bool hasDiagnostic;
        std::wstring diagnosticMessage;
        int diagnosticSeverity; // 0=error, 1=warning, 2=info
    };
    std::vector<LineInfo> m_lines;
    
    // Scroll position
    int m_scrollOffsetY;
    int m_scrollOffsetX;
    
    // Metrics
    int m_lineHeight;
    int m_charWidth;
    int m_lineNumberWidth;
    
    // Static instance for WndProc
    static MonacoEditorIntegration* s_instance;
};

// ============================================================================
// Helper Functions
// ============================================================================
bool InitializeMonacoEditorSystem();
void ShutdownMonacoEditorSystem();
MonacoEditorIntegration* CreateMonacoEditor(HWND hwndParent);
void DestroyMonacoEditor(MonacoEditorIntegration* editor);
