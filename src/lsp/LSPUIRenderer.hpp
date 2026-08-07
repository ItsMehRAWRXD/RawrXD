// ============================================================================
// LSPUIRenderer.hpp - Production LSP UI Rendering for Scintilla
// ============================================================================
// Renders diagnostic squiggles, hover tooltips, signature help, autocomplete
// Fully production-ready with memory management, error handling, theming
// ============================================================================

#pragma once
#include <Windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>

// Forward declare Scintilla types
#ifndef SCINTILLA_H
struct Sci_NotifyHeader { HWND hwndFrom; uintptr_t idFrom; unsigned int code; };
struct SCNotification { Sci_NotifyHeader nmhdr; int position; int ch; int modifiers; int modificationType; const char* text; int length; int linesAdded; int message; uintptr_t wParam; intptr_t lParam; int line; int foldLevelNow; int foldLevelPrev; int margin; int x; int y; int token; int annotationLinesAdded; int updated; int listCompletionMethod; };
#endif

namespace rawrxd::lsp {

// ============================================================================
// Diagnostic - LSP Diagnostic with full positioning
// ============================================================================
struct Diagnostic {
    int startLine = 0, startCol = 0, endLine = 0, endCol = 0;
    std::string message;
    std::string code;
    std::string source;
    enum Severity { Error = 1, Warning = 2, Info = 3, Hint = 4 } severity = Error;
    
    // For quick lookup
    bool ContainsPosition(int line, int col) const {
        if (line < startLine || line > endLine) return false;
        if (line == startLine && col < startCol) return false;
        if (line == endLine && col > endCol) return false;
        return true;
    }
};

// ============================================================================
// HoverInfo - Tooltip content with markdown support
// ============================================================================
struct HoverInfo {
    std::string contents;
    std::string language;  // For code blocks
    int line = 0, col = 0;
    bool isTrusted = false;
};

// ============================================================================
// SignatureHelp - Function signature with parameter highlighting
// ============================================================================
struct SignatureInformation {
    std::string label;
    std::string documentation;
    std::vector<std::string> parameters;
};

struct SignatureHelp {
    std::vector<SignatureInformation> signatures;
    int activeSignature = 0;
    int activeParameter = -1;
};

// ============================================================================
// CompletionItem - Autocomplete entry with metadata
// ============================================================================
struct CompletionItem {
    std::string label;
    std::string kind;        // function, variable, class, etc.
    std::string detail;      // Type info
    std::string documentation;
    std::string insertText;
    int sortText = 0;
};

// ============================================================================
// Theme - Color scheme for LSP UI elements
// ============================================================================
struct LSPTheme {
    // Diagnostic colors
    COLORREF errorColor = RGB(255, 82, 82);
    COLORREF warningColor = RGB(255, 186, 66);
    COLORREF infoColor = RGB(66, 165, 245);
    COLORREF hintColor = RGB(158, 158, 158);
    
    // Tooltip colors
    COLORREF tooltipBg = RGB(45, 45, 48);
    COLORREF tooltipFg = RGB(255, 255, 255);
    COLORREF tooltipBorder = RGB(75, 75, 78);
    
    // Autocomplete colors
    COLORREF acBg = RGB(37, 37, 38);
    COLORREF acFg = RGB(212, 212, 212);
    COLORREF acSelectedBg = RGB(0, 122, 204);
    COLORREF acSelectedFg = RGB(255, 255, 255);
    
    // Signature help
    COLORREF sigBg = RGB(45, 45, 48);
    COLORREF sigFg = RGB(255, 255, 255);
    COLORREF paramHighlight = RGB(255, 215, 0);
};

// ============================================================================
// LSPUIRenderer - Production LSP UI for Scintilla
// ============================================================================
class LSPUIRenderer {
public:
    explicit LSPUIRenderer(HWND hEditor);
    ~LSPUIRenderer();

    // Disable copy/move
    LSPUIRenderer(const LSPUIRenderer&) = delete;
    LSPUIRenderer& operator=(const LSPUIRenderer&) = delete;

    // ── Initialization ──
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }

    // ── Theme ──
    void SetTheme(const LSPTheme& theme);
    const LSPTheme& GetTheme() const { return m_theme; }

    // ── Diagnostics (squiggles) ──
    void SetDiagnostics(const std::vector<Diagnostic>& diags);
    void ClearDiagnostics();
    void ClearDiagnosticsForFile(const std::string& filePath);
    const std::vector<Diagnostic>& GetCurrentDiagnostics() const { return m_currentDiagnostics; }
    
    // Get diagnostic at position for hover
    const Diagnostic* GetDiagnosticAt(int line, int col) const;

    // ── Hover Tooltips ──
    void ShowHover(const HoverInfo& info, int x, int y);
    void ShowHoverAtPosition(const HoverInfo& info, int line, int col);
    void HideHover();
    bool IsHoverVisible() const;

    // ── Signature Help ──
    void ShowSignature(const SignatureHelp& sig);
    void UpdateSignature(const SignatureHelp& sig);
    void HideSignature();
    bool IsSignatureVisible() const;
    void CycleSignature(int direction);  // +1 or -1

    // ── Autocomplete ──
    void ShowAutocomplete(const std::vector<CompletionItem>& completions, int line, int col);
    void UpdateAutocomplete(const std::vector<CompletionItem>& completions);
    void HideAutocomplete();
    bool IsAutocompleteVisible() const;
    int GetSelectedCompletion() const;
    void SelectCompletion(int index);
    void SelectNextCompletion();
    void SelectPreviousCompletion();
    std::string GetSelectedCompletionText() const;

    // ── Event Handlers ──
    void OnMouseMove(int x, int y);
    void OnMouseHover(int x, int y);
    void OnMouseLeave();
    void OnKeyDown(WPARAM key, LPARAM lParam);
    void OnChar(WPARAM ch);
    void OnScroll();
    void OnResize();
    void OnFocusLost();
    
    // Scintilla notification handler
    void OnScintillaNotify(const SCNotification* scn);

    // ── Callbacks ──
    using CompletionCallback = std::function<void(const std::string& insertText)>;
    using SignatureCycleCallback = std::function<void(int direction)>;
    using HoverRequestCallback = std::function<void(int line, int col)>;
    
    void SetCompletionCallback(CompletionCallback cb) { m_completionCallback = std::move(cb); }
    void SetSignatureCycleCallback(SignatureCycleCallback cb) { m_signatureCycleCallback = std::move(cb); }
    void SetHoverRequestCallback(HoverRequestCallback cb) { m_hoverRequestCallback = std::move(cb); }

private:
    HWND m_hEditor;
    HWND m_hTooltip;
    HWND m_hSignatureWindow;
    HWND m_hAutocompleteList;
    HWND m_hAutocompleteTooltip;
    
    bool m_initialized = false;
    LSPTheme m_theme;
    
    // Current state
    std::vector<Diagnostic> m_currentDiagnostics;
    std::vector<CompletionItem> m_currentCompletions;
    SignatureHelp m_currentSignature;
    HoverInfo m_currentHover;
    
    // Position tracking
    int m_hoverLine = -1, m_hoverCol = -1;
    int m_acLine = -1, m_acCol = -1;
    int m_sigLine = -1, m_sigCol = -1;
    
    // Callbacks
    CompletionCallback m_completionCallback;
    SignatureCycleCallback m_signatureCycleCallback;
    HoverRequestCallback m_hoverRequestCallback;
    
    // Scintilla indicator IDs
    static constexpr int INDIC_ERROR = 0;
    static constexpr int INDIC_WARNING = 1;
    static constexpr int INDIC_INFO = 2;
    static constexpr int INDIC_HINT = 3;
    
    // Creation
    bool CreateTooltipWindow();
    bool CreateSignatureWindow();
    bool CreateAutocompleteWindow();
    bool CreateAutocompleteTooltip();
    
    // Rendering
    void RenderTooltipContent(const HoverInfo& info);
    void RenderSignatureContent(const SignatureHelp& sig);
    void PopulateAutocompleteList(const std::vector<CompletionItem>& completions);
    void UpdateAutocompleteTooltip();
    
    // Positioning
    void PositionTooltip(int x, int y);
    void PositionSignature();
    void PositionAutocomplete();
    POINT GetScreenPosFromEditorPos(int line, int col);
    int PositionFromLineCol(int line, int col);
    void LineColFromPosition(int pos, int& line, int& col);
    
    // Scintilla helpers
    void SetupIndicators();
    void ApplyIndicator(int indicator, int start, int length, COLORREF color);
    void ClearIndicator(int indicator);
    
    // Message handling
    void OnAutocompleteNotify(LPARAM lParam);
    void OnTooltipPaint();
    void OnSignaturePaint();
    
    // Utility
    std::wstring Utf8ToWide(const std::string& utf8);
    std::string WideToUtf8(const std::wstring& wide);
    int GetLineHeight();
    int GetCharWidth();
    RECT GetEditorClientRect();
    bool IsEditorVisible();
};

} // namespace rawrxd::lsp
