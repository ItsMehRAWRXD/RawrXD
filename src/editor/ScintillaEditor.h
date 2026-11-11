// ============================================================================
// ScintillaEditor.h - Modern Code Editor Control
// ============================================================================
// Replaces RichEdit with Scintilla for proper LSP support, syntax highlighting,
// multi-cursor editing, and all modern IDE features.
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <functional>

// Forward declarations for Scintilla
struct SCNotification;
typedef void* ScintillaObject;

namespace RawrXD {
namespace Editor {

// Editor capabilities flags
enum class EditorCapability {
    SYNTAX_HIGHLIGHTING,
    CODE_FOLDING,
    AUTO_COMPLETION,
    CALL_TIPS,
    MULTI_CURSOR,
    LSP_MARKERS,        // Error/warning squiggles
    LSP_INDICATORS,     // Highlight references
    GHOST_TEXT,         // Inline AI completions
    BRACE_MATCHING,
    LINE_NUMBERS,
    CODE_MARGIN,
    SCROLLBAR_MARKERS
};

// LSP Diagnostic severity
enum class DiagnosticSeverity {
    ERROR = 1,
    WARNING = 2,
    INFORMATION = 3,
    HINT = 4
};

// LSP Diagnostic structure
struct LSPDiagnostic {
    int line;
    int startColumn;
    int endColumn;
    DiagnosticSeverity severity;
    std::string message;
    std::string code;
    std::string source;
};

// Autocomplete item
struct AutoCompleteItem {
    std::string label;
    std::string detail;
    std::string documentation;
    std::string kind;  // function, variable, class, etc.
    std::string insertText;
};

// Ghost text (AI completion) segment
struct GhostTextSegment {
    int line;
    int column;
    std::string text;
    bool isInline;  // true = inline, false = multi-line block
};

// Editor configuration
struct EditorConfig {
    std::string fontName = "Consolas";
    int fontSize = 11;
    bool lineNumbers = true;
    bool codeFolding = true;
    bool autoIndent = true;
    bool braceMatching = true;
    bool virtualSpace = false;
    int tabWidth = 4;
    bool useSpaces = true;
    int marginWidth = 40;
    
    // Colors
    COLORREF colorBackground = RGB(30, 30, 30);
    COLORREF colorForeground = RGB(220, 220, 220);
    COLORREF colorLineNumber = RGB(100, 100, 100);
    COLORREF colorSelection = RGB(0, 120, 215);
    COLORREF colorCaret = RGB(255, 255, 255);
    
    // LSP colors
    COLORREF colorError = RGB(255, 100, 100);
    COLORREF colorWarning = RGB(255, 200, 100);
    COLORREF colorInfo = RGB(100, 200, 255);
    COLORREF colorHint = RGB(150, 150, 150);
};

// Callback types
using TextChangedCallback = std::function<void(int startLine, int endLine)>;
using CaretMovedCallback = std::function<void(int line, int column)>;
using CharAddedCallback = std::function<void(char ch)>;
using AutoCompleteSelectedCallback = std::function<void(const std::string& item)>;
using GhostTextAcceptedCallback = std::function<void()>;
using GhostTextRejectedCallback = std::function<void()>;

class ScintillaEditor {
public:
    ScintillaEditor();
    ~ScintillaEditor();
    
    // Window creation
    bool Create(HWND parentWindow, HINSTANCE hInstance, const RECT& rect);
    void Destroy();
    
    // Basic operations
    void SetText(const std::string& text);
    std::string GetText() const;
    std::string GetTextRange(int start, int end) const;
    void Clear();
    
    // Cursor and selection
    int GetCurrentPos() const;
    int GetCurrentLine() const;
    int GetCurrentColumn() const;
    void SetCaretPosition(int pos);
    void SetSelection(int start, int end);
    std::string GetSelectedText() const;
    void ReplaceSelection(const std::string& text);
    
    // Line operations
    int GetLineCount() const;
    std::string GetLine(int line) const;
    int GetLineLength(int line) const;
    void InsertText(int pos, const std::string& text);
    void DeleteRange(int start, int length);
    
    // Undo/Redo
    void Undo();
    void Redo();
    bool CanUndo() const;
    bool CanRedo() const;
    void EmptyUndoBuffer();
    
    // Search and replace
    int FindText(const std::string& text, int startPos = 0, bool matchCase = true, bool wholeWord = false);
    int ReplaceAll(const std::string& find, const std::string& replace);
    void EnsureVisible(int line);
    void ScrollToLine(int line);
    
    // Syntax highlighting
    void SetLexer(const std::string& language);  // "cpp", "python", "javascript", etc.
    void SetKeywords(int set, const std::string& keywords);
    void StyleSetForeground(int style, COLORREF color);
    void StyleSetBackground(int style, COLORREF color);
    void StyleSetBold(int style, bool bold);
    void StyleSetItalic(int style, bool italic);
    
    // LSP Integration
    void AddDiagnostic(const LSPDiagnostic& diagnostic);
    void ClearDiagnostics();
    void ClearDiagnostics(int line);
    void HighlightSymbol(int line, int startCol, int endCol);
    void ClearSymbolHighlights();
    
    // Autocomplete
    void ShowAutoComplete(const std::vector<AutoCompleteItem>& items);
    void HideAutoComplete();
    bool IsAutoCompleteActive() const;
    void AutoCompleteSelect(const std::string& text);
    
    // Call tips
    void ShowCallTip(int pos, const std::string& text);
    void HideCallTip();
    
    // Ghost text (AI completions)
    void ShowGhostText(const std::vector<GhostTextSegment>& segments);
    void HideGhostText();
    bool HasGhostText() const;
    void AcceptGhostText();
    void RejectGhostText();
    
    // Folding
    void FoldAll();
    void UnfoldAll();
    void ToggleFold(int line);
    bool IsLineFolded(int line) const;
    
    // Configuration
    void SetConfig(const EditorConfig& config);
    EditorConfig GetConfig() const;
    void ApplyTheme(const std::string& themeName);  // "dark", "light", "high-contrast"
    
    // Event callbacks
    void SetTextChangedCallback(TextChangedCallback callback);
    void SetCaretMovedCallback(CaretMovedCallback callback);
    void SetCharAddedCallback(CharAddedCallback callback);
    void SetAutoCompleteSelectedCallback(AutoCompleteSelectedCallback callback);
    void SetGhostTextAcceptedCallback(GhostTextAcceptedCallback callback);
    void SetGhostTextRejectedCallback(GhostTextRejectedCallback callback);
    
    // Window message handling
    LRESULT HandleNotify(SCNotification* notification);
    void HandleMessage(UINT msg, WPARAM wParam, LPARAM lParam);
    
    // DPI awareness
    void SetDPI(int dpi);
    int GetDPI() const;
    
    // Save/Load
    bool LoadFile(const std::string& path);
    bool SaveFile(const std::string& path);
    void SetReadOnly(bool readOnly);
    bool IsReadOnly() const;
    
    // Access to underlying Scintilla control
    HWND GetHWND() const;
    ScintillaObject* GetScintillaObject() const;
    
    // Capabilities
    bool HasCapability(EditorCapability cap) const;
    std::vector<EditorCapability> GetCapabilities() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    // Internal helpers
    void InitializeScintilla();
    void SetupStyles();
    void SetupMargins();
    void SetupLSPIndicators();
    void SetupAutoComplete();
    void SetupGhostText();
    
    // Scintilla direct function pointer
    using SciFnDirect = sptr_t(*)(sptr_t ptr, unsigned int iMessage, uptr_t wParam, sptr_t lParam);
    SciFnDirect fnDirect_;
    sptr_t ptrDirect_;
};

// Factory function
std::unique_ptr<ScintillaEditor> CreateScintillaEditor();

} // namespace Editor
} // namespace RawrXD
