#pragma once
#include <string>
#include <vector>
#include <string>
#include <functional>

namespace IDE {

// Simple text buffer for editing
class TextBuffer {
public:
    TextBuffer();
    ~TextBuffer();
    
    bool LoadFromFile(const char* path);
    bool SaveToFile(const char* path);
    void Clear();
    
    // Editing
    void InsertText(int line, int col, const char* text);
    void DeleteText(int line, int startCol, int endCol);
    void DeleteLine(int line);
    void InsertLine(int line, const char* text);
    
    // Access
    const char* GetLine(int line) const;
    int GetLineCount() const;
    int GetLineLength(int line) const;
    
    // Cursor
    void SetCursor(int line, int col);
    void GetCursor(int& line, int& col) const;
    
    // Selection
    void SetSelection(int startLine, int startCol, int endLine, int endCol);
    bool HasSelection() const;
    void ClearSelection();
    std::string GetSelectedText() const;
    void DeleteSelection();
    
    // Undo/Redo
    void Undo();
    void Redo();
    bool CanUndo() const;
    bool CanRedo() const;
    
    // State
    bool IsModified() const { return m_modified; }
    void SetModified(bool modified) { m_modified = modified; }
    const char* GetFilePath() const { return m_filePath; }
    const char* GetFileName() const;
    
private:
    std::vector<std::string> m_lines;
    char m_filePath[512];
    bool m_modified;
    
    int m_cursorLine;
    int m_cursorCol;
    
    int m_selStartLine, m_selStartCol;
    int m_selEndLine, m_selEndCol;
    bool m_hasSelection;
    
    // Undo stack
    struct EditAction {
        enum Type { Insert, Delete, InsertLine, DeleteLine } type;
        int line;
        int col;
        std::string text;
    };
    std::vector<EditAction> m_undoStack;
    std::vector<EditAction> m_redoStack;
    size_t m_undoIndex;
};

// Editor panel
class EditorPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static void Toggle();
    static bool IsVisible();
    static const char* Id();
    
    // File operations
    static void OpenFile(const char* path);
    static void SaveCurrentFile();
    static void SaveAsFile();
    static void CloseCurrentFile();
    static bool IsFileOpen();
    static bool IsModified();
    static const char* GetCurrentFilePath();
    
    // Edit operations
    static void CutSelection();
    static void CopySelection();
    static void PasteFromClipboard();
    
    // Navigation
    static void GoToLine(int line);
    static void GoToDefinition();
    static void FindInFile(const char* text);
    static void FindNext();
    static void FindPrevious();
    
    // Error highlighting
    static void SetErrorLine(int line, const char* message);
    static void ClearErrors();
    
    // Callbacks
    static void SetFileModifiedCallback(std::function<void(const char*, bool)> callback);
    static void SetSaveCallback(std::function<void(const char*)> callback);
    
private:
    static void RenderTabBar();
    static void RenderEditor();
    static void RenderLineNumbers();
    static void RenderTextContent();
    static void RenderStatusBar();
    static void RenderFindReplace();
    
    static void HandleInput();
    static void UpdateCursor();
    static void EnsureCursorVisible();
    
    static bool s_visible;
    static bool s_initialized;
    static bool s_showLineNumbers;
    static bool s_showMinimap;
    static bool s_wordWrap;
    
    static TextBuffer* s_currentBuffer;
    static std::vector<TextBuffer*> s_openBuffers;
    static int s_activeBufferIndex;
    
    // Find/Replace
    static char s_findBuffer[256];
    static char s_replaceBuffer[256];
    static bool s_showFindReplace;
    static bool s_findCaseSensitive;
    static bool s_findWholeWord;
    
    // Error highlighting
    static int s_errorLine;
    static char s_errorMessage[512];
    
    // Callbacks
    static std::function<void(const char*, bool)> s_fileModifiedCallback;
    static std::function<void(const char*)> s_saveCallback;
};

} // namespace IDE
