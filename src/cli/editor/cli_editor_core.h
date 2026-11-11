//=============================================================================
// cli_editor_core.h
// C++ wrapper header for MASM64 text editor core
//=============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <functional>
#include <optional>

namespace RawrXD::CLI::Editor {

// Error codes matching MASM implementation
enum class EditorError : int {
    OK = 0,
    NoMemory = 1,
    InvalidPosition = 2,
    Empty = 3
};

// Forward declaration
class TextBuffer;

//=============================================================================
// TextBuffer - Rope-based text buffer for CLI editor
//=============================================================================
class TextBuffer {
public:
    TextBuffer();
    ~TextBuffer();
    
    // Non-copyable (tree structure)
    TextBuffer(const TextBuffer&) = delete;
    TextBuffer& operator=(const TextBuffer&) = delete;
    
    // Move operations
    TextBuffer(TextBuffer&& other) noexcept;
    TextBuffer& operator=(TextBuffer&& other) noexcept;
    
    // Core operations
    EditorError Insert(size_t position, std::string_view text);
    EditorError Delete(size_t position, size_t length);
    EditorError Replace(size_t position, size_t length, std::string_view text);
    
    // Query operations
    [[nodiscard]] std::string GetText() const;
    [[nodiscard]] std::string GetSubstring(size_t position, size_t length) const;
    [[nodiscard]] char GetChar(size_t position) const;
    [[nodiscard]] size_t GetLength() const noexcept;
    [[nodiscard]] size_t GetLineCount() const noexcept;
    
    // Line operations
    [[nodiscard]] size_t GetLineStart(size_t lineNumber) const;
    [[nodiscard]] size_t GetLineEnd(size_t lineNumber) const;
    [[nodiscard]] size_t GetLineLength(size_t lineNumber) const;
    [[nodiscard]] size_t PositionToLine(size_t position) const;
    [[nodiscard]] size_t LineToPosition(size_t lineNumber) const;
    
    // Utility
    void Clear();
    [[nodiscard]] bool IsEmpty() const noexcept;
    
    // Statistics
    [[nodiscard]] size_t GetNodeCount() const noexcept;
    [[nodiscard]] int GetTreeHeight() const;
    
    // Validation
    [[nodiscard]] bool ValidateConsistency() const;
    
private:
    bool initialized_ = false;
    
    // MASM exports
    static extern "C" {
        int CliEditor_Init();
        int CliEditor_Shutdown();
        int CliEditor_Insert(uint64_t position, const char* text, uint64_t length);
        uint64_t CliEditor_GetText(char* buffer, uint64_t bufferSize);
        uint64_t CliEditor_GetLength();
        uint64_t CliEditor_GetLineCount();
        void CliEditor_Clear();
    }
};

//=============================================================================
// EditorSession - High-level editor session management
//=============================================================================
class EditorSession {
public:
    struct Config {
        bool enableSyntaxHighlighting = true;
        bool enableAutoIndent = true;
        size_t tabSize = 4;
        bool useSpaces = true;
    };
    
    explicit EditorSession(const Config& config = {});
    ~EditorSession();
    
    // File operations
    bool OpenFile(const std::string& path);
    bool SaveFile(const std::string& path);
    bool SaveFile();  // Save to current path
    void CloseFile();
    
    // Buffer access
    [[nodiscard]] TextBuffer& GetBuffer() { return buffer_; }
    [[nodiscard]] const TextBuffer& GetBuffer() const { return buffer_; }
    
    // State
    [[nodiscard]] bool HasUnsavedChanges() const noexcept;
    [[nodiscard]] std::string GetCurrentPath() const;
    [[nodiscard]] bool IsModified() const noexcept;
    
    // Cursor/selection
    struct Cursor {
        size_t line = 0;
        size_t column = 0;
        size_t absolutePosition = 0;
    };
    
    void SetCursor(const Cursor& cursor);
    [[nodiscard]] Cursor GetCursor() const;
    
    // Selection
    struct Selection {
        size_t start;
        size_t end;
        [[nodiscard]] bool IsEmpty() const noexcept { return start == end; }
        [[nodiscard]] size_t Length() const noexcept { return end - start; }
    };
    
    void SetSelection(const Selection& selection);
    [[nodiscard]] Selection GetSelection() const;
    void ClearSelection();
    
    // Edit operations
    void InsertText(const std::string& text);
    void DeleteSelection();
    void DeleteChar();
    void DeleteWord();
    void DeleteLine();
    
    // Navigation
    void MoveCursorLeft(size_t count = 1);
    void MoveCursorRight(size_t count = 1);
    void MoveCursorUp(size_t count = 1);
    void MoveCursorDown(size_t count = 1);
    void MoveCursorToLineStart();
    void MoveCursorToLineEnd();
    void MoveCursorToStart();
    void MoveCursorToEnd();
    void MoveCursorToLine(size_t line);
    
    // Search
    [[nodiscard]] std::optional<size_t> Find(std::string_view pattern, 
                                              size_t startPos = 0,
                                              bool caseSensitive = true) const;
    [[nodiscard]] std::vector<size_t> FindAll(std::string_view pattern,
                                               bool caseSensitive = true) const;
    
    // Callbacks
    using ChangeCallback = std::function<void(size_t position, size_t length)>;
    void SetOnChangeCallback(ChangeCallback callback);
    
private:
    TextBuffer buffer_;
    Config config_;
    std::string currentPath_;
    bool modified_ = false;
    Cursor cursor_;
    Selection selection_;
    ChangeCallback onChange_;
    
    void MarkModified();
};

//=============================================================================
// SyntaxHighlighter - ANSI color highlighting for terminal
//=============================================================================
class SyntaxHighlighter {
public:
    enum class TokenType {
        Text,
        Keyword,
        String,
        Comment,
        Number,
        Operator,
        Identifier,
        Preprocessor,
        Type,
        Function
    };
    
    struct Token {
        TokenType type;
        size_t start;
        size_t length;
    };
    
    // Language detection
    enum class Language {
        PlainText,
        Cpp,
        C,
        Assembly,
        Python,
        JavaScript,
        Markdown,
        CMake,
        PowerShell,
        Json
    };
    
    explicit SyntaxHighlighter(Language lang = Language::PlainText);
    
    // Tokenization
    [[nodiscard]] std::vector<Token> Tokenize(std::string_view text) const;
    
    // ANSI output
    [[nodiscard]] std::string HighlightToAnsi(std::string_view text) const;
    [[nodiscard]] std::string HighlightLineToAnsi(std::string_view line, 
                                                     size_t lineNumber) const;
    
    // Configuration
    void SetLanguage(Language lang);
    void SetTheme(const std::string& themeName);
    
    // ANSI codes
    static std::string GetAnsiReset();
    static std::string GetAnsiColor(TokenType type);
    
private:
    Language language_;
    std::string theme_;
    
    [[nodiscard]] TokenType ClassifyToken(std::string_view text, 
                                          size_t pos) const;
};

//=============================================================================
// ViewPort - Terminal viewport management
//=============================================================================
class ViewPort {
public:
    struct Size {
        size_t rows;
        size_t cols;
    };
    
    struct Position {
        size_t row;
        size_t col;
    };
    
    explicit ViewPort(const Size& size);
    
    // Resize
    void Resize(const Size& newSize);
    [[nodiscard]] Size GetSize() const noexcept;
    
    // Scroll
    void ScrollUp(size_t lines = 1);
    void ScrollDown(size_t lines = 1);
    void ScrollLeft(size_t cols = 1);
    void ScrollRight(size_t cols = 1);
    void ScrollToLine(size_t line);
    void ScrollToPosition(size_t pos);
    
    // View calculations
    [[nodiscard]] size_t GetTopLine() const noexcept { return topLine_; }
    [[nodiscard]] size_t GetLeftColumn() const noexcept { return leftCol_; }
    [[nodiscard]] size_t GetVisibleLineCount() const noexcept;
    [[nodiscard]] bool IsLineVisible(size_t line) const;
    
    // Cursor visibility
    void EnsureCursorVisible(const EditorSession::Cursor& cursor);
    [[nodiscard]] Position CursorToViewPosition(const EditorSession::Cursor& cursor) const;
    
    // Render
    [[nodiscard]] std::string RenderViewport(const TextBuffer& buffer,
                                              const SyntaxHighlighter& highlighter) const;
    
private:
    Size size_;
    size_t topLine_ = 0;
    size_t leftCol_ = 0;
};

//=============================================================================
// KeyBinding - Input handling
//=============================================================================
enum class Key {
    None,
    Char,
    Enter,
    Tab,
    Backspace,
    Delete,
    Escape,
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Home,
    End,
    PageUp,
    PageDown,
    Ctrl_A, Ctrl_B, Ctrl_C, Ctrl_D, Ctrl_E, Ctrl_F,
    Ctrl_G, Ctrl_H, Ctrl_I, Ctrl_J, Ctrl_K, Ctrl_L,
    Ctrl_M, Ctrl_N, Ctrl_O, Ctrl_P, Ctrl_Q, Ctrl_R,
    Ctrl_S, Ctrl_T, Ctrl_U, Ctrl_V, Ctrl_W, Ctrl_X,
    Ctrl_Y, Ctrl_Z,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12
};

struct KeyEvent {
    Key key;
    char ch;  // Valid when key == Key::Char
    bool ctrl;
    bool alt;
    bool shift;
};

class InputHandler {
public:
    using Handler = std::function<bool(const KeyEvent&)>;
    
    void Bind(Key key, Handler handler);
    void BindChord(Key first, Key second, Handler handler);
    
    bool ProcessInput(const KeyEvent& event);
    
    // Platform-specific input reading
    [[nodiscard]] KeyEvent ReadKey() const;
    [[nodiscard]] bool HasInput() const;
    
private:
    std::unordered_map<Key, Handler> bindings_;
    std::optional<Key> pendingChord_;
};

//=============================================================================
// EditorUI - Main editor UI controller
//=============================================================================
class EditorUI {
public:
    explicit EditorUI(EditorSession& session);
    ~EditorUI();
    
    // Main loop
    void Run();
    void Stop();
    
    // Screen management
    void ClearScreen();
    void RefreshScreen();
    void UpdateStatusLine();
    
    // Mode
    enum class Mode {
        Normal,
        Insert,
        Command,
        Visual,
        Search
    };
    
    void SetMode(Mode mode);
    [[nodiscard]] Mode GetMode() const noexcept;
    
    // Commands
    void ExecuteCommand(const std::string& command);
    void ShowMessage(const std::string& message);
    void ShowError(const std::string& error);
    
private:
    EditorSession& session_;
    ViewPort viewport_;
    SyntaxHighlighter highlighter_;
    InputHandler input_;
    Mode mode_ = Mode::Normal;
    bool running_ = false;
    std::string statusMessage_;
    std::string commandBuffer_;
    
    void SetupKeyBindings();
    void Render();
    void HandleNormalMode(const KeyEvent& key);
    void HandleInsertMode(const KeyEvent& key);
    void HandleCommandMode(const KeyEvent& key);
    void HandleVisualMode(const KeyEvent& key);
    void HandleSearchMode(const KeyEvent& key);
};

} // namespace RawrXD::CLI::Editor
