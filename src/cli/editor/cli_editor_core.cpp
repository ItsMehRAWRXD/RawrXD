//=============================================================================
// cli_editor_core.cpp
// C++ wrapper implementation for MASM64 text editor core
//=============================================================================

#include "cli_editor_core.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cstring>

namespace RawrXD::CLI::Editor {

//=============================================================================
// TextBuffer Implementation
//=============================================================================

// MASM function declarations
extern "C" {
    int CliEditor_Init();
    int CliEditor_Shutdown();
    int CliEditor_Insert(uint64_t position, const char* text, uint64_t length);
    uint64_t CliEditor_GetText(char* buffer, uint64_t bufferSize);
    uint64_t CliEditor_GetLength();
    uint64_t CliEditor_GetLineCount();
    void CliEditor_Clear();
}

TextBuffer::TextBuffer() {
    int result = CliEditor_Init();
    if (result == 0) {
        initialized_ = true;
    }
}

TextBuffer::~TextBuffer() {
    if (initialized_) {
        CliEditor_Shutdown();
    }
}

TextBuffer::TextBuffer(TextBuffer&& other) noexcept 
    : initialized_(other.initialized_) {
    other.initialized_ = false;
}

TextBuffer& TextBuffer::operator=(TextBuffer&& other) noexcept {
    if (this != &other) {
        if (initialized_) {
            CliEditor_Shutdown();
        }
        initialized_ = other.initialized_;
        other.initialized_ = false;
    }
    return *this;
}

EditorError TextBuffer::Insert(size_t position, std::string_view text) {
    if (!initialized_) {
        return EditorError::NoMemory;
    }
    if (text.empty()) {
        return EditorError::OK;
    }
    
    int result = CliEditor_Insert(position, text.data(), text.length());
    return static_cast<EditorError>(result);
}

EditorError TextBuffer::Delete(size_t position, size_t length) {
    // TODO: Implement in MASM
    // For now, this is a placeholder
    return EditorError::OK;
}

EditorError TextBuffer::Replace(size_t position, size_t length, std::string_view text) {
    auto err = Delete(position, length);
    if (err != EditorError::OK) {
        return err;
    }
    return Insert(position, text);
}

std::string TextBuffer::GetText() const {
    if (!initialized_) {
        return {};
    }
    
    uint64_t len = CliEditor_GetLength();
    if (len == 0) {
        return {};
    }
    
    std::string buffer(len + 1, '\0');
    uint64_t written = CliEditor_GetText(buffer.data(), len + 1);
    buffer.resize(written);
    return buffer;
}

std::string TextBuffer::GetSubstring(size_t position, size_t length) const {
    std::string fullText = GetText();
    if (position >= fullText.length()) {
        return {};
    }
    return fullText.substr(position, length);
}

char TextBuffer::GetChar(size_t position) const {
    std::string fullText = GetText();
    if (position >= fullText.length()) {
        return '\0';
    }
    return fullText[position];
}

size_t TextBuffer::GetLength() const noexcept {
    if (!initialized_) {
        return 0;
    }
    return CliEditor_GetLength();
}

size_t TextBuffer::GetLineCount() const noexcept {
    if (!initialized_) {
        return 1;
    }
    return CliEditor_GetLineCount();
}

size_t TextBuffer::GetLineStart(size_t lineNumber) const {
    // Simple implementation - scan for newlines
    std::string text = GetText();
    size_t pos = 0;
    size_t currentLine = 0;
    
    while (currentLine < lineNumber && pos < text.length()) {
        if (text[pos] == '\n') {
            currentLine++;
            if (currentLine == lineNumber) {
                return pos + 1;
            }
        }
        pos++;
    }
    
    return (currentLine == lineNumber) ? pos : text.length();
}

size_t TextBuffer::GetLineEnd(size_t lineNumber) const {
    std::string text = GetText();
    size_t start = GetLineStart(lineNumber);
    size_t pos = start;
    
    while (pos < text.length() && text[pos] != '\n') {
        pos++;
    }
    
    return pos;
}

size_t TextBuffer::GetLineLength(size_t lineNumber) const {
    return GetLineEnd(lineNumber) - GetLineStart(lineNumber);
}

size_t TextBuffer::PositionToLine(size_t position) const {
    std::string text = GetText();
    size_t line = 0;
    
    for (size_t i = 0; i < position && i < text.length(); i++) {
        if (text[i] == '\n') {
            line++;
        }
    }
    
    return line;
}

size_t TextBuffer::LineToPosition(size_t lineNumber) const {
    return GetLineStart(lineNumber);
}

void TextBuffer::Clear() {
    if (initialized_) {
        CliEditor_Clear();
    }
}

bool TextBuffer::IsEmpty() const noexcept {
    return GetLength() == 0;
}

size_t TextBuffer::GetNodeCount() const noexcept {
    // TODO: Export from MASM
    return 0;
}

int TextBuffer::GetTreeHeight() const {
    // TODO: Export from MASM
    return 0;
}

bool TextBuffer::ValidateConsistency() const {
    // TODO: Export from MASM
    return true;
}

//=============================================================================
// EditorSession Implementation
//=============================================================================

EditorSession::EditorSession(const Config& config) : config_(config) {}

EditorSession::~EditorSession() = default;

bool EditorSession::OpenFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    buffer_.Clear();
    auto err = buffer_.Insert(0, content);
    if (err != EditorError::OK) {
        return false;
    }
    
    currentPath_ = path;
    modified_ = false;
    cursor_ = {};
    selection_ = {};
    
    return true;
}

bool EditorSession::SaveFile(const std::string& path) {
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    std::string content = buffer_.GetText();
    file.write(content.data(), content.length());
    file.close();
    
    currentPath_ = path;
    modified_ = false;
    
    return true;
}

bool EditorSession::SaveFile() {
    if (currentPath_.empty()) {
        return false;
    }
    return SaveFile(currentPath_);
}

void EditorSession::CloseFile() {
    buffer_.Clear();
    currentPath_.clear();
    modified_ = false;
    cursor_ = {};
    selection_ = {};
}

bool EditorSession::HasUnsavedChanges() const noexcept {
    return modified_;
}

std::string EditorSession::GetCurrentPath() const {
    return currentPath_;
}

bool EditorSession::IsModified() const noexcept {
    return modified_;
}

void EditorSession::SetCursor(const Cursor& cursor) {
    cursor_ = cursor;
}

EditorSession::Cursor EditorSession::GetCursor() const {
    return cursor_;
}

void EditorSession::SetSelection(const Selection& selection) {
    selection_ = selection;
}

EditorSession::Selection EditorSession::GetSelection() const {
    return selection_;
}

void EditorSession::ClearSelection() {
    selection_ = {};
}

void EditorSession::InsertText(const std::string& text) {
    size_t pos = selection_.IsEmpty() ? cursor_.absolutePosition : selection_.start;
    size_t len = selection_.IsEmpty() ? 0 : selection_.Length();
    
    auto err = buffer_.Replace(pos, len, text);
    if (err == EditorError::OK) {
        cursor_.absolutePosition = pos + text.length();
        cursor_.line = buffer_.PositionToLine(cursor_.absolutePosition);
        cursor_.column = cursor_.absolutePosition - buffer_.LineToPosition(cursor_.line);
        ClearSelection();
        MarkModified();
        
        if (onChange_) {
            onChange_(pos, text.length());
        }
    }
}

void EditorSession::DeleteSelection() {
    if (selection_.IsEmpty()) {
        return;
    }
    
    auto err = buffer_.Delete(selection_.start, selection_.Length());
    if (err == EditorError::OK) {
        cursor_.absolutePosition = selection_.start;
        cursor_.line = buffer_.PositionToLine(cursor_.absolutePosition);
        cursor_.column = cursor_.absolutePosition - buffer_.LineToPosition(cursor_.line);
        ClearSelection();
        MarkModified();
    }
}

void EditorSession::DeleteChar() {
    if (!selection_.IsEmpty()) {
        DeleteSelection();
        return;
    }
    
    if (cursor_.absolutePosition < buffer_.GetLength()) {
        auto err = buffer_.Delete(cursor_.absolutePosition, 1);
        if (err == EditorError::OK) {
            MarkModified();
        }
    }
}

void EditorSession::DeleteWord() {
    // TODO: Implement word boundary detection
}

void EditorSession::DeleteLine() {
    size_t lineStart = buffer_.GetLineStart(cursor_.line);
    size_t lineEnd = buffer_.GetLineEnd(cursor_.line);
    
    auto err = buffer_.Delete(lineStart, lineEnd - lineStart + 1);
    if (err == EditorError::OK) {
        cursor_.absolutePosition = lineStart;
        cursor_.column = 0;
        MarkModified();
    }
}

void EditorSession::MoveCursorLeft(size_t count) {
    if (cursor_.absolutePosition >= count) {
        cursor_.absolutePosition -= count;
    } else {
        cursor_.absolutePosition = 0;
    }
    cursor_.line = buffer_.PositionToLine(cursor_.absolutePosition);
    cursor_.column = cursor_.absolutePosition - buffer_.LineToPosition(cursor_.line);
}

void EditorSession::MoveCursorRight(size_t count) {
    cursor_.absolutePosition = std::min(cursor_.absolutePosition + count, buffer_.GetLength());
    cursor_.line = buffer_.PositionToLine(cursor_.absolutePosition);
    cursor_.column = cursor_.absolutePosition - buffer_.LineToPosition(cursor_.line);
}

void EditorSession::MoveCursorUp(size_t count) {
    if (cursor_.line >= count) {
        cursor_.line -= count;
        size_t lineLen = buffer_.GetLineLength(cursor_.line);
        cursor_.column = std::min(cursor_.column, lineLen);
        cursor_.absolutePosition = buffer_.LineToPosition(cursor_.line) + cursor_.column;
    }
}

void EditorSession::MoveCursorDown(size_t count) {
    size_t lineCount = buffer_.GetLineCount();
    if (cursor_.line + count < lineCount) {
        cursor_.line += count;
        size_t lineLen = buffer_.GetLineLength(cursor_.line);
        cursor_.column = std::min(cursor_.column, lineLen);
        cursor_.absolutePosition = buffer_.LineToPosition(cursor_.line) + cursor_.column;
    }
}

void EditorSession::MoveCursorToLineStart() {
    cursor_.absolutePosition = buffer_.LineToPosition(cursor_.line);
    cursor_.column = 0;
}

void EditorSession::MoveCursorToLineEnd() {
    cursor_.absolutePosition = buffer_.GetLineEnd(cursor_.line);
    cursor_.column = cursor_.absolutePosition - buffer_.LineToPosition(cursor_.line);
}

void EditorSession::MoveCursorToStart() {
    cursor_ = {};
}

void EditorSession::MoveCursorToEnd() {
    cursor_.absolutePosition = buffer_.GetLength();
    cursor_.line = buffer_.GetLineCount() - 1;
    cursor_.column = buffer_.GetLineLength(cursor_.line);
}

void EditorSession::MoveCursorToLine(size_t line) {
    cursor_.line = std::min(line, buffer_.GetLineCount() - 1);
    size_t lineLen = buffer_.GetLineLength(cursor_.line);
    cursor_.column = std::min(cursor_.column, lineLen);
    cursor_.absolutePosition = buffer_.LineToPosition(cursor_.line) + cursor_.column;
}

std::optional<size_t> EditorSession::Find(std::string_view pattern, 
                                          size_t startPos,
                                          bool caseSensitive) const {
    std::string text = buffer_.GetText();
    
    if (!caseSensitive) {
        // Simple case-insensitive search
        std::string textLower(text);
        std::string patternLower(pattern);
        std::transform(textLower.begin(), textLower.end(), textLower.begin(), ::tolower);
        std::transform(patternLower.begin(), patternLower.end(), patternLower.begin(), ::tolower);
        
        size_t pos = textLower.find(patternLower, startPos);
        return (pos != std::string::npos) ? std::optional<size_t>(pos) : std::nullopt;
    }
    
    size_t pos = text.find(pattern, startPos);
    return (pos != std::string::npos) ? std::optional<size_t>(pos) : std::nullopt;
}

std::vector<size_t> EditorSession::FindAll(std::string_view pattern,
                                           bool caseSensitive) const {
    std::vector<size_t> results;
    size_t pos = 0;
    
    while (true) {
        auto found = Find(pattern, pos, caseSensitive);
        if (!found.has_value()) {
            break;
        }
        results.push_back(found.value());
        pos = found.value() + 1;
    }
    
    return results;
}

void EditorSession::SetOnChangeCallback(ChangeCallback callback) {
    onChange_ = callback;
}

void EditorSession::MarkModified() {
    modified_ = true;
}

//=============================================================================
// SyntaxHighlighter Implementation
//=============================================================================

SyntaxHighlighter::SyntaxHighlighter(Language lang) : language_(lang) {}

void SyntaxHighlighter::SetLanguage(Language lang) {
    language_ = lang;
}

void SyntaxHighlighter::SetTheme(const std::string& themeName) {
    theme_ = themeName;
}

std::vector<SyntaxHighlighter::Token> SyntaxHighlighter::Tokenize(std::string_view text) const {
    std::vector<Token> tokens;
    
    if (language_ == Language::PlainText) {
        tokens.push_back({TokenType::Text, 0, text.length()});
        return tokens;
    }
    
    // Simple tokenization for demonstration
    size_t pos = 0;
    while (pos < text.length()) {
        char c = text[pos];
        
        // Skip whitespace
        if (std::isspace(static_cast<unsigned char>(c))) {
            pos++;
            continue;
        }
        
        // String literals
        if (c == '"' || c == '\'') {
            size_t start = pos;
            pos++;
            while (pos < text.length() && text[pos] != c) {
                if (text[pos] == '\\' && pos + 1 < text.length()) {
                    pos += 2;
                } else {
                    pos++;
                }
            }
            if (pos < text.length()) {
                pos++;
            }
            tokens.push_back({TokenType::String, start, pos - start});
            continue;
        }
        
        // Comments
        if (c == '/' && pos + 1 < text.length()) {
            if (text[pos + 1] == '/') {
                size_t start = pos;
                while (pos < text.length() && text[pos] != '\n') {
                    pos++;
                }
                tokens.push_back({TokenType::Comment, start, pos - start});
                continue;
            }
        }
        
        // Numbers
        if (std::isdigit(static_cast<unsigned char>(c))) {
            size_t start = pos;
            while (pos < text.length() && 
                   (std::isdigit(static_cast<unsigned char>(text[pos])) || 
                    text[pos] == '.' || text[pos] == 'x' || text[pos] == 'X' ||
                    (text[pos] >= 'a' && text[pos] <= 'f') ||
                    (text[pos] >= 'A' && text[pos] <= 'F'))) {
                pos++;
            }
            tokens.push_back({TokenType::Number, start, pos - start});
            continue;
        }
        
        // Identifiers and keywords
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
            size_t start = pos;
            while (pos < text.length() && 
                   (std::isalnum(static_cast<unsigned char>(text[pos])) || text[pos] == '_')) {
                pos++;
            }
            
            TokenType type = TokenType::Identifier;
            std::string word(text.substr(start, pos - start));
            
            // Simple keyword detection for C/C++
            static const char* keywords[] = {
                "int", "char", "bool", "void", "return", "if", "else",
                "for", "while", "class", "struct", "namespace", "using",
                "public", "private", "protected", "virtual", "static",
                "const", "auto", "template", "typename", "sizeof"
            };
            
            for (const auto* kw : keywords) {
                if (word == kw) {
                    type = TokenType::Keyword;
                    break;
                }
            }
            
            tokens.push_back({type, start, pos - start});
            continue;
        }
        
        // Operators and punctuation
        size_t start = pos;
        pos++;
        tokens.push_back({TokenType::Operator, start, 1});
    }
    
    return tokens;
}

std::string SyntaxHighlighter::HighlightToAnsi(std::string_view text) const {
    auto tokens = Tokenize(text);
    std::string result;
    
    size_t lastEnd = 0;
    for (const auto& token : tokens) {
        // Add any text between tokens
        if (token.start > lastEnd) {
            result.append(text.substr(lastEnd, token.start - lastEnd));
        }
        
        // Add colored token
        result += GetAnsiColor(token.type);
        result.append(text.substr(token.start, token.length));
        result += GetAnsiReset();
        
        lastEnd = token.start + token.length;
    }
    
    // Add remaining text
    if (lastEnd < text.length()) {
        result.append(text.substr(lastEnd));
    }
    
    return result;
}

std::string SyntaxHighlighter::HighlightLineToAnsi(std::string_view line, 
                                                    size_t lineNumber) const {
    return HighlightToAnsi(line);
}

std::string SyntaxHighlighter::GetAnsiReset() {
    return "\x1b[0m";
}

std::string SyntaxHighlighter::GetAnsiColor(TokenType type) {
    switch (type) {
        case TokenType::Keyword:
            return "\x1b[35m";      // Magenta
        case TokenType::String:
            return "\x1b[32m";      // Green
        case TokenType::Comment:
            return "\x1b[90m";      // Gray
        case TokenType::Number:
            return "\x1b[33m";      // Yellow
        case TokenType::Type:
            return "\x1b[36m";      // Cyan
        case TokenType::Function:
            return "\x1b[34m";      // Blue
        default:
            return "\x1b[0m";       // Default
    }
}

SyntaxHighlighter::TokenType SyntaxHighlighter::ClassifyToken(std::string_view text, 
                                                               size_t pos) const {
    return TokenType::Text;
}

//=============================================================================
// ViewPort Implementation
//=============================================================================

ViewPort::ViewPort(const Size& size) : size_(size) {}

void ViewPort::Resize(const Size& newSize) {
    size_ = newSize;
    // Ensure scroll position is still valid
    // TODO: Recalculate based on buffer
}

ViewPort::Size ViewPort::GetSize() const noexcept {
    return size_;
}

void ViewPort::ScrollUp(size_t lines) {
    if (topLine_ >= lines) {
        topLine_ -= lines;
    } else {
        topLine_ = 0;
    }
}

void ViewPort::ScrollDown(size_t lines) {
    topLine_ += lines;
}

void ViewPort::ScrollLeft(size_t cols) {
    if (leftCol_ >= cols) {
        leftCol_ -= cols;
    } else {
        leftCol_ = 0;
    }
}

void ViewPort::ScrollRight(size_t cols) {
    leftCol_ += cols;
}

void ViewPort::ScrollToLine(size_t line) {
    topLine_ = line;
}

void ViewPort::ScrollToPosition(size_t pos) {
    // TODO: Calculate line from position
}

size_t ViewPort::GetVisibleLineCount() const noexcept {
    return size_.rows;
}

bool ViewPort::IsLineVisible(size_t line) const {
    return line >= topLine_ && line < topLine_ + size_.rows;
}

void ViewPort::EnsureCursorVisible(const EditorSession::Cursor& cursor) {
    if (cursor.line < topLine_) {
        topLine_ = cursor.line;
    } else if (cursor.line >= topLine_ + size_.rows) {
        topLine_ = cursor.line - size_.rows + 1;
    }
    
    if (cursor.column < leftCol_) {
        leftCol_ = cursor.column;
    } else if (cursor.column >= leftCol_ + size_.cols) {
        leftCol_ = cursor.column - size_.cols + 1;
    }
}

ViewPort::Position ViewPort::CursorToViewPosition(const EditorSession::Cursor& cursor) const {
    return {
        cursor.line - topLine_,
        cursor.column - leftCol_
    };
}

std::string ViewPort::RenderViewport(const TextBuffer& buffer,
                                      const SyntaxHighlighter& highlighter) const {
    std::string result;
    
    for (size_t i = 0; i < size_.rows; i++) {
        size_t lineNum = topLine_ + i;
        if (lineNum >= buffer.GetLineCount()) {
            break;
        }
        
        size_t lineStart = buffer.GetLineStart(lineNum);
        size_t lineEnd = buffer.GetLineEnd(lineNum);
        size_t lineLen = lineEnd - lineStart;
        
        // Get line content
        std::string line = buffer.GetSubstring(lineStart, lineLen);
        
        // Apply horizontal scroll
        if (leftCol_ < line.length()) {
            line = line.substr(leftCol_, size_.cols);
        } else {
            line.clear();
        }
        
        // Highlight and add to result
        result += highlighter.HighlightLineToAnsi(line, lineNum);
        result += "\n";
    }
    
    return result;
}

} // namespace RawrXD::CLI::Editor
