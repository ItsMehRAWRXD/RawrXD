#include "RawrXD_Lexer.h"
#include <cctype>
#include <cstring>

namespace RawrXD {

// Character classification tables for fast lookup
static const uint8_t kCharTable[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0,  // 0-15: control chars, tab, newline, etc
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 16-31: control chars
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 32-47: space and punctuation
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0,  // 48-57: digits 0-9
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // 64-79: @, A-O
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 3,  // 80-95: P-Z, _, etc
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,  // 96-111: `, a-o
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 0, 0, 0, 0,  // 112-127: p-z
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 128-143: extended ASCII
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 144-159
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 160-175
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 176-191
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 192-207
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 208-223
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 224-239
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0   // 240-255
};

// 0 = other, 1 = whitespace, 2 = digit, 3 = identifier char

bool IsWhitespace(char c) {
    return kCharTable[static_cast<uint8_t>(c)] == 1;
}

bool IsDigit(char c) {
    return kCharTable[static_cast<uint8_t>(c)] == 2;
}

bool IsIdentifierStart(char c) {
    return kCharTable[static_cast<uint8_t>(c)] == 3 && !IsDigit(c);
}

bool IsIdentifierChar(char c) {
    return kCharTable[static_cast<uint8_t>(c)] == 3 || IsDigit(c);
}

bool IsOperator(char c) {
    return c == '+' || c == '-' || c == '*' || c == '/' || c == '%' ||
           c == '&' || c == '|' || c == '^' || c == '~' || c == '!' ||
           c == '=' || c == '<' || c == '>' || c == '?' || c == ':';
}

bool IsPunctuation(char c) {
    return c == '(' || c == ')' || c == '{' || c == '}' ||
           c == '[' || c == ']' || c == ';' || c == ',' ||
           c == '.' || c == '"' || c == '\'' || c == '`';
}

const char* SkipWhitespace(const char* ptr) {
    while (ptr && IsWhitespace(*ptr)) {
        ++ptr;
    }
    return ptr;
}

const char* SkipLine(const char* ptr) {
    while (ptr && *ptr && *ptr != '\n') {
        ++ptr;
    }
    if (ptr && *ptr == '\n') {
        ++ptr;
    }
    return ptr;
}

size_t GetIdentifierLength(const char* ptr) {
    if (!ptr || !IsIdentifierStart(*ptr)) {
        return 0;
    }
    size_t len = 1;
    while (IsIdentifierChar(ptr[len])) {
        ++len;
    }
    return len;
}

size_t GetNumberLength(const char* ptr) {
    if (!ptr || !IsDigit(*ptr)) {
        return 0;
    }
    size_t len = 1;
    while (IsDigit(ptr[len]) || ptr[len] == '.' || ptr[len] == 'e' || ptr[len] == 'E' ||
           ptr[len] == '+' || ptr[len] == '-') {
        ++len;
    }
    return len;
}

bool IsCppKeyword(const char* str, size_t len) {
    // Binary search through sorted keyword table
    static const char* kKeywords[] = {
        "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
        "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
        "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
        "continue", "co_await", "co_return", "co_yield", "decltype", "default",
        "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit",
        "export", "extern", "false", "float", "for", "friend", "goto", "if",
        "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
        "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
        "protected", "public", "register", "reinterpret_cast", "requires", "return",
        "short", "signed", "sizeof", "static", "static_assert", "static_cast",
        "struct", "switch", "template", "this", "thread_local", "throw", "true",
        "try", "typedef", "typeid", "typename", "union", "unsigned", "using",
        "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq"
    };
    static const size_t kKeywordCount = sizeof(kKeywords) / sizeof(kKeywords[0]);
    
    // Simple linear search for small table
    for (size_t i = 0; i < kKeywordCount; ++i) {
        if (std::strlen(kKeywords[i]) == len && std::memcmp(kKeywords[i], str, len) == 0) {
            return true;
        }
    }
    return false;
}

Lexer::Lexer(const char* source, size_t length)
    : source_(source), length_(length), position_(0), line_(1), column_(1) {
}

Token Lexer::NextToken() {
    SkipWhitespaceAndComments();
    
    if (position_ >= length_) {
        return Token{TokenType::EndOfFile, nullptr, 0, line_, column_};
    }
    
    const char* start = source_ + position_;
    size_t startCol = column_;
    
    // Identifier or keyword
    if (IsIdentifierStart(*start)) {
        size_t len = GetIdentifierLength(start);
        TokenType type = IsCppKeyword(start, len) ? TokenType::Keyword : TokenType::Identifier;
        Advance(len);
        return Token{type, start, len, line_, startCol};
    }
    
    // Number literal
    if (IsDigit(*start)) {
        size_t len = GetNumberLength(start);
        Advance(len);
        return Token{TokenType::Number, start, len, line_, startCol};
    }
    
    // String literal
    if (*start == '"' || *start == '\'') {
        char quote = *start;
        size_t len = 1;
        while (start[len] && start[len] != quote && start[len] != '\n') {
            if (start[len] == '\\' && start[len + 1]) {
                len += 2;  // Skip escape sequence
            } else {
                ++len;
            }
        }
        if (start[len] == quote) {
            ++len;  // Include closing quote
        }
        Advance(len);
        return Token{TokenType::String, start, len, line_, startCol};
    }
    
    // Operator or punctuation
    if (IsOperator(*start)) {
        // Check for multi-character operators
        if ((start[0] == '-' && start[1] == '>') ||
            (start[0] == '+' && start[1] == '+') ||
            (start[0] == '-' && start[1] == '-') ||
            (start[0] == '=' && start[1] == '=') ||
            (start[0] == '!' && start[1] == '=') ||
            (start[0] == '<' && start[1] == '=') ||
            (start[0] == '>' && start[1] == '=') ||
            (start[0] == '&' && start[1] == '&') ||
            (start[0] == '|' && start[1] == '|') ||
            (start[0] == '<' && start[1] == '<') ||
            (start[0] == '>' && start[1] == '>') ||
            (start[0] == '+' && start[1] == '=') ||
            (start[0] == '-' && start[1] == '=') ||
            (start[0] == '*' && start[1] == '=') ||
            (start[0] == '/' && start[1] == '=') ||
            (start[0] == '%' && start[1] == '=') ||
            (start[0] == '&' && start[1] == '=') ||
            (start[0] == '|' && start[1] == '=') ||
            (start[0] == '^' && start[1] == '=') ||
            (start[0] == ':' && start[1] == ':')) {
            Advance(2);
            return Token{TokenType::Operator, start, 2, line_, startCol};
        }
        Advance(1);
        return Token{TokenType::Operator, start, 1, line_, startCol};
    }
    
    if (IsPunctuation(*start)) {
        Advance(1);
        return Token{TokenType::Punctuation, start, 1, line_, startCol};
    }
    
    // Unknown character
    Advance(1);
    return Token{TokenType::Unknown, start, 1, line_, startCol};
}

Token Lexer::PeekToken() const {
    Lexer temp = *this;
    return temp.NextToken();
}

void Lexer::SkipWhitespaceAndComments() {
    while (position_ < length_) {
        const char* ptr = source_ + position_;
        
        // Skip whitespace
        if (IsWhitespace(*ptr)) {
            Advance(1);
            continue;
        }
        
        // Skip single-line comments
        if (ptr[0] == '/' && ptr[1] == '/') {
            SkipLine();
            continue;
        }
        
        // Skip multi-line comments
        if (ptr[0] == '/' && ptr[1] == '*') {
            Advance(2);
            while (position_ + 1 < length_) {
                if (source_[position_] == '*' && source_[position_ + 1] == '/') {
                    Advance(2);
                    break;
                }
                Advance(1);
            }
            continue;
        }
        
        break;
    }
}

void Lexer::Advance(size_t count) {
    for (size_t i = 0; i < count && position_ < length_; ++i) {
        if (source_[position_] == '\n') {
            ++line_;
            column_ = 1;
        } else {
            ++column_;
        }
        ++position_;
    }
}

void Lexer::SkipLine() {
    while (position_ < length_ && source_[position_] != '\n') {
        ++position_;
        ++column_;
    }
    if (position_ < length_ && source_[position_] == '\n') {
        ++position_;
        ++line_;
        column_ = 1;
    }
}

// Virtual interface implementation for editor integration
void Lexer::lex(const std::wstring& text, std::vector<Token>& outTokens) {
    // Convert wstring to UTF-8 for processing
    std::string utf8;
    utf8.reserve(text.size());
    for (wchar_t wc : text) {
        if (wc < 128) {
            utf8.push_back(static_cast<char>(wc));
        } else {
            // Simple UTF-8 encoding for non-ASCII
            if (wc < 2048) {
                utf8.push_back(static_cast<char>(0xC0 | (wc >> 6)));
                utf8.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
            } else {
                utf8.push_back(static_cast<char>(0xE0 | (wc >> 12)));
                utf8.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
                utf8.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
            }
        }
    }
    
    // Create a temporary lexer for this text
    Lexer temp(utf8.c_str(), utf8.size());
    
    // Tokenize
    while (!temp.AtEnd()) {
        Token tok = temp.NextToken();
        if (tok.type == TokenType::EndOfFile) break;
        outTokens.push_back(tok);
    }
}

} // namespace RawrXD
