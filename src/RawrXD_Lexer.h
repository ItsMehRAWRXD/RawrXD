#pragma once
#include "RawrXD_Win32_Foundation.h"
#include <vector>
#include <string>
#include <cstdint>

namespace RawrXD {

enum class TokenType {
    EndOfFile,
    Identifier,
    Keyword,
    Number,
    String,
    Operator,
    Punctuation,
    Comment,
    Unknown
};

struct Token {
    TokenType type;
    const char* start;
    size_t length;
    size_t line;
    size_t column;
};

class Lexer {
public:
    Lexer(const char* source, size_t length);
    
    Token NextToken();
    Token PeekToken() const;
    
    size_t GetLine() const { return line_; }
    size_t GetColumn() const { return column_; }
    size_t GetPosition() const { return position_; }
    bool AtEnd() const { return position_ >= length_; }
    
    // Virtual interface for editor integration
    virtual void lex(const std::wstring& text, std::vector<Token>& outTokens);
    
    virtual ~Lexer() = default;
    
private:
    void SkipWhitespaceAndComments();
    void Advance(size_t count = 1);
    void SkipLine();
    
    const char* source_;
    size_t length_;
    size_t position_;
    size_t line_;
    size_t column_;
};

} // namespace RawrXD
