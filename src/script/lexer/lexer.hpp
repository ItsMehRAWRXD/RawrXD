// RawrXD-Script Lexer
// Phase 1: Bytecode Spec + C++ Parser

#pragma once

#include "token.hpp"
#include <string_view>
#include <vector>
#include <optional>

namespace RawrXD {
namespace Script {

// Lexer error codes
enum class LexerError {
    None,
    InvalidCharacter,
    UnterminatedString,
    InvalidNumber,
    InvalidEscapeSequence,
};

struct LexerResult {
    std::vector<Token> tokens;
    LexerError error;
    uint32_t errorLine;
    uint32_t errorColumn;
    std::string errorMessage;
    
    bool Success() const { return error == LexerError::None; }
};

class Lexer {
public:
    Lexer();
    
    // Tokenize source code
    LexerResult Tokenize(std::string_view source);
    
    // Reset for new input
    void Reset(std::string_view source);
    
    // Get next token (for streaming)
    Token NextToken();
    
    // Peek at next token without consuming
    Token PeekToken();
    
private:
    std::string_view source_;
    size_t position_;
    uint32_t line_;
    uint32_t column_;
    
    // Character handling
    char Current() const;
    char Peek(size_t offset = 1) const;
    char Advance();
    bool Match(char expected);
    void SkipWhitespace();
    void SkipLineComment();
    void SkipBlockComment();
    
    // Token scanning
    Token ScanToken();
    Token ScanNumber();
    Token ScanString(char quote);
    Token ScanIdentifier();
    Token ScanOperator();
    
    // Helpers
    bool IsAtEnd() const { return position_ >= source_.length(); }
    bool IsAlpha(char c) const;
    bool IsDigit(char c) const;
    bool IsAlphaNumeric(char c) const;
    bool IsIdentifierStart(char c) const;
    bool IsIdentifierPart(char c) const;
    
    TokenType LookupKeyword(std::string_view text) const;
    
    // Error handling
    Token MakeErrorToken(LexerError error, const std::string& message);
};

} // namespace Script
} // namespace RawrXD
