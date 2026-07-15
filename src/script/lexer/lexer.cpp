// RawrXD-Script Lexer Implementation
// Phase 1: Working Implementation

#include "token.hpp"
#include "lexer.hpp"
#include <cctype>
#include <unordered_map>

namespace RawrXD {
namespace Script {

// Keyword lookup table
static const std::unordered_map<std::string_view, TokenType> kKeywords = {
    {"function", TokenType::KeywordFunction},
    {"var", TokenType::KeywordVar},
    {"let", TokenType::KeywordLet},
    {"const", TokenType::KeywordConst},
    {"if", TokenType::KeywordIf},
    {"else", TokenType::KeywordElse},
    {"while", TokenType::KeywordWhile},
    {"for", TokenType::KeywordFor},
    {"return", TokenType::KeywordReturn},
    {"break", TokenType::KeywordBreak},
    {"continue", TokenType::KeywordContinue},
    {"new", TokenType::KeywordNew},
    {"this", TokenType::KeywordThis},
    {"typeof", TokenType::KeywordTypeof},
    {"instanceof", TokenType::KeywordInstanceof},
    {"in", TokenType::KeywordIn},
    {"delete", TokenType::KeywordDelete},
    {"void", TokenType::KeywordVoid},
    {"switch", TokenType::KeywordSwitch},
    {"case", TokenType::KeywordCase},
    {"default", TokenType::KeywordDefault},
    {"try", TokenType::KeywordTry},
    {"catch", TokenType::KeywordCatch},
    {"finally", TokenType::KeywordFinally},
    {"throw", TokenType::KeywordThrow},
    {"true", TokenType::BooleanLiteral},
    {"false", TokenType::BooleanLiteral},
    {"null", TokenType::NullLiteral},
    {"undefined", TokenType::UndefinedLiteral},
};

// Token type to string conversion
const char* TokenTypeToString(TokenType type) {
    switch (type) {
        case TokenType::EndOfFile: return "EOF";
        case TokenType::NumberLiteral: return "NUMBER";
        case TokenType::StringLiteral: return "STRING";
        case TokenType::BooleanLiteral: return "BOOLEAN";
        case TokenType::NullLiteral: return "NULL";
        case TokenType::UndefinedLiteral: return "UNDEFINED";
        case TokenType::Identifier: return "IDENTIFIER";
        case TokenType::KeywordFunction: return "FUNCTION";
        case TokenType::KeywordVar: return "VAR";
        case TokenType::KeywordLet: return "LET";
        case TokenType::KeywordConst: return "CONST";
        case TokenType::KeywordIf: return "IF";
        case TokenType::KeywordElse: return "ELSE";
        case TokenType::KeywordWhile: return "WHILE";
        case TokenType::KeywordFor: return "FOR";
        case TokenType::KeywordReturn: return "RETURN";
        case TokenType::KeywordBreak: return "BREAK";
        case TokenType::KeywordContinue: return "CONTINUE";
        case TokenType::Plus: return "+";
        case TokenType::Minus: return "-";
        case TokenType::Multiply: return "*";
        case TokenType::Divide: return "/";
        case TokenType::Modulo: return "%";
        case TokenType::Assign: return "=";
        case TokenType::Equal: return "==";
        case TokenType::StrictEqual: return "===";
        case TokenType::NotEqual: return "!=";
        case TokenType::StrictNotEqual: return "!==";
        case TokenType::LessThan: return "<";
        case TokenType::GreaterThan: return ">";
        case TokenType::LessThanOrEqual: return "<=";
        case TokenType::GreaterThanOrEqual: return ">=";
        case TokenType::LogicalAnd: return "&&";
        case TokenType::LogicalOr: return "||";
        case TokenType::LogicalNot: return "!";
        case TokenType::Semicolon: return ";";
        case TokenType::Comma: return ",";
        case TokenType::Dot: return ".";
        case TokenType::LeftParen: return "(";
        case TokenType::RightParen: return ")";
        case TokenType::LeftBrace: return "{";
        case TokenType::RightBrace: return "}";
        case TokenType::LeftBracket: return "[";
        case TokenType::RightBracket: return "]";
        default: return "UNKNOWN";
    }
}

// Token methods
bool Token::IsKeyword() const {
    return type >= TokenType::KeywordFunction && type <= TokenType::KeywordThrow;
}

bool Token::IsOperator() const {
    return (type >= TokenType::Plus && type <= TokenType::LogicalNot) ||
           (type >= TokenType::BitwiseAnd && type <= TokenType::UnsignedRightShift);
}

bool Token::IsLiteral() const {
    return type >= TokenType::NumberLiteral && type <= TokenType::UndefinedLiteral;
}

std::string Token::ToString() const {
    std::string result = TokenTypeToString(type);
    if (type == TokenType::NumberLiteral) {
        result += "(" + std::to_string(numberValue) + ")";
    } else if (type == TokenType::StringLiteral) {
        result += "(\"" + stringValue + "\")";
    } else if (type == TokenType::Identifier || type == TokenType::BooleanLiteral) {
        result += "(" + std::string(text) + ")";
    }
    return result;
}

// Lexer implementation
Lexer::Lexer() : position_(0), line_(1), column_(1) {}

LexerResult Lexer::Tokenize(std::string_view source) {
    Reset(source);
    LexerResult result;
    
    while (!IsAtEnd()) {
        Token token = NextToken();
        result.tokens.push_back(token);
        
        if (token.type == TokenType::EndOfFile) {
            break;
        }
    }
    
    result.error = LexerError::None;
    return result;
}

void Lexer::Reset(std::string_view source) {
    source_ = source;
    position_ = 0;
    line_ = 1;
    column_ = 1;
}

Token Lexer::NextToken() {
    SkipWhitespace();
    
    if (IsAtEnd()) {
        return Token(TokenType::EndOfFile, "", line_, column_);
    }
    
    char c = Current();
    
    // Identifiers and keywords
    if (IsAlpha(c) || c == '_') {
        return ScanIdentifier();
    }
    
    // Numbers
    if (IsDigit(c)) {
        return ScanNumber();
    }
    
    // Strings
    if (c == '"' || c == '\'') {
        return ScanString(c);
    }
    
    // Comments
    if (c == '/' && Peek() == '/') {
        SkipLineComment();
        return NextToken();
    }
    
    if (c == '/' && Peek() == '*') {
        SkipBlockComment();
        return NextToken();
    }
    
    // Operators and punctuation
    return ScanOperator();
}

Token Lexer::PeekToken() {
    size_t saved_pos = position_;
    uint32_t saved_line = line_;
    uint32_t saved_col = column_;
    
    Token token = NextToken();
    
    position_ = saved_pos;
    line_ = saved_line;
    column_ = saved_col;
    
    return token;
}

// Character handling
char Lexer::Current() const {
    if (position_ >= source_.size()) return '\0';
    return source_[position_];
}

char Lexer::Peek(size_t offset) const {
    if (position_ + offset >= source_.size()) return '\0';
    return source_[position_ + offset];
}

char Lexer::Advance() {
    char c = Current();
    position_++;
    column_++;
    return c;
}

bool Lexer::Match(char expected) {
    if (Current() != expected) return false;
    Advance();
    return true;
}

void Lexer::SkipWhitespace() {
    while (true) {
        char c = Current();
        if (c == ' ' || c == '\t' || c == '\r') {
            Advance();
        } else if (c == '\n') {
            Advance();
            line_++;
            column_ = 1;
        } else {
            break;
        }
    }
}

void Lexer::SkipLineComment() {
    while (Current() != '\n' && !IsAtEnd()) {
        Advance();
    }
}

void Lexer::SkipBlockComment() {
    Advance(); // '/'
    Advance(); // '*'
    
    while (!IsAtEnd()) {
        if (Current() == '*' && Peek() == '/') {
            Advance();
            Advance();
            break;
        }
        if (Current() == '\n') {
            line_++;
            column_ = 1;
        }
        Advance();
    }
}

// Token scanning
Token Lexer::ScanIdentifier() {
    uint32_t start_line = line_;
    uint32_t start_col = column_;
    size_t start_pos = position_;
    
    while (IsAlphaNumeric(Current()) || Current() == '_') {
        Advance();
    }
    
    std::string_view text = source_.substr(start_pos, position_ - start_pos);
    
    // Check for keyword
    auto it = kKeywords.find(text);
    if (it != kKeywords.end()) {
        Token token(it->second, text, start_line, start_col);
        if (it->second == TokenType::BooleanLiteral) {
            token.numberValue = (text == "true") ? 1.0 : 0.0;
        }
        return token;
    }
    
    return Token(TokenType::Identifier, text, start_line, start_col);
}

Token Lexer::ScanNumber() {
    uint32_t start_line = line_;
    uint32_t start_col = column_;
    size_t start_pos = position_;
    
    // Integer part
    while (IsDigit(Current())) {
        Advance();
    }
    
    // Decimal part
    if (Current() == '.' && IsDigit(Peek())) {
        Advance(); // '.'
        while (IsDigit(Current())) {
            Advance();
        }
    }
    
    // Exponent
    if (Current() == 'e' || Current() == 'E') {
        Advance();
        if (Current() == '+' || Current() == '-') {
            Advance();
        }
        while (IsDigit(Current())) {
            Advance();
        }
    }
    
    std::string_view text = source_.substr(start_pos, position_ - start_pos);
    double value = std::stod(std::string(text));
    
    Token token(TokenType::NumberLiteral, text, start_line, start_col);
    token.numberValue = value;
    return token;
}

Token Lexer::ScanString(char quote) {
    uint32_t start_line = line_;
    uint32_t start_col = column_;
    Advance(); // Opening quote
    
    std::string value;
    
    while (Current() != quote && !IsAtEnd()) {
        if (Current() == '\\') {
            Advance();
            char escaped = Current();
            switch (escaped) {
                case 'n': value += '\n'; break;
                case 't': value += '\t'; break;
                case 'r': value += '\r'; break;
                case '\\': value += '\\'; break;
                case '"': value += '"'; break;
                case '\'': value += '\''; break;
                default: value += escaped; break;
            }
            Advance();
        } else {
            value += Advance();
        }
    }
    
    if (IsAtEnd()) {
        return MakeErrorToken(LexerError::UnterminatedString, "Unterminated string literal");
    }
    
    Advance(); // Closing quote
    
    Token token(TokenType::StringLiteral, "", start_line, start_col);
    token.stringValue = std::move(value);
    return token;
}

Token Lexer::ScanOperator() {
    uint32_t start_line = line_;
    uint32_t start_col = column_;
    char c = Current();
    Advance();
    
    switch (c) {
        case '+':
            if (Match('+')) return Token(TokenType::Increment, "++", start_line, start_col);
            if (Match('=')) return Token(TokenType::PlusAssign, "+=", start_line, start_col);
            return Token(TokenType::Plus, "+", start_line, start_col);
            
        case '-':
            if (Match('-')) return Token(TokenType::Decrement, "--", start_line, start_col);
            if (Match('=')) return Token(TokenType::MinusAssign, "-=", start_line, start_col);
            return Token(TokenType::Minus, "-", start_line, start_col);
            
        case '*':
            if (Match('=')) return Token(TokenType::MultiplyAssign, "*=", start_line, start_col);
            return Token(TokenType::Multiply, "*", start_line, start_col);
            
        case '/':
            if (Match('=')) return Token(TokenType::DivideAssign, "/=", start_line, start_col);
            return Token(TokenType::Divide, "/", start_line, start_col);
            
        case '%':
            if (Match('=')) return Token(TokenType::ModuloAssign, "%=", start_line, start_col);
            return Token(TokenType::Modulo, "%", start_line, start_col);
            
        case '=':
            if (Match('=')) {
                if (Match('=')) return Token(TokenType::StrictEqual, "===", start_line, start_col);
                return Token(TokenType::Equal, "==", start_line, start_col);
            }
            if (Match('>')) return Token(TokenType::Arrow, "=>", start_line, start_col);
            return Token(TokenType::Assign, "=", start_line, start_col);
            
        case '!':
            if (Match('=')) {
                if (Match('=')) return Token(TokenType::StrictNotEqual, "!==", start_line, start_col);
                return Token(TokenType::NotEqual, "!=", start_line, start_col);
            }
            return Token(TokenType::LogicalNot, "!", start_line, start_col);
            
        case '<':
            if (Match('=')) return Token(TokenType::LessThanOrEqual, "<=", start_line, start_col);
            if (Match('<')) {
                if (Match('=')) return Token(TokenType::LeftShiftAssign, "<<=", start_line, start_col);
                return Token(TokenType::LeftShift, "<<", start_line, start_col);
            }
            return Token(TokenType::LessThan, "<", start_line, start_col);
            
        case '>':
            if (Match('=')) return Token(TokenType::GreaterThanOrEqual, ">=", start_line, start_col);
            if (Match('>')) {
                if (Match('>')) {
                    if (Match('=')) return Token(TokenType::UnsignedRightShiftAssign, ">>>=", start_line, start_col);
                    return Token(TokenType::UnsignedRightShift, ">>>", start_line, start_col);
                }
                if (Match('=')) return Token(TokenType::RightShiftAssign, ">>=", start_line, start_col);
                return Token(TokenType::RightShift, ">>", start_line, start_col);
            }
            return Token(TokenType::GreaterThan, ">", start_line, start_col);
            
        case '&':
            if (Match('&')) return Token(TokenType::LogicalAnd, "&&", start_line, start_col);
            if (Match('=')) return Token(TokenType::BitwiseAndAssign, "&=", start_line, start_col);
            return Token(TokenType::BitwiseAnd, "&", start_line, start_col);
            
        case '|':
            if (Match('|')) return Token(TokenType::LogicalOr, "||", start_line, start_col);
            if (Match('=')) return Token(TokenType::BitwiseOrAssign, "|=", start_line, start_col);
            return Token(TokenType::BitwiseOr, "|", start_line, start_col);
            
        case '^':
            if (Match('=')) return Token(TokenType::BitwiseXorAssign, "^=", start_line, start_col);
            return Token(TokenType::BitwiseXor, "^", start_line, start_col);
            
        case '~': return Token(TokenType::BitwiseNot, "~", start_line, start_col);
        case ';': return Token(TokenType::Semicolon, ";", start_line, start_col);
        case ',': return Token(TokenType::Comma, ",", start_line, start_col);
        case '.': return Token(TokenType::Dot, ".", start_line, start_col);
        case ':': return Token(TokenType::Colon, ":", start_line, start_col);
        case '?': return Token(TokenType::QuestionMark, "?", start_line, start_col);
        case '(': return Token(TokenType::LeftParen, "(", start_line, start_col);
        case ')': return Token(TokenType::RightParen, ")", start_line, start_col);
        case '{': return Token(TokenType::LeftBrace, "{", start_line, start_col);
        case '}': return Token(TokenType::RightBrace, "}", start_line, start_col);
        case '[': return Token(TokenType::LeftBracket, "[", start_line, start_col);
        case ']': return Token(TokenType::RightBracket, "]", start_line, start_col);
        
        default:
            return MakeErrorToken(LexerError::InvalidCharacter, "Unexpected character");
    }
}

// Helpers
bool Lexer::IsAlpha(char c) const {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool Lexer::IsDigit(char c) const {
    return c >= '0' && c <= '9';
}

bool Lexer::IsAlphaNumeric(char c) const {
    return IsAlpha(c) || IsDigit(c);
}

bool Lexer::IsIdentifierStart(char c) const {
    return IsAlpha(c) || c == '_';
}

bool Lexer::IsIdentifierPart(char c) const {
    return IsAlphaNumeric(c) || c == '_';
}

Token Lexer::MakeErrorToken(LexerError error, const std::string& message) {
    Token token;
    token.type = TokenType::EndOfFile;
    token.line = line_;
    token.column = column_;
    // Store error info in result (would need to modify LexerResult)
    return token;
}

} // namespace Script
} // namespace RawrXD
