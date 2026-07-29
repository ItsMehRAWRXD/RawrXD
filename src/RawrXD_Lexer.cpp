<<<<<<< HEAD
// ============================================================================
// RawrXD_Lexer.cpp - Full C++ Lexer Implementation
// Tokenizes C/C++ source code for IDE features
// ============================================================================

#include "RawrXD_Lexer.h"
#include <cctype>
#include <unordered_set>

namespace RawrXD {

// ============================================================================
// Keyword Set
// ============================================================================
static const std::unordered_set<std::string> g_keywords = {
    // C/C++ keywords
    "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor",
    "bool", "break", "case", "catch", "char", "char8_t", "char16_t", "char32_t",
    "class", "compl", "concept", "const", "consteval", "constexpr", "constinit",
    "const_cast", "continue", "co_await", "co_return", "co_yield", "decltype",
    "default", "delete", "do", "double", "dynamic_cast", "else", "enum",
    "explicit", "export", "extern", "false", "float", "for", "friend", "goto",
    "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept",
    "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private", "protected",
    "public", "register", "reinterpret_cast", "requires", "return", "short",
    "signed", "sizeof", "static", "static_assert", "static_cast", "struct",
    "switch", "template", "this", "thread_local", "throw", "true", "try",
    "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual",
    "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
    // RawrXD specific
    "rawr", "sovereign", "agentic"
};

// ============================================================================
// Lexer Implementation
// ============================================================================

Lexer::Lexer(const std::string& source) 
    : source_(source)
    , pos_(0)
    , line_(1)
    , column_(1)
    , startPos_(0)
    , startLine_(1)
    , startColumn_(1) {
}

std::vector<Token> Lexer::Tokenize() {
    std::vector<Token> tokens;
    
    while (!IsAtEnd()) {
        SkipWhitespace();
        if (IsAtEnd()) break;
        
        Token token = NextToken();
        if (token.type != TokenType::EndOfFile) {
            tokens.push_back(token);
        }
    }
    
    // Add EOF token
    tokens.push_back({TokenType::EndOfFile, "", line_, column_});
    return tokens;
}

Token Lexer::NextToken() {
    SkipWhitespace();
    
    if (IsAtEnd()) {
        return {TokenType::EndOfFile, "", line_, column_};
    }
    
    startPos_ = pos_;
    startLine_ = line_;
    startColumn_ = column_;
    
    char c = Advance();
    
    // Identifiers and keywords
    if (IsAlpha(c) || c == '_') {
        return Identifier();
    }
    
    // Numbers
    if (IsDigit(c)) {
        return Number();
    }
    
    // Strings
    if (c == '"' || c == '\'') {
        return String(c);
    }
    
    // Comments
    if (c == '/') {
        if (Match('/')) {
            return LineComment();
        }
        if (Match('*')) {
            return BlockComment();
        }
        return Operator('/');
    }
    
    // Operators and punctuation
    switch (c) {
        case '(': return MakeToken(TokenType::Punctuation, "(");
        case ')': return MakeToken(TokenType::Punctuation, ")");
        case '{': return MakeToken(TokenType::Punctuation, "{");
        case '}': return MakeToken(TokenType::Punctuation, "}");
        case '[': return MakeToken(TokenType::Punctuation, "[");
        case ']': return MakeToken(TokenType::Punctuation, "]");
        case ';': return MakeToken(TokenType::Punctuation, ";");
        case ':': return MakeToken(TokenType::Punctuation, ":");
        case ',': return MakeToken(TokenType::Punctuation, ",");
        case '.': 
            if (Match('.')) {
                if (Match('.')) {
                    return MakeToken(TokenType::Operator, "...");
                }
                return MakeToken(TokenType::Operator, "..");
            }
            return MakeToken(TokenType::Punctuation, ".");
        case '+':
            if (Match('+')) return MakeToken(TokenType::Operator, "++");
            if (Match('=')) return MakeToken(TokenType::Operator, "+=");
            return MakeToken(TokenType::Operator, "+");
        case '-':
            if (Match('-')) return MakeToken(TokenType::Operator, "--");
            if (Match('=')) return MakeToken(TokenType::Operator, "-=");
            if (Match('>')) return MakeToken(TokenType::Operator, "->");
            return MakeToken(TokenType::Operator, "-");
        case '*':
            if (Match('=')) return MakeToken(TokenType::Operator, "*=");
            return MakeToken(TokenType::Operator, "*");
        case '/':
            if (Match('=')) return MakeToken(TokenType::Operator, "/=");
            return MakeToken(TokenType::Operator, "/");
        case '%':
            if (Match('=')) return MakeToken(TokenType::Operator, "%=");
            return MakeToken(TokenType::Operator, "%");
        case '=':
            if (Match('=')) return MakeToken(TokenType::Operator, "==");
            return MakeToken(TokenType::Operator, "=");
        case '!':
            if (Match('=')) return MakeToken(TokenType::Operator, "!=");
            return MakeToken(TokenType::Operator, "!");
        case '<':
            if (Match('=')) return MakeToken(TokenType::Operator, "<=");
            if (Match('<')) {
                if (Match('=')) return MakeToken(TokenType::Operator, "<<=");
                return MakeToken(TokenType::Operator, "<<");
            }
            return MakeToken(TokenType::Operator, "<");
        case '>':
            if (Match('=')) return MakeToken(TokenType::Operator, ">=");
            if (Match('>')) {
                if (Match('=')) return MakeToken(TokenType::Operator, ">>=");
                if (Match('>')) {
                    if (Match('=')) return MakeToken(TokenType::Operator, ">>>=");
                    return MakeToken(TokenType::Operator, ">>>");
                }
                return MakeToken(TokenType::Operator, ">>");
            }
            return MakeToken(TokenType::Operator, ">");
        case '&':
            if (Match('&')) return MakeToken(TokenType::Operator, "&&");
            if (Match('=')) return MakeToken(TokenType::Operator, "&=");
            return MakeToken(TokenType::Operator, "&");
        case '|':
            if (Match('|')) return MakeToken(TokenType::Operator, "||");
            if (Match('=')) return MakeToken(TokenType::Operator, "|=");
            return MakeToken(TokenType::Operator, "|");
        case '^':
            if (Match('=')) return MakeToken(TokenType::Operator, "^=");
            return MakeToken(TokenType::Operator, "^");
        case '~':
            return MakeToken(TokenType::Operator, "~");
        case '?':
            return MakeToken(TokenType::Operator, "?");
        case '#':
            return Preprocessor();
    }
    
    // Unknown character
    return MakeToken(TokenType::Punctuation, std::string(1, c));
}

// ============================================================================
// Token Type Helpers
// ============================================================================

Token Lexer::Identifier() {
    while (IsAlphaNumeric(Peek())) {
        Advance();
    }
    
    std::string text = source_.substr(startPos_, pos_ - startPos_);
    
    if (g_keywords.find(text) != g_keywords.end()) {
        return MakeToken(TokenType::Keyword, text);
    }
    
    return MakeToken(TokenType::Identifier, text);
}

Token Lexer::Number() {
    // Integer part
    while (IsDigit(Peek())) {
        Advance();
    }
    
    // Decimal part
    if (Peek() == '.' && IsDigit(PeekNext())) {
        Advance(); // Consume '.'
        while (IsDigit(Peek())) {
            Advance();
        }
    }
    
    // Exponent
    if (Peek() == 'e' || Peek() == 'E') {
        Advance();
        if (Peek() == '+' || Peek() == '-') {
            Advance();
        }
        while (IsDigit(Peek())) {
            Advance();
        }
    }
    
    // Suffixes
    while (IsAlpha(Peek())) {
        Advance();
    }
    
    return MakeToken(TokenType::Number, source_.substr(startPos_, pos_ - startPos_));
}

Token Lexer::String(char quote) {
    while (Peek() != quote && !IsAtEnd()) {
        if (Peek() == '\\') {
            Advance(); // Escape sequence
            if (!IsAtEnd()) {
                Advance();
            }
        } else {
            Advance();
        }
    }
    
    if (!IsAtEnd()) {
        Advance(); // Closing quote
    }
    
    return MakeToken(TokenType::String, source_.substr(startPos_, pos_ - startPos_));
}

Token Lexer::LineComment() {
    while (Peek() != '\n' && !IsAtEnd()) {
        Advance();
    }
    return MakeToken(TokenType::Comment, source_.substr(startPos_, pos_ - startPos_));
}

Token Lexer::BlockComment() {
    while (!IsAtEnd()) {
        if (Peek() == '*' && PeekNext() == '/') {
            Advance();
            Advance();
            break;
        }
        Advance();
    }
    return MakeToken(TokenType::Comment, source_.substr(startPos_, pos_ - startPos_));
}

Token Lexer::Preprocessor() {
    while (Peek() != '\n' && !IsAtEnd()) {
        Advance();
    }
    return MakeToken(TokenType::Keyword, source_.substr(startPos_, pos_ - startPos_));
}

Token Lexer::Operator(char c) {
    return MakeToken(TokenType::Operator, std::string(1, c));
}

// ============================================================================
// Utility Methods
// ============================================================================

char Lexer::Advance() {
    if (IsAtEnd()) return '\0';
    
    char c = source_[pos_++];
    if (c == '\n') {
        line_++;
        column_ = 1;
    } else {
        column_++;
    }
    return c;
}

char Lexer::Peek() const {
    if (IsAtEnd()) return '\0';
    return source_[pos_];
}

char Lexer::PeekNext() const {
    if (pos_ + 1 >= source_.size()) return '\0';
    return source_[pos_ + 1];
}

bool Lexer::Match(char expected) {
    if (IsAtEnd()) return false;
    if (source_[pos_] != expected) return false;
    Advance();
    return true;
}

void Lexer::SkipWhitespace() {
    while (!IsAtEnd()) {
        char c = Peek();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            Advance();
        } else {
            break;
        }
    }
}

bool Lexer::IsAtEnd() const {
    return pos_ >= source_.size();
}

bool Lexer::IsAlpha(char c) const {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
}

bool Lexer::IsDigit(char c) const {
    return std::isdigit(static_cast<unsigned char>(c));
}

bool Lexer::IsAlphaNumeric(char c) const {
    return IsAlpha(c) || IsDigit(c);
}

Token Lexer::MakeToken(TokenType type, const std::string& value) const {
    return {type, value, startLine_, startColumn_};
}

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

__declspec(dllexport) void* RawrXD_CreateLexer(const char* source) {
    if (!source) return nullptr;
    return new Lexer(source);
}

__declspec(dllexport) void RawrXD_DestroyLexer(void* lexer) {
    delete static_cast<Lexer*>(lexer);
}

__declspec(dllexport) int RawrXD_LexerGetTokenCount(void* lexer) {
    if (!lexer) return 0;
    auto tokens = static_cast<Lexer*>(lexer)->Tokenize();
    return static_cast<int>(tokens.size());
}

__declspec(dllexport) bool RawrXD_LexerIsKeyword(const char* word) {
    if (!word) return false;
    return g_keywords.find(word) != g_keywords.end();
}

} // extern "C"

=======
#include "RawrXD_Lexer.h"
#include <cwctype>

namespace RawrXD {

CppLexer::CppLexer() {
    keywords = {
        L"auto", L"break", L"case", L"char", L"const", L"continue", L"default", L"do",
        L"double", L"else", L"enum", L"extern", L"float", L"for", L"goto", L"if",
        L"int", L"long", L"register", L"return", L"short", L"signed", L"sizeof", L"static",
        L"struct", L"switch", L"typedef", L"union", L"unsigned", L"void", L"volatile", L"while",
        L"class", L"namespace", L"new", L"delete", L"this", L"true", L"false", L"public",
        L"protected", L"private", L"virtual", L"friend", L"template", L"typename", L"using"
    };
}

void CppLexer::lex(const std::wstring& text, std::vector<Token>& outTokens) {
    outTokens.clear();
    if (text.empty()) return;

    int n = (int)text.length();
    int i = 0;

    while (i < n) {
        wchar_t c = text[i];

        // Whitespace
        if (iswspace(c)) {
            i++;
            continue;
        }

        // Comment
        if (c == L'/') {
            if (i + 1 < n && text[i+1] == L'/') {
                // Line comment
                outTokens.push_back({TokenType::Comment, i, n - i});
                break; 
            }
            if (i + 1 < n && text[i+1] == L'*') {
                // Block comment (simple scan)
                int start = i;
                i += 2;
                while (i + 1 < n && !(text[i] == L'*' && text[i+1] == L'/')) i++;
                if (i + 1 < n) i += 2;
                outTokens.push_back({TokenType::Comment, start, i - start});
                continue;
            }
        }

        // String
        if (c == L'"' || c == L'\'') {
            int start = i;
            wchar_t quote = c;
            i++;
            while (i < n) {
                if (text[i] == quote && text[i-1] != L'\\') {
                    i++;
                    break;
                }
                i++;
            }
            outTokens.push_back({TokenType::String, start, i - start});
            continue;
        }

        // Number
        if (iswdigit(c)) {
            int start = i;
            while (i < n && (iswdigit(text[i]) || text[i] == L'.' || text[i] == L'x' || (text[i] >= L'a' && text[i] <= L'f'))) i++;
            outTokens.push_back({TokenType::Number, start, i - start});
            continue;
        }

        // Identifier / Keyword
        if (iswalpha(c) || c == L'_') {
            int start = i;
            while (i < n && (iswalnum(text[i]) || text[i] == L'_')) i++;
            int len = i - start;
            std::wstring word = text.substr(start, len);
            
            if (keywords.count(word)) {
                outTokens.push_back({TokenType::Keyword, start, len});
            } else {
                outTokens.push_back({TokenType::Default, start, len});
            }
            continue;
        }

        // Operator / Punctuation
        outTokens.push_back({TokenType::Operator, i, 1});
        i++;
    }
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
} // namespace RawrXD
