//=============================================================================
// cpp_lexer.c - C++ Language Lexer
// Part of RawrXD Native Toolchain - Batch 2: Additional Language Frontends
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_TOKEN_TEXT 256
#define MAX_TOKENS 65536
#define MAX_ERRORS 256
#define MAX_STRING_LENGTH 4096

//=============================================================================
// C++ Token Types (extends C with C++ specific tokens)
//=============================================================================
typedef enum {
    // C Keywords (also valid in C++)
    TOK_AUTO, TOK_BREAK, TOK_CASE, TOK_CHAR, TOK_CONST, TOK_CONTINUE,
    TOK_DEFAULT, TOK_DO, TOK_DOUBLE, TOK_ELSE, TOK_ENUM, TOK_EXTERN,
    TOK_FLOAT, TOK_FOR, TOK_GOTO, TOK_IF, TOK_INLINE, TOK_INT,
    TOK_LONG, TOK_REGISTER, TOK_RESTRICT, TOK_RETURN, TOK_SHORT,
    TOK_SIGNED, TOK_SIZEOF, TOK_STATIC, TOK_STRUCT, TOK_SWITCH,
    TOK_TYPEDEF, TOK_UNION, TOK_UNSIGNED, TOK_VOID, TOK_VOLATILE,
    TOK_WHILE, TOK_BOOL, TOK_COMPLEX, TOK_IMAGINARY,
    
    // C++ Keywords
    TOK_ALIGNAS, TOK_ALIGNOF, TOK_AND, TOK_AND_EQ, TOK_ASM, TOK_ATOMIC_CANCEL,
    TOK_ATOMIC_COMMIT, TOK_ATOMIC_NOEXCEPT, TOK_BITAND, TOK_BITOR, TOK_CATCH,
    TOK_CLASS, TOK_COMPL, TOK_CONCEPT, TOK_CONST_CAST, TOK_CONSTEXPR,
    TOK_CO_AWAIT, TOK_CO_RETURN, TOK_CO_YIELD, TOK_DECLTYPE, TOK_DELETE,
    TOK_DYNAMIC_CAST, TOK_EXPLICIT, TOK_EXPORT, TOK_FALSE, TOK_FRIEND,
    TOK_MUTABLE, TOK_NAMESPACE, TOK_NEW, TOK_NOEXCEPT, TOK_NOT, TOK_NOT_EQ,
    TOK_NULLPTR, TOK_OPERATOR, TOK_OR, TOK_OR_EQ, TOK_PRIVATE, TOK_PROTECTED,
    TOK_PUBLIC, TOK_REFLEXPR, TOK_REINTERPRET_CAST, TOK_REQUIRES, TOK_STATIC_ASSERT,
    TOK_STATIC_CAST, TOK_TEMPLATE, TOK_THIS, TOK_THREAD_LOCAL, TOK_THROW,
    TOK_TRUE, TOK_TRY, TOK_TYPEID, TOK_TYPENAME, TOK_USING, TOK_VIRTUAL,
    TOK_WCHAR_T, TOK_XOR, TOK_XOR_EQ,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_INC, TOK_DEC, TOK_ARROW, TOK_DOT, TOK_DOT_STAR, TOK_ARROW_STAR,
    TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN, TOK_STAR_ASSIGN,
    TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN, TOK_AND_ASSIGN, TOK_OR_ASSIGN,
    TOK_XOR_ASSIGN, TOK_SHL_ASSIGN, TOK_SHR_ASSIGN,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_LOGICAL_AND, TOK_LOGICAL_OR, TOK_LOGICAL_NOT,
    TOK_BIT_AND, TOK_BIT_OR, TOK_BIT_XOR, TOK_BIT_NOT,
    TOK_SHL, TOK_SHR,
    TOK_SCOPE_RESOLUTION,  // ::
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COMMA,
    TOK_COLON, TOK_QUESTION, TOK_ELLIPSIS,  // ...
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL, TOK_STRING, TOK_CHAR_LITERAL,
    TOK_RAW_STRING,  // R"..."
    
    // Preprocessor
    TOK_HASH, TOK_HASH_HASH, TOK_PRAGMA, TOK_INCLUDE, TOK_DEFINE,
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_NEWLINE, TOK_WHITESPACE
} CPP_TokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    CPP_TokenType type;
    char text[MAX_TOKEN_TEXT];
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char string_val[MAX_TOKEN_TEXT];
    } value;
} CPP_Token;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    CPP_Token* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[MAX_ERRORS][512];
} CPPLexer;

//=============================================================================
// C++ Keywords Table
//=============================================================================
typedef struct {
    const char* word;
    CPP_TokenType type;
} CPPKeyword;

static const CPPKeyword cpp_keywords[] = {
    // C keywords
    {"auto", TOK_AUTO}, {"break", TOK_BREAK}, {"case", TOK_CASE},
    {"char", TOK_CHAR}, {"const", TOK_CONST}, {"continue", TOK_CONTINUE},
    {"default", TOK_DEFAULT}, {"do", TOK_DO}, {"double", TOK_DOUBLE},
    {"else", TOK_ELSE}, {"enum", TOK_ENUM}, {"extern", TOK_EXTERN},
    {"float", TOK_FLOAT}, {"for", TOK_FOR}, {"goto", TOK_GOTO},
    {"if", TOK_IF}, {"inline", TOK_INLINE}, {"int", TOK_INT},
    {"long", TOK_LONG}, {"register", TOK_REGISTER}, {"restrict", TOK_RESTRICT},
    {"return", TOK_RETURN}, {"short", TOK_SHORT}, {"signed", TOK_SIGNED},
    {"sizeof", TOK_SIZEOF}, {"static", TOK_STATIC}, {"struct", TOK_STRUCT},
    {"switch", TOK_SWITCH}, {"typedef", TOK_TYPEDEF}, {"union", TOK_UNION},
    {"unsigned", TOK_UNSIGNED}, {"void", TOK_VOID}, {"volatile", TOK_VOLATILE},
    {"while", TOK_WHILE}, {"_Bool", TOK_BOOL}, {"_Complex", TOK_COMPLEX},
    {"_Imaginary", TOK_IMAGINARY},
    
    // C++ keywords
    {"alignas", TOK_ALIGNAS}, {"alignof", TOK_ALIGNOF}, {"and", TOK_AND},
    {"and_eq", TOK_AND_EQ}, {"asm", TOK_ASM}, {"atomic_cancel", TOK_ATOMIC_CANCEL},
    {"atomic_commit", TOK_ATOMIC_COMMIT}, {"atomic_noexcept", TOK_ATOMIC_NOEXCEPT},
    {"bitand", TOK_BITAND}, {"bitor", TOK_BITOR}, {"catch", TOK_CATCH},
    {"class", TOK_CLASS}, {"compl", TOK_COMPL}, {"concept", TOK_CONCEPT},
    {"const_cast", TOK_CONST_CAST}, {"consteval", TOK_CONSTEXPR},
    {"constexpr", TOK_CONSTEXPR}, {"constinit", TOK_CONSTEXPR},
    {"co_await", TOK_CO_AWAIT}, {"co_return", TOK_CO_RETURN},
    {"co_yield", TOK_CO_YIELD}, {"decltype", TOK_DECLTYPE},
    {"delete", TOK_DELETE}, {"dynamic_cast", TOK_DYNAMIC_CAST},
    {"explicit", TOK_EXPLICIT}, {"export", TOK_EXPORT}, {"false", TOK_FALSE},
    {"friend", TOK_FRIEND}, {"mutable", TOK_MUTABLE}, {"namespace", TOK_NAMESPACE},
    {"new", TOK_NEW}, {"noexcept", TOK_NOEXCEPT}, {"not", TOK_NOT},
    {"not_eq", TOK_NOT_EQ}, {"nullptr", TOK_NULLPTR}, {"operator", TOK_OPERATOR},
    {"or", TOK_OR}, {"or_eq", TOK_OR_EQ}, {"private", TOK_PRIVATE},
    {"protected", TOK_PROTECTED}, {"public", TOK_PUBLIC}, {"reflexpr", TOK_REFLEXPR},
    {"reinterpret_cast", TOK_REINTERPRET_CAST}, {"requires", TOK_REQUIRES},
    {"static_assert", TOK_STATIC_ASSERT}, {"static_cast", TOK_STATIC_CAST},
    {"template", TOK_TEMPLATE}, {"this", TOK_THIS}, {"thread_local", TOK_THREAD_LOCAL},
    {"throw", TOK_THROW}, {"true", TOK_TRUE}, {"try", TOK_TRY},
    {"typeid", TOK_TYPEID}, {"typename", TOK_TYPENAME}, {"using", TOK_USING},
    {"virtual", TOK_VIRTUAL}, {"wchar_t", TOK_WCHAR_T}, {"xor", TOK_XOR},
    {"xor_eq", TOK_XOR_EQ},
    {NULL, TOK_EOF}
};

//=============================================================================
// Utility Functions
//=============================================================================
static int is_alpha_or_underscore(int c) {
    return isalpha(c) || c == '_';
}

static int is_alnum_or_underscore(int c) {
    return isalnum(c) || c == '_';
}

static void cpp_lexer_add_error(CPPLexer* lexer, const char* format, ...) {
    if (lexer->error_count >= MAX_ERRORS) return;
    va_list args;
    va_start(args, format);
    vsnprintf(lexer->errors[lexer->error_count], 512, format, args);
    va_end(args);
    lexer->error_count++;
}

static void cpp_lexer_add_token(CPPLexer* lexer, CPP_TokenType type, const char* text, int line, int col) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = realloc(lexer->tokens, lexer->token_capacity * sizeof(CPP_Token));
    }
    CPP_Token* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, MAX_TOKEN_TEXT - 1);
    tok->text[MAX_TOKEN_TEXT - 1] = '\0';
    tok->line = line;
    tok->column = col;
}

static char cpp_lexer_peek(CPPLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char cpp_lexer_peek_next(CPPLexer* lexer) {
    if (lexer->pos + 1 >= lexer->length) return '\0';
    return lexer->source[lexer->pos + 1];
}

static char cpp_lexer_advance(CPPLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    char c = lexer->source[lexer->pos++];
    if (c == '\n') {
        lexer->line++;
        lexer->column = 1;
    } else {
        lexer->column++;
    }
    return c;
}

static int cpp_lexer_match(CPPLexer* lexer, char expected) {
    if (cpp_lexer_peek(lexer) == expected) {
        cpp_lexer_advance(lexer);
        return 1;
    }
    return 0;
}

static void cpp_lexer_skip_whitespace(CPPLexer* lexer) {
    while (isspace(cpp_lexer_peek(lexer)) && cpp_lexer_peek(lexer) != '\n') {
        cpp_lexer_advance(lexer);
    }
}

static void cpp_lexer_skip_line(CPPLexer* lexer) {
    while (cpp_lexer_peek(lexer) != '\n' && cpp_lexer_peek(lexer) != '\0') {
        cpp_lexer_advance(lexer);
    }
}

//=============================================================================
// Token Recognition Functions
//=============================================================================

static CPP_TokenType cpp_get_keyword_type(const char* word) {
    for (int i = 0; cpp_keywords[i].word != NULL; i++) {
        if (strcmp(cpp_keywords[i].word, word) == 0) {
            return cpp_keywords[i].type;
        }
    }
    return TOK_IDENTIFIER;
}

static void cpp_lexer_read_identifier(CPPLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    while (is_alnum_or_underscore(cpp_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = cpp_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    CPP_TokenType type = cpp_get_keyword_type(buffer);
    cpp_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void cpp_lexer_read_number(CPPLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    int is_float = 0;
    int is_hex = 0;
    int is_bin = 0;
    int is_oct = 0;
    
    // Check for hex (0x or 0X)
    if (cpp_lexer_peek(lexer) == '0' && 
        (cpp_lexer_peek_next(lexer) == 'x' || cpp_lexer_peek_next(lexer) == 'X')) {
        is_hex = 1;
        buffer[i++] = cpp_lexer_advance(lexer);  // '0'
        buffer[i++] = cpp_lexer_advance(lexer);  // 'x' or 'X'
        while (isxdigit(cpp_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = cpp_lexer_advance(lexer);
        }
    }
    // Check for binary (0b or 0B) - C++14
    else if (cpp_lexer_peek(lexer) == '0' && 
             (cpp_lexer_peek_next(lexer) == 'b' || cpp_lexer_peek_next(lexer) == 'B')) {
        is_bin = 1;
        buffer[i++] = cpp_lexer_advance(lexer);  // '0'
        buffer[i++] = cpp_lexer_advance(lexer);  // 'b' or 'B'
        while ((cpp_lexer_peek(lexer) == '0' || cpp_lexer_peek(lexer) == '1') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = cpp_lexer_advance(lexer);
        }
    }
    // Octal or decimal
    else {
        while (isdigit(cpp_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
            char c = cpp_lexer_advance(lexer);
            buffer[i++] = c;
            if (c == '8' || c == '9') is_oct = 0;
            else if (c >= '0' && c <= '7' && i == 1) is_oct = 1;
        }
        
        // Decimal point or exponent
        if (cpp_lexer_peek(lexer) == '.' || cpp_lexer_peek(lexer) == 'e' || cpp_lexer_peek(lexer) == 'E') {
            is_float = 1;
            if (cpp_lexer_peek(lexer) == '.') {
                buffer[i++] = cpp_lexer_advance(lexer);
                while (isdigit(cpp_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
                    buffer[i++] = cpp_lexer_advance(lexer);
                }
            }
            if (cpp_lexer_peek(lexer) == 'e' || cpp_lexer_peek(lexer) == 'E') {
                buffer[i++] = cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '+' || cpp_lexer_peek(lexer) == '-') {
                    buffer[i++] = cpp_lexer_advance(lexer);
                }
                while (isdigit(cpp_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
                    buffer[i++] = cpp_lexer_advance(lexer);
                }
            }
        }
    }
    
    // Integer suffixes (u, U, l, L, ll, LL, ul, uL, etc.)
    // Floating suffixes (f, F, l, L)
    while (i < MAX_TOKEN_TEXT - 1) {
        char c = cpp_lexer_peek(lexer);
        if (is_float) {
            if (c == 'f' || c == 'F' || c == 'l' || c == 'L') {
                buffer[i++] = cpp_lexer_advance(lexer);
            } else break;
        } else {
            if (c == 'u' || c == 'U' || c == 'l' || c == 'L') {
                buffer[i++] = cpp_lexer_advance(lexer);
            } else break;
        }
    }
    
    buffer[i] = '\0';
    cpp_lexer_add_token(lexer, is_float ? TOK_FLOAT_LITERAL : TOK_INTEGER, buffer, start_line, start_col);
}

static void cpp_lexer_read_string(CPPLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    char quote = cpp_lexer_advance(lexer);  // Opening quote
    
    while (cpp_lexer_peek(lexer) != quote && cpp_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        if (cpp_lexer_peek(lexer) == '\\') {
            cpp_lexer_advance(lexer);  // Backslash
            char escape = cpp_lexer_advance(lexer);
            switch (escape) {
                case 'n': buffer[i++] = '\n'; break;
                case 't': buffer[i++] = '\t'; break;
                case 'r': buffer[i++] = '\r'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '"': buffer[i++] = '"'; break;
                case '\'': buffer[i++] = '\''; break;
                case '0': buffer[i++] = '\0'; break;
                case 'x': {
                    // Hex escape
                    char hex[3] = {0};
                    if (isxdigit(cpp_lexer_peek(lexer))) hex[0] = cpp_lexer_advance(lexer);
                    if (isxdigit(cpp_lexer_peek(lexer))) hex[1] = cpp_lexer_advance(lexer);
                    buffer[i++] = (char)strtol(hex, NULL, 16);
                    break;
                }
                default: buffer[i++] = escape; break;
            }
        } else {
            buffer[i++] = cpp_lexer_advance(lexer);
        }
    }
    
    if (cpp_lexer_peek(lexer) == quote) {
        cpp_lexer_advance(lexer);  // Closing quote
    } else {
        cpp_lexer_add_error(lexer, "Unterminated string literal at line %d", start_line);
    }
    
    buffer[i] = '\0';
    cpp_lexer_add_token(lexer, quote == '"' ? TOK_STRING : TOK_CHAR_LITERAL, buffer, start_line, start_col);
}

static void cpp_lexer_read_raw_string(CPPLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    // R"delimiter(raw_characters)delimiter"
    cpp_lexer_advance(lexer);  // 'R'
    cpp_lexer_advance(lexer);  // '"'
    
    // Read delimiter
    char delimiter[16] = {0};
    int delim_len = 0;
    while (cpp_lexer_peek(lexer) != '(' && cpp_lexer_peek(lexer) != '\0' && delim_len < 15) {
        delimiter[delim_len++] = cpp_lexer_advance(lexer);
    }
    
    if (cpp_lexer_peek(lexer) != '(') {
        cpp_lexer_add_error(lexer, "Invalid raw string literal at line %d", start_line);
        return;
    }
    cpp_lexer_advance(lexer);  // '('
    
    // Read raw characters
    while (i < MAX_STRING_LENGTH - 1) {
        if (cpp_lexer_peek(lexer) == ')') {
            // Check for closing delimiter
            int match = 1;
            for (int j = 0; j < delim_len; j++) {
                if (cpp_lexer_peek_next_n(lexer, j + 1) != delimiter[j]) {
                    match = 0;
                    break;
                }
            }
            if (match && cpp_lexer_peek_next_n(lexer, delim_len + 1) == '"') {
                cpp_lexer_advance(lexer);  // ')'
                for (int j = 0; j < delim_len; j++) cpp_lexer_advance(lexer);
                cpp_lexer_advance(lexer);  // '"'
                break;
            }
        }
        buffer[i++] = cpp_lexer_advance(lexer);
    }
    
    buffer[i] = '\0';
    cpp_lexer_add_token(lexer, TOK_RAW_STRING, buffer, start_line, start_col);
}

// Helper for peeking n characters ahead
static char cpp_lexer_peek_next_n(CPPLexer* lexer, int n) {
    if (lexer->pos + n >= lexer->length) return '\0';
    return lexer->source[lexer->pos + n];
}

static void cpp_lexer_read_preprocessor(CPPLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    
    cpp_lexer_advance(lexer);  // '#'
    cpp_lexer_skip_whitespace(lexer);
    
    char directive[MAX_TOKEN_TEXT];
    int i = 0;
    while (isalpha(cpp_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        directive[i++] = cpp_lexer_advance(lexer);
    }
    directive[i] = '\0';
    
    if (strcmp(directive, "include") == 0) {
        cpp_lexer_add_token(lexer, TOK_INCLUDE, "#include", start_line, start_col);
    } else if (strcmp(directive, "define") == 0) {
        cpp_lexer_add_token(lexer, TOK_DEFINE, "#define", start_line, start_col);
    } else if (strcmp(directive, "pragma") == 0) {
        cpp_lexer_add_token(lexer, TOK_PRAGMA, "#pragma", start_line, start_col);
    } else {
        cpp_lexer_add_token(lexer, TOK_HASH, "#", start_line, start_col);
    }
    
    // Skip rest of preprocessor line
    cpp_lexer_skip_line(lexer);
}

//=============================================================================
// Main Lexer Functions
//=============================================================================

CPPLexer* cpp_lexer_create(const char* source) {
    CPPLexer* lexer = malloc(sizeof(CPPLexer));
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = malloc(lexer->token_capacity * sizeof(CPP_Token));
    lexer->token_count = 0;
    lexer->error_count = 0;
    return lexer;
}

void cpp_lexer_destroy(CPPLexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

int cpp_lexer_tokenize(CPPLexer* lexer) {
    while (lexer->pos < lexer->length) {
        int start_line = lexer->line;
        int start_col = lexer->column;
        char c = cpp_lexer_peek(lexer);
        
        // Skip whitespace (but not newlines)
        if (isspace(c) && c != '\n') {
            cpp_lexer_skip_whitespace(lexer);
            continue;
        }
        
        // Newline
        if (c == '\n') {
            cpp_lexer_add_token(lexer, TOK_NEWLINE, "\\n", lexer->line, lexer->column);
            cpp_lexer_advance(lexer);
            continue;
        }
        
        // Comments
        if (c == '/' && cpp_lexer_peek_next(lexer) == '/') {
            cpp_lexer_skip_line(lexer);
            continue;
        }
        if (c == '/' && cpp_lexer_peek_next(lexer) == '*') {
            cpp_lexer_advance(lexer);
            cpp_lexer_advance(lexer);
            while (!(cpp_lexer_peek(lexer) == '*' && cpp_lexer_peek_next(lexer) == '/') && 
                   cpp_lexer_peek(lexer) != '\0') {
                cpp_lexer_advance(lexer);
            }
            if (cpp_lexer_peek(lexer) == '*') {
                cpp_lexer_advance(lexer);
                cpp_lexer_advance(lexer);
            }
            continue;
        }
        
        // Preprocessor
        if (c == '#' && start_col == 1) {
            cpp_lexer_read_preprocessor(lexer);
            continue;
        }
        
        // Identifiers and keywords
        if (is_alpha_or_underscore(c)) {
            cpp_lexer_read_identifier(lexer);
            continue;
        }
        
        // Numbers
        if (isdigit(c)) {
            cpp_lexer_read_number(lexer);
            continue;
        }
        
        // Strings and characters
        if (c == '"' || c == '\'') {
            cpp_lexer_read_string(lexer);
            continue;
        }
        
        // Raw strings (R"...")
        if (c == 'R' && cpp_lexer_peek_next(lexer) == '"') {
            cpp_lexer_read_raw_string(lexer);
            continue;
        }
        
        // Operators and delimiters
        switch (c) {
            case '(': cpp_lexer_add_token(lexer, TOK_LPAREN, "(", start_line, start_col); cpp_lexer_advance(lexer); break;
            case ')': cpp_lexer_add_token(lexer, TOK_RPAREN, ")", start_line, start_col); cpp_lexer_advance(lexer); break;
            case '{': cpp_lexer_add_token(lexer, TOK_LBRACE, "{", start_line, start_col); cpp_lexer_advance(lexer); break;
            case '}': cpp_lexer_add_token(lexer, TOK_RBRACE, "}", start_line, start_col); cpp_lexer_advance(lexer); break;
            case '[': cpp_lexer_add_token(lexer, TOK_LBRACKET, "[", start_line, start_col); cpp_lexer_advance(lexer); break;
            case ']': cpp_lexer_add_token(lexer, TOK_RBRACKET, "]", start_line, start_col); cpp_lexer_advance(lexer); break;
            case ';': cpp_lexer_add_token(lexer, TOK_SEMICOLON, ";", start_line, start_col); cpp_lexer_advance(lexer); break;
            case ',': cpp_lexer_add_token(lexer, TOK_COMMA, ",", start_line, start_col); cpp_lexer_advance(lexer); break;
            case ':': cpp_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col); cpp_lexer_advance(lexer); break;
            case '?': cpp_lexer_add_token(lexer, TOK_QUESTION, "?", start_line, start_col); cpp_lexer_advance(lexer); break;
            case '~': cpp_lexer_add_token(lexer, TOK_BIT_NOT, "~", start_line, start_col); cpp_lexer_advance(lexer); break;
            
            case '+':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '+') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_INC, "++", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_PLUS_ASSIGN, "+=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_PLUS, "+", start_line, start_col);
                }
                break;
                
            case '-':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '-') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_DEC, "--", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_MINUS_ASSIGN, "-=", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '>') {
                    cpp_lexer_advance(lexer);
                    if (cpp_lexer_peek(lexer) == '*') {
                        cpp_lexer_advance(lexer);
                        cpp_lexer_add_token(lexer, TOK_ARROW_STAR, "->*", start_line, start_col);
                    } else {
                        cpp_lexer_add_token(lexer, TOK_ARROW, "->", start_line, start_col);
                    }
                } else {
                    cpp_lexer_add_token(lexer, TOK_MINUS, "-", start_line, start_col);
                }
                break;
                
            case '*':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_STAR_ASSIGN, "*=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_STAR, "*", start_line, start_col);
                }
                break;
                
            case '/':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_SLASH_ASSIGN, "/=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_SLASH, "/", start_line, start_col);
                }
                break;
                
            case '%':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_PERCENT_ASSIGN, "%=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_PERCENT, "%", start_line, start_col);
                }
                break;
                
            case '=':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_EQ, "==", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_ASSIGN, "=", start_line, start_col);
                }
                break;
                
            case '!':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_NE, "!=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_LOGICAL_NOT, "!", start_line, start_col);
                }
                break;
                
            case '<':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_LE, "<=", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '<') {
                    cpp_lexer_advance(lexer);
                    if (cpp_lexer_peek(lexer) == '=') {
                        cpp_lexer_advance(lexer);
                        cpp_lexer_add_token(lexer, TOK_SHL_ASSIGN, "<<=", start_line, start_col);
                    } else {
                        cpp_lexer_add_token(lexer, TOK_SHL, "<<", start_line, start_col);
                    }
                } else {
                    cpp_lexer_add_token(lexer, TOK_LT, "<", start_line, start_col);
                }
                break;
                
            case '>':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_GE, ">=", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '>') {
                    cpp_lexer_advance(lexer);
                    if (cpp_lexer_peek(lexer) == '=') {
                        cpp_lexer_advance(lexer);
                        cpp_lexer_add_token(lexer, TOK_SHR_ASSIGN, ">>=", start_line, start_col);
                    } else {
                        cpp_lexer_add_token(lexer, TOK_SHR, ">>", start_line, start_col);
                    }
                } else {
                    cpp_lexer_add_token(lexer, TOK_GT, ">", start_line, start_col);
                }
                break;
                
            case '&':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '&') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_LOGICAL_AND, "&&", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_AND_ASSIGN, "&=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_BIT_AND, "&", start_line, start_col);
                }
                break;
                
            case '|':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '|') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_LOGICAL_OR, "||", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_OR_ASSIGN, "|=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_BIT_OR, "|", start_line, start_col);
                }
                break;
                
            case '^':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '=') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_XOR_ASSIGN, "^=", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_BIT_XOR, "^", start_line, start_col);
                }
                break;
                
            case '.':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == '.' && cpp_lexer_peek_next(lexer) == '.') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_ELLIPSIS, "...", start_line, start_col);
                } else if (cpp_lexer_peek(lexer) == '*') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_DOT_STAR, ".*", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_DOT, ".", start_line, start_col);
                }
                break;
                
            case ':':
                cpp_lexer_advance(lexer);
                if (cpp_lexer_peek(lexer) == ':') {
                    cpp_lexer_advance(lexer);
                    cpp_lexer_add_token(lexer, TOK_SCOPE_RESOLUTION, "::", start_line, start_col);
                } else {
                    cpp_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col);
                }
                break;
                
            default:
                cpp_lexer_add_error(lexer, "Unexpected character '%c' at line %d, column %d", c, start_line, start_col);
                cpp_lexer_advance(lexer);
                break;
        }
    }
    
    cpp_lexer_add_token(lexer, TOK_EOF, "EOF", lexer->line, lexer->column);
    return lexer->error_count == 0 ? 0 : -1;
}

const char* cpp_token_type_to_string(CPP_TokenType type) {
    switch (type) {
        // C keywords
        case TOK_AUTO: return "AUTO";
        case TOK_BREAK: return "BREAK";
        case TOK_CASE: return "CASE";
        case TOK_CHAR: return "CHAR";
        case TOK_CONST: return "CONST";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_DEFAULT: return "DEFAULT";
        case TOK_DO: return "DO";
        case TOK_DOUBLE: return "DOUBLE";
        case TOK_ELSE: return "ELSE";
        case TOK_ENUM: return "ENUM";
        case TOK_EXTERN: return "EXTERN";
        case TOK_FLOAT: return "FLOAT";
        case TOK_FOR: return "FOR";
        case TOK_GOTO: return "GOTO";
        case TOK_IF: return "IF";
        case TOK_INLINE: return "INLINE";
        case TOK_INT: return "INT";
        case TOK_LONG: return "LONG";
        case TOK_REGISTER: return "REGISTER";
        case TOK_RESTRICT: return "RESTRICT";
        case TOK_RETURN: return "RETURN";
        case TOK_SHORT: return "SHORT";
        case TOK_SIGNED: return "SIGNED";
        case TOK_SIZEOF: return "SIZEOF";
        case TOK_STATIC: return "STATIC";
        case TOK_STRUCT: return "STRUCT";
        case TOK_SWITCH: return "SWITCH";
        case TOK_TYPEDEF: return "TYPEDEF";
        case TOK_UNION: return "UNION";
        case TOK_UNSIGNED: return "UNSIGNED";
        case TOK_VOID: return "VOID";
        case TOK_VOLATILE: return "VOLATILE";
        case TOK_WHILE: return "WHILE";
        case TOK_BOOL: return "BOOL";
        case TOK_COMPLEX: return "COMPLEX";
        case TOK_IMAGINARY: return "IMAGINARY";
        
        // C++ keywords
        case TOK_ALIGNAS: return "ALIGNAS";
        case TOK_ALIGNOF: return "ALIGNOF";
        case TOK_AND: return "AND";
        case TOK_AND_EQ: return "AND_EQ";
        case TOK_ASM: return "ASM";
        case TOK_ATOMIC_CANCEL: return "ATOMIC_CANCEL";
        case TOK_ATOMIC_COMMIT: return "ATOMIC_COMMIT";
        case TOK_ATOMIC_NOEXCEPT: return "ATOMIC_NOEXCEPT";
        case TOK_BITAND: return "BITAND";
        case TOK_BITOR: return "BITOR";
        case TOK_CATCH: return "CATCH";
        case TOK_CLASS: return "CLASS";
        case TOK_COMPL: return "COMPL";
        case TOK_CONCEPT: return "CONCEPT";
        case TOK_CONST_CAST: return "CONST_CAST";
        case TOK_CONSTEXPR: return "CONSTEXPR";
        case TOK_CO_AWAIT: return "CO_AWAIT";
        case TOK_CO_RETURN: return "CO_RETURN";
        case TOK_CO_YIELD: return "CO_YIELD";
        case TOK_DECLTYPE: return "DECLTYPE";
        case TOK_DELETE: return "DELETE";
        case TOK_DYNAMIC_CAST: return "DYNAMIC_CAST";
        case TOK_EXPLICIT: return "EXPLICIT";
        case TOK_EXPORT: return "EXPORT";
        case TOK_FALSE: return "FALSE";
        case TOK_FRIEND: return "FRIEND";
        case TOK_MUTABLE: return "MUTABLE";
        case TOK_NAMESPACE: return "NAMESPACE";
        case TOK_NEW: return "NEW";
        case TOK_NOEXCEPT: return "NOEXCEPT";
        case TOK_NOT: return "NOT";
        case TOK_NOT_EQ: return "NOT_EQ";
        case TOK_NULLPTR: return "NULLPTR";
        case TOK_OPERATOR: return "OPERATOR";
        case TOK_OR: return "OR";
        case TOK_OR_EQ: return "OR_EQ";
        case TOK_PRIVATE: return "PRIVATE";
        case TOK_PROTECTED: return "PROTECTED";
        case TOK_PUBLIC: return "PUBLIC";
        case TOK_REFLEXPR: return "REFLEXPR";
        case TOK_REINTERPRET_CAST: return "REINTERPRET_CAST";
        case TOK_REQUIRES: return "REQUIRES";
        case TOK_STATIC_ASSERT: return "STATIC_ASSERT";
        case TOK_STATIC_CAST: return "STATIC_CAST";
        case TOK_TEMPLATE: return "TEMPLATE";
        case TOK_THIS: return "THIS";
        case TOK_THREAD_LOCAL: return "THREAD_LOCAL";
        case TOK_THROW: return "THROW";
        case TOK_TRUE: return "TRUE";
        case TOK_TRY: return "TRY";
        case TOK_TYPEID: return "TYPEID";
        case TOK_TYPENAME: return "TYPENAME";
        case TOK_USING: return "USING";
        case TOK_VIRTUAL: return "VIRTUAL";
        case TOK_WCHAR_T: return "WCHAR_T";
        case TOK_XOR: return "XOR";
        case TOK_XOR_EQ: return "XOR_EQ";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_INC: return "INC";
        case TOK_DEC: return "DEC";
        case TOK_ARROW: return "ARROW";
        case TOK_DOT: return "DOT";
        case TOK_DOT_STAR: return "DOT_STAR";
        case TOK_ARROW_STAR: return "ARROW_STAR";
        case TOK_ASSIGN: return "ASSIGN";
        case TOK_PLUS_ASSIGN: return "PLUS_ASSIGN";
        case TOK_MINUS_ASSIGN: return "MINUS_ASSIGN";
        case TOK_STAR_ASSIGN: return "STAR_ASSIGN";
        case TOK_SLASH_ASSIGN: return "SLASH_ASSIGN";
        case TOK_PERCENT_ASSIGN: return "PERCENT_ASSIGN";
        case TOK_AND_ASSIGN: return "AND_ASSIGN";
        case TOK_OR_ASSIGN: return "OR_ASSIGN";
        case TOK_XOR_ASSIGN: return "XOR_ASSIGN";
        case TOK_SHL_ASSIGN: return "SHL_ASSIGN";
        case TOK_SHR_ASSIGN: return "SHR_ASSIGN";
        case TOK_EQ: return "EQ";
        case TOK_NE: return "NE";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_LOGICAL_AND: return "LOGICAL_AND";
        case TOK_LOGICAL_OR: return "LOGICAL_OR";
        case TOK_LOGICAL_NOT: return "LOGICAL_NOT";
        case TOK_BIT_AND: return "BIT_AND";
        case TOK_BIT_OR: return "BIT_OR";
        case TOK_BIT_XOR: return "BIT_XOR";
        case TOK_BIT_NOT: return "BIT_NOT";
        case TOK_SHL: return "SHL";
        case TOK_SHR: return "SHR";
        case TOK_SCOPE_RESOLUTION: return "SCOPE_RESOLUTION";
        
        // Delimiters
        case TOK_LPAREN: return "LPAREN";
        case TOK_RPAREN: return "RPAREN";
        case TOK_LBRACE: return "LBRACE";
        case TOK_RBRACE: return "RBRACE";
        case TOK_LBRACKET: return "LBRACKET";
        case TOK_RBRACKET: return "RBRACKET";
        case TOK_SEMICOLON: return "SEMICOLON";
        case TOK_COMMA: return "COMMA";
        case TOK_COLON: return "COLON";
        case TOK_QUESTION: return "QUESTION";
        case TOK_ELLIPSIS: return "ELLIPSIS";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_CHAR_LITERAL: return "CHAR_LITERAL";
        case TOK_RAW_STRING: return "RAW_STRING";
        
        // Preprocessor
        case TOK_HASH: return "HASH";
        case TOK_HASH_HASH: return "HASH_HASH";
        case TOK_PRAGMA: return "PRAGMA";
        case TOK_INCLUDE: return "INCLUDE";
        case TOK_DEFINE: return "DEFINE";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_NEWLINE: return "NEWLINE";
        case TOK_WHITESPACE: return "WHITESPACE";
        
        default: return "UNKNOWN";
    }
}

void cpp_lexer_print_tokens(CPPLexer* lexer) {
    printf("\n=== C++ Lexer Output ===\n");
    printf("Total tokens: %zu\n\n", lexer->token_count);
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        CPP_Token* tok = &lexer->tokens[i];
        printf("[%4zu] %-20s line %3d col %3d  '%s'\n",
               i, cpp_token_type_to_string(tok->type), tok->line, tok->column, tok->text);
    }
    
    if (lexer->error_count > 0) {
        printf("\n=== Errors ===\n");
        for (int i = 0; i < lexer->error_count; i++) {
            printf("  Error %d: %s\n", i + 1, lexer->errors[i]);
        }
    }
}

//=============================================================================
// Test Main
//=============================================================================
#ifdef CPP_LEXER_TEST

int main(int argc, char* argv[]) {
    const char* test_code = 
        "#include <iostream>\n"
        "\n"
        "class Point {\n"
        "public:\n"
        "    int x, y;\n"
        "    Point(int x_val, int y_val) : x(x_val), y(y_val) {}\n"
        "    double distance() const {\n"
        "        return std::sqrt(x * x + y * y);\n"
        "    }\n"
        "};\n"
        "\n"
        "template<typename T>\n"
        "T max(T a, T b) {\n"
        "    return (a > b) ? a : b;\n"
        "}\n"
        "\n"
        "int main() {\n"
        "    auto p = new Point(3, 4);\n"
        "    constexpr int size = 100;\n"
        "    std::cout << \"Distance: \" << p->distance() << std::endl;\n"
        "    delete p;\n"
        "    return 0;\n"
        "}\n";
    
    printf("C++ Lexer Test\n");
    printf("==============\n\n");
    printf("Input code:\n%s\n", test_code);
    
    CPPLexer* lexer = cpp_lexer_create(test_code);
    int result = cpp_lexer_tokenize(lexer);
    
    cpp_lexer_print_tokens(lexer);
    
    printf("\n=== Result ===\n");
    if (result == 0) {
        printf("SUCCESS: Tokenized %zu tokens with %d errors\n", 
               lexer->token_count, lexer->error_count);
    } else {
        printf("FAILED: %d errors occurred\n", lexer->error_count);
    }
    
    cpp_lexer_destroy(lexer);
    return result;
}

#endif