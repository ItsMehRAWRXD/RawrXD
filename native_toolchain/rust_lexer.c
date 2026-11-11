//=============================================================================
// rust_lexer.c - Rust Language Lexer
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
// Rust Token Types
//=============================================================================
typedef enum {
    // Strict keywords (cannot be used as identifiers)
    TOK_AS, TOK_ASYNC, TOK_AWAIT, TOK_BREAK, TOK_CONST, TOK_CONTINUE,
    TOK_CRATE, TOK_DYN, TOK_ELSE, TOK_ENUM, TOK_EXTERN, TOK_FALSE,
    TOK_FN, TOK_FOR, TOK_IF, TOK_IMPL, TOK_IN, TOK_LET, TOK_LOOP,
    TOK_MATCH, TOK_MOD, TOK_MOVE, TOK_MUT, TOK_PUB, TOK_REF, TOK_RETURN,
    TOK_SELFVALUE, TOK_SELFTYPE, TOK_STATIC, TOK_STRUCT, TOK_SUPER,
    TOK_TRAIT, TOK_TRUE, TOK_TYPE, TOK_UNSAFE, TOK_USE, TOK_WHERE,
    TOK_WHILE,
    
    // Reserved keywords (for future use)
    TOK_ABSTRACT, TOK_BECOME, TOK_BOX, TOK_DO, TOK_FINAL, TOK_MACRO,
    TOK_OVERRIDE, TOK_PRIV, TOK_TYPEOF, TOK_UNSIZED, TOK_VIRTUAL,
    TOK_YIELD,
    
    // Weak keywords (context-dependent)
    TOK_UNION_KEYWORD, TOK_STATICLIFETIME,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_NOT, TOK_AND, TOK_OR, TOK_XOR, TOK_SHL, TOK_SHR,
    TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN, TOK_STAR_ASSIGN,
    TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN, TOK_AND_ASSIGN, TOK_OR_ASSIGN,
    TOK_XOR_ASSIGN, TOK_SHL_ASSIGN, TOK_SHR_ASSIGN,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_LOGICAL_AND, TOK_LOGICAL_OR,
    TOK_RANGE, TOK_RANGE_INCLUSIVE, TOK_RANGE_FROM, TOK_RANGE_TO,
    TOK_ARROW, TOK_THIN_ARROW, TOK_FAT_ARROW,
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COMMA,
    TOK_COLON, TOK_DOUBLE_COLON, TOK_DOT, TOK_DOUBLE_DOT, TOK_DOUBLE_DOT_EQ,
    TOK_POUND, TOK_DOLLAR, TOK_QUESTION, TOK_AT, TOK_BACKSLASH,
    TOK_APOSTROPHE,  // For lifetimes
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL, 
    TOK_STRING, TOK_BYTE_STRING, TOK_RAW_STRING, TOK_BYTE_RAW_STRING,
    TOK_CHAR_LITERAL, TOK_BYTE_LITERAL,
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_WHITESPACE, TOK_COMMENT, TOK_DOC_COMMENT,
    TOK_INNER_DOC_COMMENT, TOK_OUTER_DOC_COMMENT,
    
    // Macros
    TOK_MACRO_RULES, TOK_MACRO_INVOCATION
} RustTokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    RustTokenType type;
    char text[MAX_TOKEN_TEXT];
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char string_val[MAX_TOKEN_TEXT];
    } value;
} RustToken;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    RustToken* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[MAX_ERRORS][512];
} RustLexer;

//=============================================================================
// Rust Keywords Table
//=============================================================================
typedef struct {
    const char* word;
    RustTokenType type;
} RustKeyword;

static const RustKeyword rust_keywords[] = {
    // Strict keywords
    {"as", TOK_AS}, {"async", TOK_ASYNC}, {"await", TOK_AWAIT},
    {"break", TOK_BREAK}, {"const", TOK_CONST}, {"continue", TOK_CONTINUE},
    {"crate", TOK_CRATE}, {"dyn", TOK_DYN}, {"else", TOK_ELSE},
    {"enum", TOK_ENUM}, {"extern", TOK_EXTERN}, {"false", TOK_FALSE},
    {"fn", TOK_FN}, {"for", TOK_FOR}, {"if", TOK_IF},
    {"impl", TOK_IMPL}, {"in", TOK_IN}, {"let", TOK_LET},
    {"loop", TOK_LOOP}, {"match", TOK_MATCH}, {"mod", TOK_MOD},
    {"move", TOK_MOVE}, {"mut", TOK_MUT}, {"pub", TOK_PUB},
    {"ref", TOK_REF}, {"return", TOK_RETURN}, {"self", TOK_SELFVALUE},
    {"Self", TOK_SELFTYPE}, {"static", TOK_STATIC}, {"struct", TOK_STRUCT},
    {"super", TOK_SUPER}, {"trait", TOK_TRAIT}, {"true", TOK_TRUE},
    {"type", TOK_TYPE}, {"unsafe", TOK_UNSAFE}, {"use", TOK_USE},
    {"where", TOK_WHERE}, {"while", TOK_WHILE},
    
    // Reserved keywords
    {"abstract", TOK_ABSTRACT}, {"become", TOK_BECOME}, {"box", TOK_BOX},
    {"do", TOK_DO}, {"final", TOK_FINAL}, {"macro", TOK_MACRO},
    {"override", TOK_OVERRIDE}, {"priv", TOK_PRIV}, {"typeof", TOK_TYPEOF},
    {"unsized", TOK_UNSIZED}, {"virtual", TOK_VIRTUAL}, {"yield", TOK_YIELD},
    
    // Weak keywords (context-dependent)
    {"union", TOK_UNION_KEYWORD}, {"'static", TOK_STATICLIFETIME},
    
    {NULL, TOK_EOF}
};

//=============================================================================
// Utility Functions
//=============================================================================
static int rust_is_ident_start(int c) {
    return isalpha(c) || c == '_';
}

static int rust_is_ident_continue(int c) {
    return isalnum(c) || c == '_';
}

static void rust_lexer_add_error(RustLexer* lexer, const char* format, ...) {
    if (lexer->error_count >= MAX_ERRORS) return;
    va_list args;
    va_start(args, format);
    vsnprintf(lexer->errors[lexer->error_count], 512, format, args);
    va_end(args);
    lexer->error_count++;
}

static void rust_lexer_add_token(RustLexer* lexer, RustTokenType type, const char* text, int line, int col) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = realloc(lexer->tokens, lexer->token_capacity * sizeof(RustToken));
    }
    RustToken* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, MAX_TOKEN_TEXT - 1);
    tok->text[MAX_TOKEN_TEXT - 1] = '\0';
    tok->line = line;
    tok->column = col;
}

static char rust_lexer_peek(RustLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char rust_lexer_peek_next(RustLexer* lexer) {
    if (lexer->pos + 1 >= lexer->length) return '\0';
    return lexer->source[lexer->pos + 1];
}

static char rust_lexer_advance(RustLexer* lexer) {
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

static void rust_lexer_skip_whitespace(RustLexer* lexer) {
    while (isspace(rust_lexer_peek(lexer)) && rust_lexer_peek(lexer) != '\n') {
        rust_lexer_advance(lexer);
    }
}

//=============================================================================
// Token Recognition Functions
//=============================================================================

static RustTokenType rust_get_keyword_type(const char* word) {
    for (int i = 0; rust_keywords[i].word != NULL; i++) {
        if (strcmp(rust_keywords[i].word, word) == 0) {
            return rust_keywords[i].type;
        }
    }
    return TOK_IDENTIFIER;
}

static void rust_lexer_read_identifier(RustLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    while (rust_is_ident_continue(rust_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = rust_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    RustTokenType type = rust_get_keyword_type(buffer);
    rust_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void rust_lexer_read_number(RustLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    int is_float = 0;
    
    // Check for base prefix
    if (rust_lexer_peek(lexer) == '0') {
        buffer[i++] = rust_lexer_advance(lexer);
        char next = rust_lexer_peek(lexer);
        if (next == 'b' || next == 'B') {
            // Binary
            buffer[i++] = rust_lexer_advance(lexer);
            while ((rust_lexer_peek(lexer) == '0' || rust_lexer_peek(lexer) == '1' ||
                    rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = rust_lexer_advance(lexer);
            }
        } else if (next == 'o' || next == 'O') {
            // Octal
            buffer[i++] = rust_lexer_advance(lexer);
            while ((rust_lexer_peek(lexer) >= '0' && rust_lexer_peek(lexer) <= '7' ||
                    rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = rust_lexer_advance(lexer);
            }
        } else if (next == 'x' || next == 'X') {
            // Hexadecimal
            buffer[i++] = rust_lexer_advance(lexer);
            while ((isxdigit(rust_lexer_peek(lexer)) || rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = rust_lexer_advance(lexer);
            }
        } else if (next == '.') {
            // Float starting with 0.
            is_float = 1;
            buffer[i++] = rust_lexer_advance(lexer);
            while ((isdigit(rust_lexer_peek(lexer)) || rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = rust_lexer_advance(lexer);
            }
        }
    } else {
        // Decimal
        while ((isdigit(rust_lexer_peek(lexer)) || rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = rust_lexer_advance(lexer);
        }
        
        if (rust_lexer_peek(lexer) == '.' && isdigit(rust_lexer_peek_next(lexer))) {
            is_float = 1;
            buffer[i++] = rust_lexer_advance(lexer);
            while ((isdigit(rust_lexer_peek(lexer)) || rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = rust_lexer_advance(lexer);
            }
        }
    }
    
    // Exponent
    if (rust_lexer_peek(lexer) == 'e' || rust_lexer_peek(lexer) == 'E') {
        is_float = 1;
        buffer[i++] = rust_lexer_advance(lexer);
        if (rust_lexer_peek(lexer) == '+' || rust_lexer_peek(lexer) == '-') {
            buffer[i++] = rust_lexer_advance(lexer);
        }
        while ((isdigit(rust_lexer_peek(lexer)) || rust_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = rust_lexer_advance(lexer);
        }
    }
    
    // Type suffix
    while (i < MAX_TOKEN_TEXT - 1) {
        char c = rust_lexer_peek(lexer);
        if (c == 'u' || c == 'i' || c == 'f') {
            buffer[i++] = rust_lexer_advance(lexer);
            while (isdigit(rust_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = rust_lexer_advance(lexer);
            }
        } else if (c == 'e' && !is_float) {
            // e as exponent marker already handled above
            break;
        } else {
            break;
        }
    }
    
    buffer[i] = '\0';
    rust_lexer_add_token(lexer, is_float ? TOK_FLOAT_LITERAL : TOK_INTEGER, buffer, start_line, start_col);
}

static void rust_lexer_read_string(RustLexer* lexer, int is_byte) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    char quote = rust_lexer_advance(lexer);  // " or '
    if (is_byte) rust_lexer_advance(lexer);  // b prefix
    
    while (rust_lexer_peek(lexer) != quote && rust_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        if (rust_lexer_peek(lexer) == '\\') {
            rust_lexer_advance(lexer);
            char escape = rust_lexer_advance(lexer);
            switch (escape) {
                case 'n': buffer[i++] = '\n'; break;
                case 't': buffer[i++] = '\t'; break;
                case 'r': buffer[i++] = '\r'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '"': buffer[i++] = '"'; break;
                case '\'': buffer[i++] = '\''; break;
                case '0': buffer[i++] = '\0'; break;
                case 'x': {
                    char hex[3] = {0};
                    if (isxdigit(rust_lexer_peek(lexer))) hex[0] = rust_lexer_advance(lexer);
                    if (isxdigit(rust_lexer_peek(lexer))) hex[1] = rust_lexer_advance(lexer);
                    buffer[i++] = (char)strtol(hex, NULL, 16);
                    break;
                }
                case 'u': {
                    // Unicode escape \u{XXXX}
                    if (rust_lexer_peek(lexer) == '{') {
                        rust_lexer_advance(lexer);
                        char hex[7] = {0};
                        int h = 0;
                        while (isxdigit(rust_lexer_peek(lexer)) && h < 6) {
                            hex[h++] = rust_lexer_advance(lexer);
                        }
                        if (rust_lexer_peek(lexer) == '}') rust_lexer_advance(lexer);
                        // Simplified: just store as placeholder
                        buffer[i++] = '?';
                    }
                    break;
                }
                default: buffer[i++] = escape; break;
            }
        } else {
            buffer[i++] = rust_lexer_advance(lexer);
        }
    }
    
    if (rust_lexer_peek(lexer) == quote) {
        rust_lexer_advance(lexer);
    } else {
        rust_lexer_add_error(lexer, "Unterminated string literal at line %d", start_line);
    }
    
    buffer[i] = '\0';
    
    RustTokenType type;
    if (quote == '"') {
        type = is_byte ? TOK_BYTE_STRING : TOK_STRING;
    } else {
        type = is_byte ? TOK_BYTE_LITERAL : TOK_CHAR_LITERAL;
    }
    rust_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void rust_lexer_read_raw_string(RustLexer* lexer, int is_byte) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    if (is_byte) rust_lexer_advance(lexer);  // b
    rust_lexer_advance(lexer);  // r
    
    // Count # for delimiter
    int hash_count = 0;
    while (rust_lexer_peek(lexer) == '#') {
        hash_count++;
        rust_lexer_advance(lexer);
    }
    
    if (rust_lexer_peek(lexer) != '"') {
        rust_lexer_add_error(lexer, "Invalid raw string literal at line %d", start_line);
        return;
    }
    rust_lexer_advance(lexer);  // "
    
    // Read until closing " followed by hash_count #
    while (i < MAX_STRING_LENGTH - 1) {
        if (rust_lexer_peek(lexer) == '"') {
            rust_lexer_advance(lexer);
            int close_hash = 0;
            while (rust_lexer_peek(lexer) == '#' && close_hash < hash_count) {
                rust_lexer_advance(lexer);
                close_hash++;
            }
            if (close_hash == hash_count) {
                break;
            }
            // Not a close, add the quote and hashes to content
            buffer[i++] = '"';
            for (int h = 0; h < close_hash; h++) buffer[i++] = '#';
        } else if (rust_lexer_peek(lexer) == '\0') {
            rust_lexer_add_error(lexer, "Unterminated raw string at line %d", start_line);
            break;
        } else {
            buffer[i++] = rust_lexer_advance(lexer);
        }
    }
    
    buffer[i] = '\0';
    rust_lexer_add_token(lexer, is_byte ? TOK_BYTE_RAW_STRING : TOK_RAW_STRING, buffer, start_line, start_col);
}

static void rust_lexer_read_lifetime(RustLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    buffer[i++] = rust_lexer_advance(lexer);  // '
    
    // Check for 'static
    if (rust_lexer_peek(lexer) == 's' && rust_lexer_peek_next(lexer) == 't') {
        char word[16] = {0};
        int w = 0;
        while (rust_is_ident_continue(rust_lexer_peek(lexer)) && w < 15) {
            word[w++] = rust_lexer_advance(lexer);
        }
        if (strcmp(word, "static") == 0) {
            rust_lexer_add_token(lexer, TOK_STATICLIFETIME, "'static", start_line, start_col);
            return;
        }
        // Not 'static, add chars to buffer
        for (int j = 0; j < w; j++) buffer[i++] = word[j];
    } else {
        while (rust_is_ident_continue(rust_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = rust_lexer_advance(lexer);
        }
    }
    
    buffer[i] = '\0';
    rust_lexer_add_token(lexer, TOK_IDENTIFIER, buffer, start_line, start_col);
}

static void rust_lexer_skip_comment(RustLexer* lexer) {
    rust_lexer_advance(lexer);  // /
    rust_lexer_advance(lexer);  // /
    
    while (rust_lexer_peek(lexer) != '\n' && rust_lexer_peek(lexer) != '\0') {
        rust_lexer_advance(lexer);
    }
}

static void rust_lexer_skip_block_comment(RustLexer* lexer) {
    int start_line = lexer->line;
    rust_lexer_advance(lexer);  // /
    rust_lexer_advance(lexer);  // *
    
    while (!(rust_lexer_peek(lexer) == '*' && rust_lexer_peek_next(lexer) == '/') &&
           rust_lexer_peek(lexer) != '\0') {
        rust_lexer_advance(lexer);
    }
    
    if (rust_lexer_peek(lexer) == '*') {
        rust_lexer_advance(lexer);
        rust_lexer_advance(lexer);
    } else {
        rust_lexer_add_error(lexer, "Unterminated block comment starting at line %d", start_line);
    }
}

static void rust_lexer_read_doc_comment(RustLexer* lexer, int is_inner) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    
    rust_lexer_advance(lexer);  // /
    rust_lexer_advance(lexer);  // /
    if (is_inner) rust_lexer_advance(lexer);  // !
    rust_lexer_advance(lexer);  // /
    
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    while (rust_lexer_peek(lexer) != '\n' && rust_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        buffer[i++] = rust_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    rust_lexer_add_token(lexer, is_inner ? TOK_INNER_DOC_COMMENT : TOK_OUTER_DOC_COMMENT, 
                         buffer, start_line, start_col);
}

//=============================================================================
// Main Lexer Functions
//=============================================================================

RustLexer* rust_lexer_create(const char* source) {
    RustLexer* lexer = malloc(sizeof(RustLexer));
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = malloc(lexer->token_capacity * sizeof(RustToken));
    lexer->token_count = 0;
    lexer->error_count = 0;
    return lexer;
}

void rust_lexer_destroy(RustLexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

int rust_lexer_tokenize(RustLexer* lexer) {
    while (lexer->pos < lexer->length) {
        int start_line = lexer->line;
        int start_col = lexer->column;
        char c = rust_lexer_peek(lexer);
        
        // Skip whitespace
        if (isspace(c)) {
            rust_lexer_advance(lexer);
            continue;
        }
        
        // Comments
        if (c == '/' && rust_lexer_peek_next(lexer) == '/') {
            // Check for doc comments
            if (lexer->pos + 2 < lexer->length) {
                char third = lexer->source[lexer->pos + 2];
                if (third == '!') {
                    rust_lexer_read_doc_comment(lexer, 1);
                    continue;
                } else if (third == '/') {
                    rust_lexer_read_doc_comment(lexer, 0);
                    continue;
                }
            }
            rust_lexer_skip_comment(lexer);
            continue;
        }
        
        if (c == '/' && rust_lexer_peek_next(lexer) == '*') {
            rust_lexer_skip_block_comment(lexer);
            continue;
        }
        
        // Identifiers and keywords
        if (rust_is_ident_start(c)) {
            rust_lexer_read_identifier(lexer);
            continue;
        }
        
        // Numbers
        if (isdigit(c)) {
            rust_lexer_read_number(lexer);
            continue;
        }
        
        // Strings
        if (c == '"') {
            rust_lexer_read_string(lexer, 0);
            continue;
        }
        
        // Byte strings
        if (c == 'b' && rust_lexer_peek_next(lexer) == '"') {
            rust_lexer_read_string(lexer, 1);
            continue;
        }
        
        // Raw strings
        if (c == 'r' && rust_lexer_peek_next(lexer) == '"') {
            rust_lexer_read_raw_string(lexer, 0);
            continue;
        }
        if (c == 'b' && rust_lexer_peek_next(lexer) == 'r') {
            rust_lexer_read_raw_string(lexer, 1);
            continue;
        }
        
        // Character literals
        if (c == '\'') {
            // Check if it's a lifetime or char literal
            if (rust_lexer_peek_next(lexer) != '\0' && 
                !isdigit(rust_lexer_peek_next(lexer)) &&
                rust_lexer_peek_next(lexer) != '\'') {
                rust_lexer_read_lifetime(lexer);
                continue;
            }
        }
        
        // Byte character literals
        if (c == 'b' && rust_lexer_peek_next(lexer) == '\'') {
            rust_lexer_read_string(lexer, 1);
            continue;
        }
        
        // Operators and delimiters
        switch (c) {
            case '(': rust_lexer_add_token(lexer, TOK_LPAREN, "(", start_line, start_col); rust_lexer_advance(lexer); break;
            case ')': rust_lexer_add_token(lexer, TOK_RPAREN, ")", start_line, start_col); rust_lexer_advance(lexer); break;
            case '{': rust_lexer_add_token(lexer, TOK_LBRACE, "{", start_line, start_col); rust_lexer_advance(lexer); break;
            case '}': rust_lexer_add_token(lexer, TOK_RBRACE, "}", start_line, start_col); rust_lexer_advance(lexer); break;
            case '[': rust_lexer_add_token(lexer, TOK_LBRACKET, "[", start_line, start_col); rust_lexer_advance(lexer); break;
            case ']': rust_lexer_add_token(lexer, TOK_RBRACKET, "]", start_line, start_col); rust_lexer_advance(lexer); break;
            case ';': rust_lexer_add_token(lexer, TOK_SEMICOLON, ";", start_line, start_col); rust_lexer_advance(lexer); break;
            case ',': rust_lexer_add_token(lexer, TOK_COMMA, ",", start_line, start_col); rust_lexer_advance(lexer); break;
            case '#': rust_lexer_add_token(lexer, TOK_POUND, "#", start_line, start_col); rust_lexer_advance(lexer); break;
            case '$': rust_lexer_add_token(lexer, TOK_DOLLAR, "$", start_line, start_col); rust_lexer_advance(lexer); break;
            case '?': rust_lexer_add_token(lexer, TOK_QUESTION, "?", start_line, start_col); rust_lexer_advance(lexer); break;
            case '@': rust_lexer_add_token(lexer, TOK_AT, "@", start_line, start_col); rust_lexer_advance(lexer); break;
            case '\\': rust_lexer_add_token(lexer, TOK_BACKSLASH, "\\", start_line, start_col); rust_lexer_advance(lexer); break;
            
            case '+':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_PLUS_ASSIGN, "+=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_PLUS, "+", start_line, start_col);
                }
                break;
                
            case '-':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_MINUS_ASSIGN, "-=", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '>') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_THIN_ARROW, "->", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_MINUS, "-", start_line, start_col);
                }
                break;
                
            case '*':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_STAR_ASSIGN, "*=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_STAR, "*", start_line, start_col);
                }
                break;
                
            case '/':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_SLASH_ASSIGN, "/=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_SLASH, "/", start_line, start_col);
                }
                break;
                
            case '%':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_PERCENT_ASSIGN, "%=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_PERCENT, "%", start_line, start_col);
                }
                break;
                
            case '=':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_EQ, "==", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '>') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_FAT_ARROW, "=>", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_ASSIGN, "=", start_line, start_col);
                }
                break;
                
            case '!':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_NE, "!=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_NOT, "!", start_line, start_col);
                }
                break;
                
            case '<':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_LE, "<=", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '<') {
                    rust_lexer_advance(lexer);
                    if (rust_lexer_peek(lexer) == '=') {
                        rust_lexer_advance(lexer);
                        rust_lexer_add_token(lexer, TOK_SHL_ASSIGN, "<<=", start_line, start_col);
                    } else {
                        rust_lexer_add_token(lexer, TOK_SHL, "<<", start_line, start_col);
                    }
                } else {
                    rust_lexer_add_token(lexer, TOK_LT, "<", start_line, start_col);
                }
                break;
                
            case '>':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_GE, ">=", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '>') {
                    rust_lexer_advance(lexer);
                    if (rust_lexer_peek(lexer) == '=') {
                        rust_lexer_advance(lexer);
                        rust_lexer_add_token(lexer, TOK_SHR_ASSIGN, ">>=", start_line, start_col);
                    } else {
                        rust_lexer_add_token(lexer, TOK_SHR, ">>", start_line, start_col);
                    }
                } else {
                    rust_lexer_add_token(lexer, TOK_GT, ">", start_line, start_col);
                }
                break;
                
            case '&':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '&') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_LOGICAL_AND, "&&", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_AND_ASSIGN, "&=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_AND, "&", start_line, start_col);
                }
                break;
                
            case '|':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '|') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_LOGICAL_OR, "||", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_OR_ASSIGN, "|=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_OR, "|", start_line, start_col);
                }
                break;
                
            case '^':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_XOR_ASSIGN, "^=", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_XOR, "^", start_line, start_col);
                }
                break;
                
            case '.':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == '.' && rust_lexer_peek_next(lexer) == '.') {
                    rust_lexer_advance(lexer);
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_ELLIPSIS, "...", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '.' && rust_lexer_peek_next(lexer) == '=') {
                    rust_lexer_advance(lexer);
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_RANGE_INCLUSIVE, "..=", start_line, start_col);
                } else if (rust_lexer_peek(lexer) == '.') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_RANGE, "..", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_DOT, ".", start_line, start_col);
                }
                break;
                
            case ':':
                rust_lexer_advance(lexer);
                if (rust_lexer_peek(lexer) == ':') {
                    rust_lexer_advance(lexer);
                    rust_lexer_add_token(lexer, TOK_DOUBLE_COLON, "::", start_line, start_col);
                } else {
                    rust_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col);
                }
                break;
                
            default:
                rust_lexer_add_error(lexer, "Unexpected character '%c' at line %d, column %d", c, start_line, start_col);
                rust_lexer_advance(lexer);
                break;
        }
    }
    
    rust_lexer_add_token(lexer, TOK_EOF, "EOF", lexer->line, lexer->column);
    return lexer->error_count == 0 ? 0 : -1;
}

const char* rust_token_type_to_string(RustTokenType type) {
    switch (type) {
        // Strict keywords
        case TOK_AS: return "AS";
        case TOK_ASYNC: return "ASYNC";
        case TOK_AWAIT: return "AWAIT";
        case TOK_BREAK: return "BREAK";
        case TOK_CONST: return "CONST";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_CRATE: return "CRATE";
        case TOK_DYN: return "DYN";
        case TOK_ELSE: return "ELSE";
        case TOK_ENUM: return "ENUM";
        case TOK_EXTERN: return "EXTERN";
        case TOK_FALSE: return "FALSE";
        case TOK_FN: return "FN";
        case TOK_FOR: return "FOR";
        case TOK_IF: return "IF";
        case TOK_IMPL: return "IMPL";
        case TOK_IN: return "IN";
        case TOK_LET: return "LET";
        case TOK_LOOP: return "LOOP";
        case TOK_MATCH: return "MATCH";
        case TOK_MOD: return "MOD";
        case TOK_MOVE: return "MOVE";
        case TOK_MUT: return "MUT";
        case TOK_PUB: return "PUB";
        case TOK_REF: return "REF";
        case TOK_RETURN: return "RETURN";
        case TOK_SELFVALUE: return "SELF";
        case TOK_SELFTYPE: return "SELF_TYPE";
        case TOK_STATIC: return "STATIC";
        case TOK_STRUCT: return "STRUCT";
        case TOK_SUPER: return "SUPER";
        case TOK_TRAIT: return "TRAIT";
        case TOK_TRUE: return "TRUE";
        case TOK_TYPE: return "TYPE";
        case TOK_UNSAFE: return "UNSAFE";
        case TOK_USE: return "USE";
        case TOK_WHERE: return "WHERE";
        case TOK_WHILE: return "WHILE";
        
        // Reserved keywords
        case TOK_ABSTRACT: return "ABSTRACT";
        case TOK_BECOME: return "BECOME";
        case TOK_BOX: return "BOX";
        case TOK_DO: return "DO";
        case TOK_FINAL: return "FINAL";
        case TOK_MACRO: return "MACRO";
        case TOK_OVERRIDE: return "OVERRIDE";
        case TOK_PRIV: return "PRIV";
        case TOK_TYPEOF: return "TYPEOF";
        case TOK_UNSIZED: return "UNSIZED";
        case TOK_VIRTUAL: return "VIRTUAL";
        case TOK_YIELD: return "YIELD";
        
        // Weak keywords
        case TOK_UNION_KEYWORD: return "UNION_KEYWORD";
        case TOK_STATICLIFETIME: return "STATIC_LIFETIME";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_NOT: return "NOT";
        case TOK_AND: return "AND";
        case TOK_OR: return "OR";
        case TOK_XOR: return "XOR";
        case TOK_SHL: return "SHL";
        case TOK_SHR: return "SHR";
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
        case TOK_RANGE: return "RANGE";
        case TOK_RANGE_INCLUSIVE: return "RANGE_INCLUSIVE";
        case TOK_RANGE_FROM: return "RANGE_FROM";
        case TOK_RANGE_TO: return "RANGE_TO";
        case TOK_ARROW: return "ARROW";
        case TOK_THIN_ARROW: return "THIN_ARROW";
        case TOK_FAT_ARROW: return "FAT_ARROW";
        
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
        case TOK_DOUBLE_COLON: return "DOUBLE_COLON";
        case TOK_DOT: return "DOT";
        case TOK_DOUBLE_DOT: return "DOUBLE_DOT";
        case TOK_DOUBLE_DOT_EQ: return "DOUBLE_DOT_EQ";
        case TOK_POUND: return "POUND";
        case TOK_DOLLAR: return "DOLLAR";
        case TOK_QUESTION: return "QUESTION";
        case TOK_AT: return "AT";
        case TOK_BACKSLASH: return "BACKSLASH";
        case TOK_APOSTROPHE: return "APOSTROPHE";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_BYTE_STRING: return "BYTE_STRING";
        case TOK_RAW_STRING: return "RAW_STRING";
        case TOK_BYTE_RAW_STRING: return "BYTE_RAW_STRING";
        case TOK_CHAR_LITERAL: return "CHAR_LITERAL";
        case TOK_BYTE_LITERAL: return "BYTE_LITERAL";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_WHITESPACE: return "WHITESPACE";
        case TOK_COMMENT: return "COMMENT";
        case TOK_DOC_COMMENT: return "DOC_COMMENT";
        case TOK_INNER_DOC_COMMENT: return "INNER_DOC_COMMENT";
        case TOK_OUTER_DOC_COMMENT: return "OUTER_DOC_COMMENT";
        
        // Macros
        case TOK_MACRO_RULES: return "MACRO_RULES";
        case TOK_MACRO_INVOCATION: return "MACRO_INVOCATION";
        
        default: return "UNKNOWN";
    }
}

void rust_lexer_print_tokens(RustLexer* lexer) {
    printf("\n=== Rust Lexer Output ===\n");
    printf("Total tokens: %zu\n\n", lexer->token_count);
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        RustToken* tok = &lexer->tokens[i];
        printf("[%4zu] %-25s line %3d col %3d  '%s'\n",
               i, rust_token_type_to_string(tok->type), tok->line, tok->column, tok->text);
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
#ifdef RUST_LEXER_TEST

int main(int argc, char* argv[]) {
    const char* test_code = 
        "/// A simple Point struct\n"
        "pub struct Point {\n"
        "    x: f64,\n"
        "    y: f64,\n"
        "}\n"
        "\n"
        "impl Point {\n"
        "    pub fn new(x: f64, y: f64) -> Self {\n"
        "        Point { x, y }\n"
        "    }\n"
        "    \n"
        "    pub fn distance(&self) -> f64 {\n"
        "        (self.x * self.x + self.y * self.y).sqrt()\n"
        "    }\n"
        "}\n"
        "\n"
        "fn main() {\n"
        "    let p = Point::new(3.0, 4.0);\n"
        "    println!(\"Distance: {}\", p.distance());\n"
        "    \n"
        "    // Pattern matching\n"
        "    let numbers = vec![1, 2, 3, 4, 5];\n"
        "    for n in &numbers {\n"
        "        match n {\n"
        "            1 => println!(\"one\"),\n"
        "            2..=4 => println!(\"two to four\"),\n"
        "            _ => println!(\"other\"),\n"
        "        }\n"
        "    }\n"
        "}\n";
    
    printf("Rust Lexer Test\n");
    printf("===============\n\n");
    printf("Input code:\n%s\n", test_code);
    
    RustLexer* lexer = rust_lexer_create(test_code);
    int result = rust_lexer_tokenize(lexer);
    
    rust_lexer_print_tokens(lexer);
    
    printf("\n=== Result ===\n");
    if (result == 0) {
        printf("SUCCESS: Tokenized %zu tokens with %d errors\n", 
               lexer->token_count, lexer->error_count);
    } else {
        printf("FAILED: %d errors occurred\n", lexer->error_count);
    }
    
    rust_lexer_destroy(lexer);
    return result;
}

#endif