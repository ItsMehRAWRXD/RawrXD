//=============================================================================
// go_lexer.c - Go Language Lexer
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
// Go Token Types
//=============================================================================
typedef enum {
    // Keywords
    TOK_BREAK, TOK_CASE, TOK_CHAN, TOK_CONST, TOK_CONTINUE,
    TOK_DEFAULT, TOK_DEFER, TOK_ELSE, TOK_FALLTHROUGH, TOK_FOR,
    TOK_FUNC, TOK_GO, TOK_GOTO, TOK_IF, TOK_IMPORT,
    TOK_INTERFACE, TOK_MAP, TOK_PACKAGE, TOK_RANGE, TOK_RETURN,
    TOK_SELECT, TOK_STRUCT, TOK_SWITCH, TOK_TYPE, TOK_VAR,
    
    // Predeclared identifiers (builtins)
    TOK_BOOL, TOK_BYTE, TOK_COMPLEX64, TOK_COMPLEX128, TOK_ERROR,
    TOK_FLOAT32, TOK_FLOAT64, TOK_INT, TOK_INT8, TOK_INT16,
    TOK_INT32, TOK_INT64, TOK_MAKE, TOK_NEW, TOK_NIL,
    TOK_PANIC, TOK_PRINT, TOK_PRINTLN, TOK_REAL, TOK_IMAG,
    TOK_RECOVER, TOK_RUNE, TOK_STRING_TYPE, TOK_UINT, TOK_UINT8,
    TOK_UINT16, TOK_UINT32, TOK_UINT64, TOK_UINTPTR,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_AND, TOK_OR, TOK_XOR, TOK_SHL, TOK_SHR,
    TOK_AND_NOT,  // &^
    TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN, TOK_STAR_ASSIGN,
    TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN, TOK_AND_ASSIGN, TOK_OR_ASSIGN,
    TOK_XOR_ASSIGN, TOK_SHL_ASSIGN, TOK_SHR_ASSIGN, TOK_AND_NOT_ASSIGN,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_LOGICAL_AND, TOK_LOGICAL_OR, TOK_LOGICAL_NOT,
    TOK_ARROW,  // <-
    TOK_INC, TOK_DEC,
    TOK_COLON_ASSIGN,  // :=
    TOK_ELLIPSIS,  // ...
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COMMA,
    TOK_COLON, TOK_DOT, TOK_BACKSLASH,
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL, 
    TOK_IMAGINARY_LITERAL, TOK_STRING, TOK_RAW_STRING, TOK_RUNE_LITERAL,
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_WHITESPACE, TOK_COMMENT,
    
    // Directives
    TOK_BUILD_TAG, TOK_LINE_DIRECTIVE
} GoTokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    GoTokenType type;
    char text[MAX_TOKEN_TEXT];
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char string_val[MAX_TOKEN_TEXT];
    } value;
} GoToken;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    GoToken* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[MAX_ERRORS][512];
    int semicolon_inserted;  // Track automatic semicolon insertion
} GoLexer;

//=============================================================================
// Go Keywords Table
//=============================================================================
typedef struct {
    const char* word;
    GoTokenType type;
} GoKeyword;

static const GoKeyword go_keywords[] = {
    {"break", TOK_BREAK}, {"case", TOK_CASE}, {"chan", TOK_CHAN},
    {"const", TOK_CONST}, {"continue", TOK_CONTINUE}, {"default", TOK_DEFAULT},
    {"defer", TOK_DEFER}, {"else", TOK_ELSE}, {"fallthrough", TOK_FALLTHROUGH},
    {"for", TOK_FOR}, {"func", TOK_FUNC}, {"go", TOK_GO},
    {"goto", TOK_GOTO}, {"if", TOK_IF}, {"import", TOK_IMPORT},
    {"interface", TOK_INTERFACE}, {"map", TOK_MAP}, {"package", TOK_PACKAGE},
    {"range", TOK_RANGE}, {"return", TOK_RETURN}, {"select", TOK_SELECT},
    {"struct", TOK_STRUCT}, {"switch", TOK_SWITCH}, {"type", TOK_TYPE},
    {"var", TOK_VAR},
    {NULL, TOK_EOF}
};

static const GoKeyword go_predeclared[] = {
    {"bool", TOK_BOOL}, {"byte", TOK_BYTE}, {"complex64", TOK_COMPLEX64},
    {"complex128", TOK_COMPLEX128}, {"error", TOK_ERROR},
    {"float32", TOK_FLOAT32}, {"float64", TOK_FLOAT64}, {"int", TOK_INT},
    {"int8", TOK_INT8}, {"int16", TOK_INT16}, {"int32", TOK_INT32},
    {"int64", TOK_INT64}, {"make", TOK_MAKE}, {"new", TOK_NEW},
    {"nil", TOK_NIL}, {"panic", TOK_PANIC}, {"print", TOK_PRINT},
    {"println", TOK_PRINTLN}, {"real", TOK_REAL}, {"imag", TOK_IMAG},
    {"recover", TOK_RECOVER}, {"rune", TOK_RUNE}, {"string", TOK_STRING_TYPE},
    {"uint", TOK_UINT}, {"uint8", TOK_UINT8}, {"uint16", TOK_UINT16},
    {"uint32", TOK_UINT32}, {"uint64", TOK_UINT64}, {"uintptr", TOK_UINTPTR},
    {NULL, TOK_EOF}
};

//=============================================================================
// Utility Functions
//=============================================================================
static int go_is_ident_start(int c) {
    return isalpha(c) || c == '_';
}

static int go_is_ident_continue(int c) {
    return isalnum(c) || c == '_';
}

static void go_lexer_add_error(GoLexer* lexer, const char* format, ...) {
    if (lexer->error_count >= MAX_ERRORS) return;
    va_list args;
    va_start(args, format);
    vsnprintf(lexer->errors[lexer->error_count], 512, format, args);
    va_end(args);
    lexer->error_count++;
}

static void go_lexer_add_token(GoLexer* lexer, GoTokenType type, const char* text, int line, int col) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = realloc(lexer->tokens, lexer->token_capacity * sizeof(GoToken));
    }
    GoToken* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, MAX_TOKEN_TEXT - 1);
    tok->text[MAX_TOKEN_TEXT - 1] = '\0';
    tok->line = line;
    tok->column = col;
}

static char go_lexer_peek(GoLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char go_lexer_peek_next(GoLexer* lexer) {
    if (lexer->pos + 1 >= lexer->length) return '\0';
    return lexer->source[lexer->pos + 1];
}

static char go_lexer_advance(GoLexer* lexer) {
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

static void go_lexer_skip_whitespace(GoLexer* lexer) {
    while (isspace(go_lexer_peek(lexer)) && go_lexer_peek(lexer) != '\n') {
        go_lexer_advance(lexer);
    }
}

//=============================================================================
// Token Recognition Functions
//=============================================================================

static GoTokenType go_get_keyword_type(const char* word) {
    for (int i = 0; go_keywords[i].word != NULL; i++) {
        if (strcmp(go_keywords[i].word, word) == 0) {
            return go_keywords[i].type;
        }
    }
    for (int i = 0; go_predeclared[i].word != NULL; i++) {
        if (strcmp(go_predeclared[i].word, word) == 0) {
            return go_predeclared[i].type;
        }
    }
    return TOK_IDENTIFIER;
}

static void go_lexer_read_identifier(GoLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    while (go_is_ident_continue(go_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = go_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    GoTokenType type = go_get_keyword_type(buffer);
    go_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void go_lexer_read_number(GoLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    int is_float = 0;
    int is_imaginary = 0;
    
    // Check for base prefix
    if (go_lexer_peek(lexer) == '0') {
        buffer[i++] = go_lexer_advance(lexer);
        char next = go_lexer_peek(lexer);
        if (next == 'b' || next == 'B') {
            // Binary
            buffer[i++] = go_lexer_advance(lexer);
            while ((go_lexer_peek(lexer) == '0' || go_lexer_peek(lexer) == '1' ||
                    go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = go_lexer_advance(lexer);
            }
        } else if (next == 'o' || next == 'O') {
            // Octal
            buffer[i++] = go_lexer_advance(lexer);
            while (((go_lexer_peek(lexer) >= '0' && go_lexer_peek(lexer) <= '7') ||
                    go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = go_lexer_advance(lexer);
            }
        } else if (next == 'x' || next == 'X') {
            // Hexadecimal
            buffer[i++] = go_lexer_advance(lexer);
            while ((isxdigit(go_lexer_peek(lexer)) || go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = go_lexer_advance(lexer);
            }
        } else if (next == '.') {
            // Float starting with 0.
            is_float = 1;
            buffer[i++] = go_lexer_advance(lexer);
            while ((isdigit(go_lexer_peek(lexer)) || go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = go_lexer_advance(lexer);
            }
        } else {
            // Octal literal (0 followed by octal digits)
            while (((go_lexer_peek(lexer) >= '0' && go_lexer_peek(lexer) <= '7') ||
                    go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = go_lexer_advance(lexer);
            }
        }
    } else {
        // Decimal
        while ((isdigit(go_lexer_peek(lexer)) || go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = go_lexer_advance(lexer);
        }
        
        if (go_lexer_peek(lexer) == '.' && isdigit(go_lexer_peek_next(lexer))) {
            is_float = 1;
            buffer[i++] = go_lexer_advance(lexer);
            while ((isdigit(go_lexer_peek(lexer)) || go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = go_lexer_advance(lexer);
            }
        }
    }
    
    // Exponent
    if (go_lexer_peek(lexer) == 'e' || go_lexer_peek(lexer) == 'E') {
        is_float = 1;
        buffer[i++] = go_lexer_advance(lexer);
        if (go_lexer_peek(lexer) == '+' || go_lexer_peek(lexer) == '-') {
            buffer[i++] = go_lexer_advance(lexer);
        }
        while ((isdigit(go_lexer_peek(lexer)) || go_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = go_lexer_advance(lexer);
        }
    }
    
    // Imaginary suffix
    if (go_lexer_peek(lexer) == 'i') {
        is_imaginary = 1;
        buffer[i++] = go_lexer_advance(lexer);
    }
    
    buffer[i] = '\0';
    
    GoTokenType type;
    if (is_imaginary) {
        type = TOK_IMAGINARY_LITERAL;
    } else if (is_float) {
        type = TOK_FLOAT_LITERAL;
    } else {
        type = TOK_INTEGER;
    }
    go_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void go_lexer_read_string(GoLexer* lexer, int is_raw) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    if (is_raw) {
        // Raw string: `...`
        go_lexer_advance(lexer);  // `
        while (go_lexer_peek(lexer) != '`' && go_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
            buffer[i++] = go_lexer_advance(lexer);
        }
        if (go_lexer_peek(lexer) == '`') {
            go_lexer_advance(lexer);
        } else {
            go_lexer_add_error(lexer, "Unterminated raw string at line %d", start_line);
        }
        buffer[i] = '\0';
        go_lexer_add_token(lexer, TOK_RAW_STRING, buffer, start_line, start_col);
    } else {
        // Interpreted string: "..."
        go_lexer_advance(lexer);  // "
        while (go_lexer_peek(lexer) != '"' && go_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
            if (go_lexer_peek(lexer) == '\\') {
                go_lexer_advance(lexer);
                char escape = go_lexer_advance(lexer);
                switch (escape) {
                    case 'a': buffer[i++] = '\a'; break;
                    case 'b': buffer[i++] = '\b'; break;
                    case 'f': buffer[i++] = '\f'; break;
                    case 'n': buffer[i++] = '\n'; break;
                    case 'r': buffer[i++] = '\r'; break;
                    case 't': buffer[i++] = '\t'; break;
                    case 'v': buffer[i++] = '\v'; break;
                    case '\\': buffer[i++] = '\\'; break;
                    case '"': buffer[i++] = '"'; break;
                    case '\'': buffer[i++] = '\''; break;
                    case 'x': {
                        char hex[3] = {0};
                        if (isxdigit(go_lexer_peek(lexer))) hex[0] = go_lexer_advance(lexer);
                        if (isxdigit(go_lexer_peek(lexer))) hex[1] = go_lexer_advance(lexer);
                        buffer[i++] = (char)strtol(hex, NULL, 16);
                        break;
                    }
                    case 'u': {
                        // Unicode escape \uXXXX
                        if (go_lexer_peek(lexer) == '{') {
                            go_lexer_advance(lexer);
                            char hex[7] = {0};
                            int h = 0;
                            while (isxdigit(go_lexer_peek(lexer)) && h < 6) {
                                hex[h++] = go_lexer_advance(lexer);
                            }
                            if (go_lexer_peek(lexer) == '}') go_lexer_advance(lexer);
                            buffer[i++] = '?';  // Simplified
                        }
                        break;
                    }
                    case 'U': {
                        // Unicode escape \UXXXXXXXX
                        if (go_lexer_peek(lexer) == '{') {
                            go_lexer_advance(lexer);
                            char hex[9] = {0};
                            int h = 0;
                            while (isxdigit(go_lexer_peek(lexer)) && h < 8) {
                                hex[h++] = go_lexer_advance(lexer);
                            }
                            if (go_lexer_peek(lexer) == '}') go_lexer_advance(lexer);
                            buffer[i++] = '?';
                        }
                        break;
                    }
                    default: buffer[i++] = escape; break;
                }
            } else {
                buffer[i++] = go_lexer_advance(lexer);
            }
        }
        if (go_lexer_peek(lexer) == '"') {
            go_lexer_advance(lexer);
        } else {
            go_lexer_add_error(lexer, "Unterminated string at line %d", start_line);
        }
        buffer[i] = '\0';
        go_lexer_add_token(lexer, TOK_STRING, buffer, start_line, start_col);
    }
}

static void go_lexer_read_rune(GoLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[16];
    int i = 0;
    
    go_lexer_advance(lexer);  // '
    
    if (go_lexer_peek(lexer) == '\\') {
        go_lexer_advance(lexer);
        char escape = go_lexer_advance(lexer);
        switch (escape) {
            case 'a': buffer[i++] = '\a'; break;
            case 'b': buffer[i++] = '\b'; break;
            case 'f': buffer[i++] = '\f'; break;
            case 'n': buffer[i++] = '\n'; break;
            case 'r': buffer[i++] = '\r'; break;
            case 't': buffer[i++] = '\t'; break;
            case 'v': buffer[i++] = '\v'; break;
            case '\\': buffer[i++] = '\\'; break;
            case '\'': buffer[i++] = '\''; break;
            case 'x': {
                char hex[3] = {0};
                if (isxdigit(go_lexer_peek(lexer))) hex[0] = go_lexer_advance(lexer);
                if (isxdigit(go_lexer_peek(lexer))) hex[1] = go_lexer_advance(lexer);
                buffer[i++] = (char)strtol(hex, NULL, 16);
                break;
            }
            case 'u': case 'U': {
                // Unicode
                if (go_lexer_peek(lexer) == '{') {
                    go_lexer_advance(lexer);
                    while (isxdigit(go_lexer_peek(lexer))) go_lexer_advance(lexer);
                    if (go_lexer_peek(lexer) == '}') go_lexer_advance(lexer);
                }
                buffer[i++] = '?';
                break;
            }
            default: buffer[i++] = escape; break;
        }
    } else {
        buffer[i++] = go_lexer_advance(lexer);
    }
    
    if (go_lexer_peek(lexer) == '\'') {
        go_lexer_advance(lexer);
    } else {
        go_lexer_add_error(lexer, "Unterminated rune at line %d", start_line);
    }
    
    buffer[i] = '\0';
    go_lexer_add_token(lexer, TOK_RUNE_LITERAL, buffer, start_line, start_col);
}

static void go_lexer_skip_comment(GoLexer* lexer) {
    go_lexer_advance(lexer);  // /
    go_lexer_advance(lexer);  // /
    
    while (go_lexer_peek(lexer) != '\n' && go_lexer_peek(lexer) != '\0') {
        go_lexer_advance(lexer);
    }
}

static void go_lexer_skip_block_comment(GoLexer* lexer) {
    int start_line = lexer->line;
    go_lexer_advance(lexer);  // /
    go_lexer_advance(lexer);  // *
    
    while (!(go_lexer_peek(lexer) == '*' && go_lexer_peek_next(lexer) == '/') &&
           go_lexer_peek(lexer) != '\0') {
        go_lexer_advance(lexer);
    }
    
    if (go_lexer_peek(lexer) == '*') {
        go_lexer_advance(lexer);
        go_lexer_advance(lexer);
    } else {
        go_lexer_add_error(lexer, "Unterminated block comment starting at line %d", start_line);
    }
}

//=============================================================================
// Main Lexer Functions
//=============================================================================

GoLexer* go_lexer_create(const char* source) {
    GoLexer* lexer = malloc(sizeof(GoLexer));
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = malloc(lexer->token_capacity * sizeof(GoToken));
    lexer->token_count = 0;
    lexer->error_count = 0;
    lexer->semicolon_inserted = 0;
    return lexer;
}

void go_lexer_destroy(GoLexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

int go_lexer_tokenize(GoLexer* lexer) {
    while (lexer->pos < lexer->length) {
        int start_line = lexer->line;
        int start_col = lexer->column;
        char c = go_lexer_peek(lexer);
        
        // Skip whitespace (but not newlines - they trigger semicolon insertion)
        if (isspace(c) && c != '\n') {
            go_lexer_advance(lexer);
            continue;
        }
        
        // Newline - check for semicolon insertion
        if (c == '\n') {
            go_lexer_advance(lexer);
            continue;
        }
        
        // Comments
        if (c == '/' && go_lexer_peek_next(lexer) == '/') {
            go_lexer_skip_comment(lexer);
            continue;
        }
        
        if (c == '/' && go_lexer_peek_next(lexer) == '*') {
            go_lexer_skip_block_comment(lexer);
            continue;
        }
        
        // Identifiers and keywords
        if (go_is_ident_start(c)) {
            go_lexer_read_identifier(lexer);
            continue;
        }
        
        // Numbers
        if (isdigit(c)) {
            go_lexer_read_number(lexer);
            continue;
        }
        
        // Strings
        if (c == '"') {
            go_lexer_read_string(lexer, 0);
            continue;
        }
        
        // Raw strings
        if (c == '`') {
            go_lexer_read_string(lexer, 1);
            continue;
        }
        
        // Rune literals
        if (c == '\'') {
            go_lexer_read_rune(lexer);
            continue;
        }
        
        // Operators and delimiters
        switch (c) {
            case '(': go_lexer_add_token(lexer, TOK_LPAREN, "(", start_line, start_col); go_lexer_advance(lexer); break;
            case ')': go_lexer_add_token(lexer, TOK_RPAREN, ")", start_line, start_col); go_lexer_advance(lexer); break;
            case '{': go_lexer_add_token(lexer, TOK_LBRACE, "{", start_line, start_col); go_lexer_advance(lexer); break;
            case '}': go_lexer_add_token(lexer, TOK_RBRACE, "}", start_line, start_col); go_lexer_advance(lexer); break;
            case '[': go_lexer_add_token(lexer, TOK_LBRACKET, "[", start_line, start_col); go_lexer_advance(lexer); break;
            case ']': go_lexer_add_token(lexer, TOK_RBRACKET, "]", start_line, start_col); go_lexer_advance(lexer); break;
            case ';': go_lexer_add_token(lexer, TOK_SEMICOLON, ";", start_line, start_col); go_lexer_advance(lexer); break;
            case ',': go_lexer_add_token(lexer, TOK_COMMA, ",", start_line, start_col); go_lexer_advance(lexer); break;
            case '.':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '.' && go_lexer_peek_next(lexer) == '.') {
                    go_lexer_advance(lexer);
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_ELLIPSIS, "...", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '.') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_DOUBLE_DOT, "..", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_DOT, ".", start_line, start_col);
                }
                break;
            case ':':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_COLON_ASSIGN, ":=", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col);
                }
                break;
            case '+':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_PLUS_ASSIGN, "+=", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '+') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_INC, "++", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_PLUS, "+", start_line, start_col);
                }
                break;
            case '-':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_MINUS_ASSIGN, "-=", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '-') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_DEC, "--", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '>') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_ARROW, "<-", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_MINUS, "-", start_line, start_col);
                }
                break;
            case '*':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_STAR_ASSIGN, "*=", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_STAR, "*", start_line, start_col);
                }
                break;
            case '/':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_SLASH_ASSIGN, "/=", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_SLASH, "/", start_line, start_col);
                }
                break;
            case '%':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_PERCENT_ASSIGN, "%=", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_PERCENT, "%", start_line, start_col);
                }
                break;
            case '=':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_EQ, "==", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_ASSIGN, "=", start_line, start_col);
                }
                break;
            case '!':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_NE, "!=", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_LOGICAL_NOT, "!", start_line, start_col);
                }
                break;
            case '<':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_LE, "<=", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '<') {
                    go_lexer_advance(lexer);
                    if (go_lexer_peek(lexer) == '=') {
                        go_lexer_advance(lexer);
                        go_lexer_add_token(lexer, TOK_SHL_ASSIGN, "<<=", start_line, start_col);
                    } else if (go_lexer_peek(lexer) == '-') {
                        go_lexer_advance(lexer);
                        go_lexer_add_token(lexer, TOK_ARROW, "<-", start_line, start_col);
                    } else {
                        go_lexer_add_token(lexer, TOK_SHL, "<<", start_line, start_col);
                    }
                } else if (go_lexer_peek(lexer) == '-') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_ARROW, "<-", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_LT, "<", start_line, start_col);
                }
                break;
            case '>':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_GE, ">=", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '>') {
                    go_lexer_advance(lexer);
                    if (go_lexer_peek(lexer) == '=') {
                        go_lexer_advance(lexer);
                        go_lexer_add_token(lexer, TOK_SHR_ASSIGN, ">>=", start_line, start_col);
                    } else {
                        go_lexer_add_token(lexer, TOK_SHR, ">>", start_line, start_col);
                    }
                } else {
                    go_lexer_add_token(lexer, TOK_GT, ">", start_line, start_col);
                }
                break;
            case '&':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_AND_ASSIGN, "&=", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '&') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_LOGICAL_AND, "&&", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '^') {
                    go_lexer_advance(lexer);
                    if (go_lexer_peek(lexer) == '=') {
                        go_lexer_advance(lexer);
                        go_lexer_add_token(lexer, TOK_AND_NOT_ASSIGN, "&^=", start_line, start_col);
                    } else {
                        go_lexer_add_token(lexer, TOK_AND_NOT, "&^", start_line, start_col);
                    }
                } else {
                    go_lexer_add_token(lexer, TOK_AND, "&", start_line, start_col);
                }
                break;
            case '|':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_OR_ASSIGN, "|=", start_line, start_col);
                } else if (go_lexer_peek(lexer) == '|') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_LOGICAL_OR, "||", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_OR, "|", start_line, start_col);
                }
                break;
            case '^':
                go_lexer_advance(lexer);
                if (go_lexer_peek(lexer) == '=') {
                    go_lexer_advance(lexer);
                    go_lexer_add_token(lexer, TOK_XOR_ASSIGN, "^=", start_line, start_col);
                } else {
                    go_lexer_add_token(lexer, TOK_XOR, "^", start_line, start_col);
                }
                break;
            case '\\':
                go_lexer_add_token(lexer, TOK_BACKSLASH, "\\", start_line, start_col);
                go_lexer_advance(lexer);
                break;
            default:
                go_lexer_add_error(lexer, "Unexpected character '%c' at line %d, column %d", c, start_line, start_col);
                go_lexer_advance(lexer);
                break;
        }
    }
    
    go_lexer_add_token(lexer, TOK_EOF, "EOF", lexer->line, lexer->column);
    return lexer->error_count == 0 ? 0 : -1;
}

const char* go_token_type_to_string(GoTokenType type) {
    switch (type) {
        // Keywords
        case TOK_BREAK: return "BREAK";
        case TOK_CASE: return "CASE";
        case TOK_CHAN: return "CHAN";
        case TOK_CONST: return "CONST";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_DEFAULT: return "DEFAULT";
        case TOK_DEFER: return "DEFER";
        case TOK_ELSE: return "ELSE";
        case TOK_FALLTHROUGH: return "FALLTHROUGH";
        case TOK_FOR: return "FOR";
        case TOK_FUNC: return "FUNC";
        case TOK_GO: return "GO";
        case TOK_GOTO: return "GOTO";
        case TOK_IF: return "IF";
        case TOK_IMPORT: return "IMPORT";
        case TOK_INTERFACE: return "INTERFACE";
        case TOK_MAP: return "MAP";
        case TOK_PACKAGE: return "PACKAGE";
        case TOK_RANGE: return "RANGE";
        case TOK_RETURN: return "RETURN";
        case TOK_SELECT: return "SELECT";
        case TOK_STRUCT: return "STRUCT";
        case TOK_SWITCH: return "SWITCH";
        case TOK_TYPE: return "TYPE";
        case TOK_VAR: return "VAR";
        
        // Predeclared
        case TOK_BOOL: return "BOOL";
        case TOK_BYTE: return "BYTE";
        case TOK_COMPLEX64: return "COMPLEX64";
        case TOK_COMPLEX128: return "COMPLEX128";
        case TOK_ERROR: return "ERROR";
        case TOK_FLOAT32: return "FLOAT32";
        case TOK_FLOAT64: return "FLOAT64";
        case TOK_INT: return "INT";
        case TOK_INT8: return "INT8";
        case TOK_INT16: return "INT16";
        case TOK_INT32: return "INT32";
        case TOK_INT64: return "INT64";
        case TOK_MAKE: return "MAKE";
        case TOK_NEW: return "NEW";
        case TOK_NIL: return "NIL";
        case TOK_PANIC: return "PANIC";
        case TOK_PRINT: return "PRINT";
        case TOK_PRINTLN: return "PRINTLN";
        case TOK_REAL: return "REAL";
        case TOK_IMAG: return "IMAG";
        case TOK_RECOVER: return "RECOVER";
        case TOK_RUNE: return "RUNE";
        case TOK_STRING_TYPE: return "STRING_TYPE";
        case TOK_UINT: return "UINT";
        case TOK_UINT8: return "UINT8";
        case TOK_UINT16: return "UINT16";
        case TOK_UINT32: return "UINT32";
        case TOK_UINT64: return "UINT64";
        case TOK_UINTPTR: return "UINTPTR";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_AND: return "AND";
        case TOK_OR: return "OR";
        case TOK_XOR: return "XOR";
        case TOK_SHL: return "SHL";
        case TOK_SHR: return "SHR";
        case TOK_AND_NOT: return "AND_NOT";
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
        case TOK_AND_NOT_ASSIGN: return "AND_NOT_ASSIGN";
        case TOK_EQ: return "EQ";
        case TOK_NE: return "NE";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_LOGICAL_AND: return "LOGICAL_AND";
        case TOK_LOGICAL_OR: return "LOGICAL_OR";
        case TOK_LOGICAL_NOT: return "LOGICAL_NOT";
        case TOK_ARROW: return "ARROW";
        case TOK_INC: return "INC";
        case TOK_DEC: return "DEC";
        case TOK_COLON_ASSIGN: return "COLON_ASSIGN";
        case TOK_ELLIPSIS: return "ELLIPSIS";
        
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
        case TOK_DOT: return "DOT";
        case TOK_DOUBLE_DOT: return "DOUBLE_DOT";
        case TOK_BACKSLASH: return "BACKSLASH";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_IMAGINARY_LITERAL: return "IMAGINARY_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_RAW_STRING: return "RAW_STRING";
        case TOK_RUNE_LITERAL: return "RUNE_LITERAL";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_WHITESPACE: return "WHITESPACE";
        case TOK_COMMENT: return "COMMENT";
        case TOK_BUILD_TAG: return "BUILD_TAG";
        case TOK_LINE_DIRECTIVE: return "LINE_DIRECTIVE";
        
        default: return "UNKNOWN";
    }
}

void go_lexer_print_tokens(GoLexer* lexer) {
    printf("\n=== Go Lexer Output ===\n");
    printf("Total tokens: %zu\n\n", lexer->token_count);
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        GoToken* tok = &lexer->tokens[i];
        printf("[%4zu] %-25s line %3d col %3d  '%s'\n",
               i, go_token_type_to_string(tok->type), tok->line, tok->column, tok->text);
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
#ifdef GO_LEXER_TEST

int main(int argc, char* argv[]) {
    const char* test_code = 
        "package main\n"
        "\n"
        "import (\n"
        "    \"fmt\"\n"
        "    \"math\"\n"
        ")\n"
        "\n"
        "// Point represents a point in 2D space\n"
        "type Point struct {\n"
        "    X, Y float64\n"
        "}\n"
        "\n"
        "func (p Point) Distance() float64 {\n"
        "    return math.Sqrt(p.X*p.X + p.Y*p.Y)\n"
        "}\n"
        "\n"
        "func main() {\n"
        "    p := Point{X: 3.0, Y: 4.0}\n"
        "    fmt.Printf(\"Distance: %f\\n\", p.Distance())\n"
        "    \n"
        "    // Channels\n"
        "    ch := make(chan int)\n"
        "    go func() {\n"
        "        ch <- 42\n"
        "    }()\n"
        "    \n"
        "    select {\n"
        "    case v := <-ch:\n"
        "        fmt.Println(v)\n"
        "    default:\n"
        "        fmt.Println(\"no value\")\n"
        "    }\n"
        "}\n";
    
    printf("Go Lexer Test\n");
    printf("=============\n\n");
    printf("Input code:\n%s\n", test_code);
    
    GoLexer* lexer = go_lexer_create(test_code);
    int result = go_lexer_tokenize(lexer);
    
    go_lexer_print_tokens(lexer);
    
    printf("\n=== Result ===\n");
    if (result == 0) {
        printf("SUCCESS: Tokenized %zu tokens with %d errors\n", 
               lexer->token_count, lexer->error_count);
    } else {
        printf("FAILED: %d errors occurred\n", lexer->error_count);
    }
    
    go_lexer_destroy(lexer);
    return result;
}

#endif