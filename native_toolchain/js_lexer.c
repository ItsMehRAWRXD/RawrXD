//=============================================================================
// js_lexer.c - JavaScript Language Lexer
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
// JavaScript Token Types
//=============================================================================
typedef enum {
    // Keywords (ECMAScript 2020+)
    TOK_BREAK, TOK_CASE, TOK_CATCH, TOK_CLASS, TOK_CONST,
    TOK_CONTINUE, TOK_DEBUGGER, TOK_DEFAULT, TOK_DELETE, TOK_DO,
    TOK_ELSE, TOK_EXPORT, TOK_EXTENDS, TOK_FINALLY, TOK_FOR,
    TOK_FUNCTION, TOK_IF, TOK_IMPORT, TOK_IN, TOK_INSTANCEOF,
    TOK_NEW, TOK_RETURN, TOK_SUPER, TOK_SWITCH, TOK_THIS,
    TOK_THROW, TOK_TRY, TOK_TYPEOF, TOK_VAR, TOK_VOID,
    TOK_WHILE, TOK_WITH, TOK_YIELD,
    
    // Strict mode reserved words
    TOK_IMPLEMENTS, TOK_INTERFACE, TOK_LET, TOK_PACKAGE, TOK_PRIVATE,
    TOK_PROTECTED, TOK_PUBLIC, TOK_STATIC,
    
    // Future reserved words
    TOK_ENUM, TOK_AWAIT,
    
    // Literals
    TOK_NULL, TOK_TRUE, TOK_FALSE, TOK_UNDEFINED, TOK_NAN, TOK_INFINITY,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_INC, TOK_DEC, TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN,
    TOK_STAR_ASSIGN, TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN,
    TOK_AND_ASSIGN, TOK_OR_ASSIGN, TOK_XOR_ASSIGN, TOK_SHL_ASSIGN,
    TOK_SHR_ASSIGN, TOK_USHR_ASSIGN, TOK_EXP_ASSIGN,
    TOK_EQ, TOK_NE, TOK_STRICT_EQ, TOK_STRICT_NE,
    TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_SHL, TOK_SHR, TOK_USHR, TOK_EXP,  // **
    TOK_LOGICAL_AND, TOK_LOGICAL_OR, TOK_LOGICAL_NOT,
    TOK_BIT_AND, TOK_BIT_OR, TOK_BIT_XOR, TOK_BIT_NOT,
    TOK_ARROW,  // =>
    TOK_SPREAD, TOK_REST,  // ...
    TOK_NULLISH,  // ??
    TOK_OPTIONAL_CHAIN,  // ?.
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COMMA,
    TOK_COLON, TOK_DOT, TOK_QUESTION,
    TOK_BACKTICK,  // Template literals
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL, TOK_BIGINT_LITERAL,
    TOK_STRING, TOK_TEMPLATE_LITERAL, TOK_REGEX_LITERAL,
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_WHITESPACE, TOK_COMMENT, TOK_DOC_COMMENT,
    TOK_HASHBANG,  // #!
    
    // JSX (if enabled)
    TOK_JSX_OPEN, TOK_JSX_CLOSE, TOK_JSX_SELF_CLOSE
} JSTokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    JSTokenType type;
    char text[MAX_TOKEN_TEXT];
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char string_val[MAX_TOKEN_TEXT];
    } value;
} JSToken;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    JSToken* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[MAX_ERRORS][512];
    int in_template;  // Track template literal nesting
    int template_depth;
} JSLexer;

//=============================================================================
// JavaScript Keywords Table
//=============================================================================
typedef struct {
    const char* word;
    JSTokenType type;
} JSKeyword;

static const JSKeyword js_keywords[] = {
    // Keywords
    {"break", TOK_BREAK}, {"case", TOK_CASE}, {"catch", TOK_CATCH},
    {"class", TOK_CLASS}, {"const", TOK_CONST}, {"continue", TOK_CONTINUE},
    {"debugger", TOK_DEBUGGER}, {"default", TOK_DEFAULT}, {"delete", TOK_DELETE},
    {"do", TOK_DO}, {"else", TOK_ELSE}, {"export", TOK_EXPORT},
    {"extends", TOK_EXTENDS}, {"finally", TOK_FINALLY}, {"for", TOK_FOR},
    {"function", TOK_FUNCTION}, {"if", TOK_IF}, {"import", TOK_IMPORT},
    {"in", TOK_IN}, {"instanceof", TOK_INSTANCEOF}, {"new", TOK_NEW},
    {"return", TOK_RETURN}, {"super", TOK_SUPER}, {"switch", TOK_SWITCH},
    {"this", TOK_THIS}, {"throw", TOK_THROW}, {"try", TOK_TRY},
    {"typeof", TOK_TYPEOF}, {"var", TOK_VAR}, {"void", TOK_VOID},
    {"while", TOK_WHILE}, {"with", TOK_WITH}, {"yield", TOK_YIELD},
    
    // Strict mode reserved
    {"implements", TOK_IMPLEMENTS}, {"interface", TOK_INTERFACE}, {"let", TOK_LET},
    {"package", TOK_PACKAGE}, {"private", TOK_PRIVATE}, {"protected", TOK_PROTECTED},
    {"public", TOK_PUBLIC}, {"static", TOK_STATIC},
    
    // Future reserved
    {"enum", TOK_ENUM}, {"await", TOK_AWAIT},
    
    // Literals
    {"null", TOK_NULL}, {"true", TOK_TRUE}, {"false", TOK_FALSE},
    {"undefined", TOK_UNDEFINED}, {"NaN", TOK_NAN}, {"Infinity", TOK_INFINITY},
    
    {NULL, TOK_EOF}
};

//=============================================================================
// Utility Functions
//=============================================================================
static int js_is_ident_start(int c) {
    return isalpha(c) || c == '_' || c == '$';
}

static int js_is_ident_continue(int c) {
    return isalnum(c) || c == '_' || c == '$';
}

static void js_lexer_add_error(JSLexer* lexer, const char* format, ...) {
    if (lexer->error_count >= MAX_ERRORS) return;
    va_list args;
    va_start(args, format);
    vsnprintf(lexer->errors[lexer->error_count], 512, format, args);
    va_end(args);
    lexer->error_count++;
}

static void js_lexer_add_token(JSLexer* lexer, JSTokenType type, const char* text, int line, int col) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = realloc(lexer->tokens, lexer->token_capacity * sizeof(JSToken));
    }
    JSToken* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, MAX_TOKEN_TEXT - 1);
    tok->text[MAX_TOKEN_TEXT - 1] = '\0';
    tok->line = line;
    tok->column = col;
}

static char js_lexer_peek(JSLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char js_lexer_peek_next(JSLexer* lexer) {
    if (lexer->pos + 1 >= lexer->length) return '\0';
    return lexer->source[lexer->pos + 1];
}

static char js_lexer_advance(JSLexer* lexer) {
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

static void js_lexer_skip_whitespace(JSLexer* lexer) {
    while (isspace(js_lexer_peek(lexer)) && js_lexer_peek(lexer) != '\n') {
        js_lexer_advance(lexer);
    }
}

//=============================================================================
// Token Recognition Functions
//=============================================================================

static JSTokenType js_get_keyword_type(const char* word) {
    for (int i = 0; js_keywords[i].word != NULL; i++) {
        if (strcmp(js_keywords[i].word, word) == 0) {
            return js_keywords[i].type;
        }
    }
    return TOK_IDENTIFIER;
}

static void js_lexer_read_identifier(JSLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    while (js_is_ident_continue(js_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = js_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    JSTokenType type = js_get_keyword_type(buffer);
    js_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void js_lexer_read_number(JSLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    int is_float = 0;
    int is_bigint = 0;
    
    // Check for base prefix
    if (js_lexer_peek(lexer) == '0') {
        buffer[i++] = js_lexer_advance(lexer);
        char next = js_lexer_peek(lexer);
        if (next == 'b' || next == 'B') {
            // Binary
            buffer[i++] = js_lexer_advance(lexer);
            while ((js_lexer_peek(lexer) == '0' || js_lexer_peek(lexer) == '1' ||
                    js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = js_lexer_advance(lexer);
            }
        } else if (next == 'o' || next == 'O') {
            // Octal
            buffer[i++] = js_lexer_advance(lexer);
            while (((js_lexer_peek(lexer) >= '0' && js_lexer_peek(lexer) <= '7') ||
                    js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = js_lexer_advance(lexer);
            }
        } else if (next == 'x' || next == 'X') {
            // Hexadecimal
            buffer[i++] = js_lexer_advance(lexer);
            while ((isxdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = js_lexer_advance(lexer);
            }
        } else if (next == '.') {
            // Float starting with 0.
            is_float = 1;
            buffer[i++] = js_lexer_advance(lexer);
            while ((isdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = js_lexer_advance(lexer);
            }
        }
    } else {
        // Decimal
        while ((isdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = js_lexer_advance(lexer);
        }
        
        if (js_lexer_peek(lexer) == '.' && isdigit(js_lexer_peek_next(lexer))) {
            is_float = 1;
            buffer[i++] = js_lexer_advance(lexer);
            while ((isdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = js_lexer_advance(lexer);
            }
        }
    }
    
    // Exponent
    if (js_lexer_peek(lexer) == 'e' || js_lexer_peek(lexer) == 'E') {
        is_float = 1;
        buffer[i++] = js_lexer_advance(lexer);
        if (js_lexer_peek(lexer) == '+' || js_lexer_peek(lexer) == '-') {
            buffer[i++] = js_lexer_advance(lexer);
        }
        while ((isdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = js_lexer_advance(lexer);
        }
    }
    
    // BigInt suffix
    if (js_lexer_peek(lexer) == 'n' && !is_float) {
        is_bigint = 1;
        buffer[i++] = js_lexer_advance(lexer);
    }
    
    buffer[i] = '\0';
    
    JSTokenType type;
    if (is_bigint) {
        type = TOK_BIGINT_LITERAL;
    } else if (is_float) {
        type = TOK_FLOAT_LITERAL;
    } else {
        type = TOK_INTEGER;
    }
    js_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void js_lexer_read_string(JSLexer* lexer, char quote) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    js_lexer_advance(lexer);  // Opening quote
    
    while (js_lexer_peek(lexer) != quote && js_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        if (js_lexer_peek(lexer) == '\\') {
            js_lexer_advance(lexer);
            char escape = js_lexer_advance(lexer);
            switch (escape) {
                case 'n': buffer[i++] = '\n'; break;
                case 't': buffer[i++] = '\t'; break;
                case 'r': buffer[i++] = '\r'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '"': buffer[i++] = '"'; break;
                case '\'': buffer[i++] = '\''; break;
                case 'b': buffer[i++] = '\b'; break;
                case 'f': buffer[i++] = '\f'; break;
                case 'v': buffer[i++] = '\v'; break;
                case '0': buffer[i++] = '\0'; break;
                case 'x': {
                    char hex[3] = {0};
                    if (isxdigit(js_lexer_peek(lexer))) hex[0] = js_lexer_advance(lexer);
                    if (isxdigit(js_lexer_peek(lexer))) hex[1] = js_lexer_advance(lexer);
                    buffer[i++] = (char)strtol(hex, NULL, 16);
                    break;
                }
                case 'u': {
                    // Unicode escape \uXXXX
                    char hex[5] = {0};
                    for (int h = 0; h < 4 && isxdigit(js_lexer_peek(lexer)); h++) {
                        hex[h] = js_lexer_advance(lexer);
                    }
                    buffer[i++] = '?';  // Simplified
                    break;
                }
                case 'U': {
                    // Unicode escape \UXXXXXXXX
                    char hex[9] = {0};
                    for (int h = 0; h < 8 && isxdigit(js_lexer_peek(lexer)); h++) {
                        hex[h] = js_lexer_advance(lexer);
                    }
                    buffer[i++] = '?';
                    break;
                }
                default: buffer[i++] = escape; break;
            }
        } else if (js_lexer_peek(lexer) == '\n') {
            js_lexer_add_error(lexer, "Unterminated string at line %d", start_line);
            break;
        } else {
            buffer[i++] = js_lexer_advance(lexer);
        }
    }
    
    if (js_lexer_peek(lexer) == quote) {
        js_lexer_advance(lexer);
    } else {
        js_lexer_add_error(lexer, "Unterminated string at line %d", start_line);
    }
    
    buffer[i] = '\0';
    js_lexer_add_token(lexer, TOK_STRING, buffer, start_line, start_col);
}

static void js_lexer_read_template_literal(JSLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    js_lexer_advance(lexer);  // Backtick
    
    while (js_lexer_peek(lexer) != '`' && js_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        if (js_lexer_peek(lexer) == '$' && js_lexer_peek_next(lexer) == '{') {
            // End of template part, start of expression
            buffer[i] = '\0';
            js_lexer_add_token(lexer, TOK_TEMPLATE_LITERAL, buffer, start_line, start_col);
            js_lexer_advance(lexer);  // $
            js_lexer_advance(lexer);  // {
            js_lexer_add_token(lexer, TOK_LBRACE, "{", lexer->line, lexer->column - 1);
            lexer->in_template = 1;
            lexer->template_depth++;
            return;
        }
        
        if (js_lexer_peek(lexer) == '\\') {
            js_lexer_advance(lexer);
            char escape = js_lexer_advance(lexer);
            switch (escape) {
                case 'n': buffer[i++] = '\n'; break;
                case 't': buffer[i++] = '\t'; break;
                case 'r': buffer[i++] = '\r'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '`': buffer[i++] = '`'; break;
                case '$': buffer[i++] = '$'; break;
                default: buffer[i++] = escape; break;
            }
        } else {
            buffer[i++] = js_lexer_advance(lexer);
        }
    }
    
    if (js_lexer_peek(lexer) == '`') {
        js_lexer_advance(lexer);
        buffer[i] = '\0';
        js_lexer_add_token(lexer, TOK_TEMPLATE_LITERAL, buffer, start_line, start_col);
        lexer->in_template = 0;
        lexer->template_depth = 0;
    } else {
        js_lexer_add_error(lexer, "Unterminated template literal at line %d", start_line);
    }
}

static void js_lexer_read_regex(JSLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    js_lexer_advance(lexer);  // /
    
    while (js_lexer_peek(lexer) != '/' && js_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        if (js_lexer_peek(lexer) == '\\') {
            buffer[i++] = js_lexer_advance(lexer);
            buffer[i++] = js_lexer_advance(lexer);
        } else if (js_lexer_peek(lexer) == '[') {
            buffer[i++] = js_lexer_advance(lexer);
            while (js_lexer_peek(lexer) != ']' && js_lexer_peek(lexer) != '\0') {
                if (js_lexer_peek(lexer) == '\\') {
                    buffer[i++] = js_lexer_advance(lexer);
                }
                buffer[i++] = js_lexer_advance(lexer);
            }
        } else if (js_lexer_peek(lexer) == '\n') {
            js_lexer_add_error(lexer, "Unterminated regex at line %d", start_line);
            return;
        } else {
            buffer[i++] = js_lexer_advance(lexer);
        }
    }
    
    if (js_lexer_peek(lexer) == '/') {
        js_lexer_advance(lexer);
        // Read flags
        while ((js_lexer_peek(lexer) == 'g' || js_lexer_peek(lexer) == 'i' || 
                js_lexer_peek(lexer) == 'm' || js_lexer_peek(lexer) == 's' ||
                js_lexer_peek(lexer) == 'u' || js_lexer_peek(lexer) == 'y') && i < MAX_STRING_LENGTH - 1) {
            buffer[i++] = js_lexer_advance(lexer);
        }
    } else {
        js_lexer_add_error(lexer, "Unterminated regex at line %d", start_line);
    }
    
    buffer[i] = '\0';
    js_lexer_add_token(lexer, TOK_REGEX_LITERAL, buffer, start_line, start_col);
}

static void js_lexer_skip_line_comment(JSLexer* lexer) {
    js_lexer_advance(lexer);  // /
    js_lexer_advance(lexer);  // /
    
    while (js_lexer_peek(lexer) != '\n' && js_lexer_peek(lexer) != '\0') {
        js_lexer_advance(lexer);
    }
}

static void js_lexer_skip_block_comment(JSLexer* lexer) {
    int start_line = lexer->line;
    js_lexer_advance(lexer);  // /
    js_lexer_advance(lexer);  // *
    
    while (!(js_lexer_peek(lexer) == '*' && js_lexer_peek_next(lexer) == '/') &&
           js_lexer_peek(lexer) != '\0') {
        js_lexer_advance(lexer);
    }
    
    if (js_lexer_peek(lexer) == '*') {
        js_lexer_advance(lexer);
        js_lexer_advance(lexer);
    } else {
        js_lexer_add_error(lexer, "Unterminated block comment starting at line %d", start_line);
    }
}

static void js_lexer_read_hashbang(JSLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    buffer[i++] = js_lexer_advance(lexer);  // #
    buffer[i++] = js_lexer_advance(lexer);  // !
    
    while (js_lexer_peek(lexer) != '\n' && js_lexer_peek(lexer) != '\0' && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = js_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    js_lexer_add_token(lexer, TOK_HASHBANG, buffer, start_line, start_col);
}

//=============================================================================
// Main Lexer Functions
//=============================================================================

JSLexer* js_lexer_create(const char* source) {
    JSLexer* lexer = malloc(sizeof(JSLexer));
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = malloc(lexer->token_capacity * sizeof(JSToken));
    lexer->token_count = 0;
    lexer->error_count = 0;
    lexer->in_template = 0;
    lexer->template_depth = 0;
    return lexer;
}

void js_lexer_destroy(JSLexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

int js_lexer_tokenize(JSLexer* lexer) {
    while (lexer->pos < lexer->length) {
        int start_line = lexer->line;
        int start_col = lexer->column;
        char c = js_lexer_peek(lexer);
        
        // Skip whitespace
        if (isspace(c)) {
            js_lexer_advance(lexer);
            continue;
        }
        
        // Hashbang (shebang) at start
        if (c == '#' && lexer->pos == 0 && js_lexer_peek_next(lexer) == '!') {
            js_lexer_read_hashbang(lexer);
            continue;
        }
        
        // Comments
        if (c == '/' && js_lexer_peek_next(lexer) == '/') {
            js_lexer_skip_line_comment(lexer);
            continue;
        }
        
        if (c == '/' && js_lexer_peek_next(lexer) == '*') {
            js_lexer_skip_block_comment(lexer);
            continue;
        }
        
        // Identifiers and keywords
        if (js_is_ident_start(c)) {
            js_lexer_read_identifier(lexer);
            continue;
        }
        
        // Numbers
        if (isdigit(c)) {
            js_lexer_read_number(lexer);
            continue;
        }
        
        // Strings
        if (c == '"' || c == '\'') {
            js_lexer_read_string(lexer, c);
            continue;
        }
        
        // Template literals
        if (c == '`') {
            js_lexer_read_template_literal(lexer);
            continue;
        }
        
        // Regex literals (context-sensitive, simplified)
        // In a real implementation, this would check if we're in a position
        // where a regex literal is valid
        if (c == '/' && !lexer->in_template) {
            // Check if this could be a regex
            // Simplified: assume it's a regex if previous token suggests it
            js_lexer_read_regex(lexer);
            continue;
        }
        
        // Operators and delimiters
        switch (c) {
            case '(': js_lexer_add_token(lexer, TOK_LPAREN, "(", start_line, start_col); js_lexer_advance(lexer); break;
            case ')': 
                js_lexer_add_token(lexer, TOK_RPAREN, ")", start_line, start_col); 
                js_lexer_advance(lexer);
                if (lexer->in_template && lexer->template_depth > 0) {
                    // Continue template literal after expression
                    lexer->template_depth--;
                    if (lexer->template_depth == 0) {
                        js_lexer_read_template_literal(lexer);
                    }
                }
                break;
            case '{': js_lexer_add_token(lexer, TOK_LBRACE, "{", start_line, start_col); js_lexer_advance(lexer); break;
            case '}': js_lexer_add_token(lexer, TOK_RBRACE, "}", start_line, start_col); js_lexer_advance(lexer); break;
            case '[': js_lexer_add_token(lexer, TOK_LBRACKET, "[", start_line, start_col); js_lexer_advance(lexer); break;
            case ']': js_lexer_add_token(lexer, TOK_RBRACKET, "]", start_line, start_col); js_lexer_advance(lexer); break;
            case ';': js_lexer_add_token(lexer, TOK_SEMICOLON, ";", start_line, start_col); js_lexer_advance(lexer); break;
            case ',': js_lexer_add_token(lexer, TOK_COMMA, ",", start_line, start_col); js_lexer_advance(lexer); break;
            case ':': js_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col); js_lexer_advance(lexer); break;
            case '?':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '.') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_OPTIONAL_CHAIN, "?.", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_QUESTION, "?", start_line, start_col);
                }
                break;
                
            case '+':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '+') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_INC, "++", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_PLUS_ASSIGN, "+=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_PLUS, "+", start_line, start_col);
                }
                break;
                
            case '-':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '-') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_DEC, "--", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_MINUS_ASSIGN, "-=", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '>') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_ARROW, "=>", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_MINUS, "-", start_line, start_col);
                }
                break;
                
            case '*':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '*') {
                    js_lexer_advance(lexer);
                    if (js_lexer_peek(lexer) == '=') {
                        js_lexer_advance(lexer);
                        js_lexer_add_token(lexer, TOK_EXP_ASSIGN, "**=", start_line, start_col);
                    } else {
                        js_lexer_add_token(lexer, TOK_EXP, "**", start_line, start_col);
                    }
                } else if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_STAR_ASSIGN, "*=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_STAR, "*", start_line, start_col);
                }
                break;
                
            case '/':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_SLASH_ASSIGN, "/=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_SLASH, "/", start_line, start_col);
                }
                break;
                
            case '%':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_PERCENT_ASSIGN, "%=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_PERCENT, "%", start_line, start_col);
                }
                break;
                
            case '=':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    if (js_lexer_peek(lexer) == '=') {
                        js_lexer_advance(lexer);
                        js_lexer_add_token(lexer, TOK_STRICT_EQ, "===", start_line, start_col);
                    } else {
                        js_lexer_add_token(lexer, TOK_EQ, "==", start_line, start_col);
                    }
                } else if (js_lexer_peek(lexer) == '>') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_ARROW, "=>", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_ASSIGN, "=", start_line, start_col);
                }
                break;
                
            case '!':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    if (js_lexer_peek(lexer) == '=') {
                        js_lexer_advance(lexer);
                        js_lexer_add_token(lexer, TOK_STRICT_NE, "!==", start_line, start_col);
                    } else {
                        js_lexer_add_token(lexer, TOK_NE, "!=", start_line, start_col);
                    }
                } else {
                    js_lexer_add_token(lexer, TOK_LOGICAL_NOT, "!", start_line, start_col);
                }
                break;
                
            case '<':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_LE, "<=", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '<') {
                    js_lexer_advance(lexer);
                    if (js_lexer_peek(lexer) == '=') {
                        js_lexer_advance(lexer);
                        js_lexer_add_token(lexer, TOK_SHL_ASSIGN, "<<=", start_line, start_col);
                    } else {
                        js_lexer_add_token(lexer, TOK_SHL, "<<", start_line, start_col);
                    }
                } else {
                    js_lexer_add_token(lexer, TOK_LT, "<", start_line, start_col);
                }
                break;
                
            case '>':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_GE, ">=", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '>') {
                    js_lexer_advance(lexer);
                    if (js_lexer_peek(lexer) == '>') {
                        js_lexer_advance(lexer);
                        if (js_lexer_peek(lexer) == '=') {
                            js_lexer_advance(lexer);
                            js_lexer_add_token(lexer, TOK_USHR_ASSIGN, ">>>=", start_line, start_col);
                        } else {
                            js_lexer_add_token(lexer, TOK_USHR, ">>>", start_line, start_col);
                        }
                    } else if (js_lexer_peek(lexer) == '=') {
                        js_lexer_advance(lexer);
                        js_lexer_add_token(lexer, TOK_SHR_ASSIGN, ">>=", start_line, start_col);
                    } else {
                        js_lexer_add_token(lexer, TOK_SHR, ">>", start_line, start_col);
                    }
                } else {
                    js_lexer_add_token(lexer, TOK_GT, ">", start_line, start_col);
                }
                break;
                
            case '&':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '&') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_LOGICAL_AND, "&&", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_AND_ASSIGN, "&=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_BIT_AND, "&", start_line, start_col);
                }
                break;
                
            case '|':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '|') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_LOGICAL_OR, "||", start_line, start_col);
                } else if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_OR_ASSIGN, "|=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_BIT_OR, "|", start_line, start_col);
                }
                break;
                
            case '^':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '=') {
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_XOR_ASSIGN, "^=", start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_BIT_XOR, "^", start_line, start_col);
                }
                break;
                
            case '~':
                js_lexer_add_token(lexer, TOK_BIT_NOT, "~", start_line, start_col);
                js_lexer_advance(lexer);
                break;
                
            case '.':
                js_lexer_advance(lexer);
                if (js_lexer_peek(lexer) == '.' && js_lexer_peek_next(lexer) == '.') {
                    js_lexer_advance(lexer);
                    js_lexer_advance(lexer);
                    js_lexer_add_token(lexer, TOK_SPREAD, "...", start_line, start_col);
                } else if (isdigit(js_lexer_peek(lexer))) {
                    // Decimal number starting with .
                    char buffer[MAX_TOKEN_TEXT];
                    int i = 0;
                    buffer[i++] = '.';
                    while ((isdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                        buffer[i++] = js_lexer_advance(lexer);
                    }
                    if (js_lexer_peek(lexer) == 'e' || js_lexer_peek(lexer) == 'E') {
                        buffer[i++] = js_lexer_advance(lexer);
                        if (js_lexer_peek(lexer) == '+' || js_lexer_peek(lexer) == '-') {
                            buffer[i++] = js_lexer_advance(lexer);
                        }
                        while ((isdigit(js_lexer_peek(lexer)) || js_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                            buffer[i++] = js_lexer_advance(lexer);
                        }
                    }
                    buffer[i] = '\0';
                    js_lexer_add_token(lexer, TOK_FLOAT_LITERAL, buffer, start_line, start_col);
                } else {
                    js_lexer_add_token(lexer, TOK_DOT, ".", start_line, start_col);
                }
                break;
                
            default:
                js_lexer_add_error(lexer, "Unexpected character '%c' at line %d, column %d", c, start_line, start_col);
                js_lexer_advance(lexer);
                break;
        }
    }
    
    js_lexer_add_token(lexer, TOK_EOF, "EOF", lexer->line, lexer->column);
    return lexer->error_count == 0 ? 0 : -1;
}

const char* js_token_type_to_string(JSTokenType type) {
    switch (type) {
        // Keywords
        case TOK_BREAK: return "BREAK";
        case TOK_CASE: return "CASE";
        case TOK_CATCH: return "CATCH";
        case TOK_CLASS: return "CLASS";
        case TOK_CONST: return "CONST";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_DEBUGGER: return "DEBUGGER";
        case TOK_DEFAULT: return "DEFAULT";
        case TOK_DELETE: return "DELETE";
        case TOK_DO: return "DO";
        case TOK_ELSE: return "ELSE";
        case TOK_EXPORT: return "EXPORT";
        case TOK_EXTENDS: return "EXTENDS";
        case TOK_FINALLY: return "FINALLY";
        case TOK_FOR: return "FOR";
        case TOK_FUNCTION: return "FUNCTION";
        case TOK_IF: return "IF";
        case TOK_IMPORT: return "IMPORT";
        case TOK_IN: return "IN";
        case TOK_INSTANCEOF: return "INSTANCEOF";
        case TOK_NEW: return "NEW";
        case TOK_RETURN: return "RETURN";
        case TOK_SUPER: return "SUPER";
        case TOK_SWITCH: return "SWITCH";
        case TOK_THIS: return "THIS";
        case TOK_THROW: return "THROW";
        case TOK_TRY: return "TRY";
        case TOK_TYPEOF: return "TYPEOF";
        case TOK_VAR: return "VAR";
        case TOK_VOID: return "VOID";
        case TOK_WHILE: return "WHILE";
        case TOK_WITH: return "WITH";
        case TOK_YIELD: return "YIELD";
        
        // Strict mode reserved
        case TOK_IMPLEMENTS: return "IMPLEMENTS";
        case TOK_INTERFACE: return "INTERFACE";
        case TOK_LET: return "LET";
        case TOK_PACKAGE: return "PACKAGE";
        case TOK_PRIVATE: return "PRIVATE";
        case TOK_PROTECTED: return "PROTECTED";
        case TOK_PUBLIC: return "PUBLIC";
        case TOK_STATIC: return "STATIC";
        
        // Future reserved
        case TOK_ENUM: return "ENUM";
        case TOK_AWAIT: return "AWAIT";
        
        // Literals
        case TOK_NULL: return "NULL";
        case TOK_TRUE: return "TRUE";
        case TOK_FALSE: return "FALSE";
        case TOK_UNDEFINED: return "UNDEFINED";
        case TOK_NAN: return "NAN";
        case TOK_INFINITY: return "INFINITY";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_INC: return "INC";
        case TOK_DEC: return "DEC";
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
        case TOK_USHR_ASSIGN: return "USHR_ASSIGN";
        case TOK_EXP_ASSIGN: return "EXP_ASSIGN";
        case TOK_EQ: return "EQ";
        case TOK_NE: return "NE";
        case TOK_STRICT_EQ: return "STRICT_EQ";
        case TOK_STRICT_NE: return "STRICT_NE";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_SHL: return "SHL";
        case TOK_SHR: return "SHR";
        case TOK_USHR: return "USHR";
        case TOK_EXP: return "EXP";
        case TOK_LOGICAL_AND: return "LOGICAL_AND";
        case TOK_LOGICAL_OR: return "LOGICAL_OR";
        case TOK_LOGICAL_NOT: return "LOGICAL_NOT";
        case TOK_BIT_AND: return "BIT_AND";
        case TOK_BIT_OR: return "BIT_OR";
        case TOK_BIT_XOR: return "BIT_XOR";
        case TOK_BIT_NOT: return "BIT_NOT";
        case TOK_ARROW: return "ARROW";
        case TOK_SPREAD: return "SPREAD";
        case TOK_REST: return "REST";
        case TOK_NULLISH: return "NULLISH";
        case TOK_OPTIONAL_CHAIN: return "OPTIONAL_CHAIN";
        
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
        case TOK_QUESTION: return "QUESTION";
        case TOK_BACKTICK: return "BACKTICK";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_BIGINT_LITERAL: return "BIGINT_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_TEMPLATE_LITERAL: return "TEMPLATE_LITERAL";
        case TOK_REGEX_LITERAL: return "REGEX_LITERAL";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_WHITESPACE: return "WHITESPACE";
        case TOK_COMMENT: return "COMMENT";
        case TOK_DOC_COMMENT: return "DOC_COMMENT";
        case TOK_HASHBANG: return "HASHBANG";
        
        // JSX
        case TOK_JSX_OPEN: return "JSX_OPEN";
        case TOK_JSX_CLOSE: return "JSX_CLOSE";
        case TOK_JSX_SELF_CLOSE: return "JSX_SELF_CLOSE";
        
        default: return "UNKNOWN";
    }
}

void js_lexer_print_tokens(JSLexer* lexer) {
    printf("\n=== JavaScript Lexer Output ===\n");
    printf("Total tokens: %zu\n\n", lexer->token_count);
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        JSToken* tok = &lexer->tokens[i];
        printf("[%4zu] %-25s line %3d col %3d  '%s'\n",
               i, js_token_type_to_string(tok->type), tok->line, tok->column, tok->text);
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
#ifdef JS_LEXER_TEST

int main(int argc, char* argv[]) {
    const char* test_code = 
        "#!/usr/bin/env node\n"
        "\n"
        "// Point class example\n"
        "class Point {\n"
        "    constructor(x, y) {\n"
        "        this.x = x;\n"
        "        this.y = y;\n"
        "    }\n"
        "    \n"
        "    distance() {\n"
        "        return Math.sqrt(this.x ** 2 + this.y ** 2);\n"
        "    }\n"
        "    \n"
        "    static origin() {\n"
        "        return new Point(0, 0);\n"
        "    }\n"
        "}\n"
        "\n"
        "// Arrow functions and destructuring\n"
        "const add = (a, b) => a + b;\n"
        "const { x, y } = new Point(3, 4);\n"
        "\n"
        "// Template literals\n"
        "const msg = `Distance: ${new Point(3, 4).distance()}`;\n"
        "\n"
        "// Async/await\n"
        "async function fetchData() {\n"
        "    try {\n"
        "        const res = await fetch('/api/data');\n"
        "        return await res.json();\n"
        "    } catch (err) {\n"
        "        console.error(err);\n"
        "    }\n"
        "}\n"
        "\n"
        "// Spread operator\n"
        "const arr = [1, 2, ...[3, 4]];\n"
        "\n"
        "// Optional chaining\n"
        "const val = obj?.prop?.value ?? 'default';\n"
        "\n"
        "// BigInt\n"
        "const big = 9007199254740991n;\n"
        "\n"
        "// Regex\n"
        "const regex = /\\d+/gi;\n";
    
    printf("JavaScript Lexer Test\n");
    printf("=====================\n\n");
    printf("Input code:\n%s\n", test_code);
    
    JSLexer* lexer = js_lexer_create(test_code);
    int result = js_lexer_tokenize(lexer);
    
    js_lexer_print_tokens(lexer);
    
    printf("\n=== Result ===\n");
    if (result == 0) {
        printf("SUCCESS: Tokenized %zu tokens with %d errors\n", 
               lexer->token_count, lexer->error_count);
    } else {
        printf("FAILED: %d errors occurred\n", lexer->error_count);
    }
    
    js_lexer_destroy(lexer);
    return result;
}

#endif