//=============================================================================
// python_lexer.c - Python Language Lexer
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
#define MAX_INDENT_LEVELS 100

//=============================================================================
// Python Token Types
//=============================================================================
typedef enum {
    // Keywords
    TOK_FALSE, TOK_NONE, TOK_TRUE, TOK_AND, TOK_AS, TOK_ASSERT,
    TOK_ASYNC, TOK_AWAIT, TOK_BREAK, TOK_CLASS, TOK_CONTINUE,
    TOK_DEF, TOK_DEL, TOK_ELIF, TOK_ELSE, TOK_EXCEPT,
    TOK_FINALLY, TOK_FOR, TOK_FROM, TOK_GLOBAL, TOK_IF,
    TOK_IMPORT, TOK_IN, TOK_IS, TOK_LAMBDA, TOK_NONLOCAL,
    TOK_NOT, TOK_OR, TOK_PASS, TOK_RAISE, TOK_RETURN,
    TOK_TRY, TOK_WHILE, TOK_WITH, TOK_YIELD,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_DOUBLE_SLASH,
    TOK_PERCENT, TOK_AT, TOK_LSHIFT, TOK_RSHIFT, TOK_AMPERSAND,
    TOK_PIPE, TOK_CARET, TOK_TILDE, TOK_LT, TOK_GT,
    TOK_LE, TOK_GE, TOK_EQ, TOK_NE, TOK_COLON_ASSIGN,  // :=
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACKET, TOK_RBRACKET,
    TOK_LBRACE, TOK_RBRACE, TOK_COMMA, TOK_COLON, TOK_DOT,
    TOK_SEMICOLON, TOK_ARROW,  // ->
    TOK_ELLIPSIS,  // ...
    TOK_BACKSLASH,
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL,
    TOK_STRING, TOK_BYTES, TOK_FORMATTED_STRING, TOK_RAW_STRING,
    TOK_TRIPLE_STRING, TOK_TRIPLE_RAW_STRING,
    
    // Indentation
    TOK_INDENT, TOK_DEDENT, TOK_NEWLINE,
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_COMMENT, TOK_DOCSTRING,
    
    // Decorators
    TOK_DECORATOR  // @identifier
} PythonTokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    PythonTokenType type;
    char text[MAX_TOKEN_TEXT];
    int line;
    int column;
    int indent_level;
    union {
        int64_t int_val;
        double float_val;
        char string_val[MAX_TOKEN_TEXT];
    } value;
} PythonToken;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    PythonToken* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[MAX_ERRORS][512];
    
    // Indentation tracking
    int indent_stack[MAX_INDENT_LEVELS];
    int indent_level;
    int at_line_start;
    int paren_depth;  // Track parentheses for implicit line continuation
    int bracket_depth;
    int brace_depth;
} PythonLexer;

//=============================================================================
// Python Keywords Table
//=============================================================================
typedef struct {
    const char* word;
    PythonTokenType type;
} PythonKeyword;

static const PythonKeyword python_keywords[] = {
    {"False", TOK_FALSE}, {"None", TOK_NONE}, {"True", TOK_TRUE},
    {"and", TOK_AND}, {"as", TOK_AS}, {"assert", TOK_ASSERT},
    {"async", TOK_ASYNC}, {"await", TOK_AWAIT}, {"break", TOK_BREAK},
    {"class", TOK_CLASS}, {"continue", TOK_CONTINUE}, {"def", TOK_DEF},
    {"del", TOK_DEL}, {"elif", TOK_ELIF}, {"else", TOK_ELSE},
    {"except", TOK_EXCEPT}, {"finally", TOK_FINALLY}, {"for", TOK_FOR},
    {"from", TOK_FROM}, {"global", TOK_GLOBAL}, {"if", TOK_IF},
    {"import", TOK_IMPORT}, {"in", TOK_IN}, {"is", TOK_IS},
    {"lambda", TOK_LAMBDA}, {"nonlocal", TOK_NONLOCAL}, {"not", TOK_NOT},
    {"or", TOK_OR}, {"pass", TOK_PASS}, {"raise", TOK_RAISE},
    {"return", TOK_RETURN}, {"try", TOK_TRY}, {"while", TOK_WHILE},
    {"with", TOK_WITH}, {"yield", TOK_YIELD},
    {NULL, TOK_EOF}
};

//=============================================================================
// Utility Functions
//=============================================================================
static int py_is_ident_start(int c) {
    return isalpha(c) || c == '_';
}

static int py_is_ident_continue(int c) {
    return isalnum(c) || c == '_';
}

static void py_lexer_add_error(PythonLexer* lexer, const char* format, ...) {
    if (lexer->error_count >= MAX_ERRORS) return;
    va_list args;
    va_start(args, format);
    vsnprintf(lexer->errors[lexer->error_count], 512, format, args);
    va_end(args);
    lexer->error_count++;
}

static void py_lexer_add_token(PythonLexer* lexer, PythonTokenType type, const char* text, int line, int col) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = realloc(lexer->tokens, lexer->token_capacity * sizeof(PythonToken));
    }
    PythonToken* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, MAX_TOKEN_TEXT - 1);
    tok->text[MAX_TOKEN_TEXT - 1] = '\0';
    tok->line = line;
    tok->column = col;
    tok->indent_level = lexer->indent_level;
}

static char py_lexer_peek(PythonLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char py_lexer_peek_next(PythonLexer* lexer) {
    if (lexer->pos + 1 >= lexer->length) return '\0';
    return lexer->source[lexer->pos + 1];
}

static char py_lexer_advance(PythonLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    char c = lexer->source[lexer->pos++];
    if (c == '\n') {
        lexer->line++;
        lexer->column = 1;
        lexer->at_line_start = 1;
    } else {
        lexer->column++;
    }
    return c;
}

static void py_lexer_skip_spaces(PythonLexer* lexer) {
    while (py_lexer_peek(lexer) == ' ' || py_lexer_peek(lexer) == '\t') {
        py_lexer_advance(lexer);
    }
}

//=============================================================================
// Indentation Handling
//=============================================================================

static void py_lexer_handle_indentation(PythonLexer* lexer) {
    if (!lexer->at_line_start) return;
    
    // Skip blank lines and comments
    size_t save_pos = lexer->pos;
    int save_line = lexer->line;
    int save_col = lexer->column;
    
    py_lexer_skip_spaces(lexer);
    
    if (py_lexer_peek(lexer) == '\n' || py_lexer_peek(lexer) == '#' || py_lexer_peek(lexer) == '\0') {
        // Blank line or comment - restore position
        lexer->pos = save_pos;
        lexer->line = save_line;
        lexer->column = save_col;
        lexer->at_line_start = 0;
        return;
    }
    
    // Calculate indent level
    int indent = lexer->column - 1;
    
    if (indent > lexer->indent_stack[lexer->indent_level]) {
        // Indent
        if (lexer->indent_level >= MAX_INDENT_LEVELS - 1) {
            py_lexer_add_error(lexer, "Maximum indentation level exceeded at line %d", lexer->line);
            return;
        }
        lexer->indent_level++;
        lexer->indent_stack[lexer->indent_level] = indent;
        py_lexer_add_token(lexer, TOK_INDENT, "INDENT", lexer->line, 1);
    } else if (indent < lexer->indent_stack[lexer->indent_level]) {
        // Dedent
        while (lexer->indent_level > 0 && indent < lexer->indent_stack[lexer->indent_level]) {
            lexer->indent_level--;
            py_lexer_add_token(lexer, TOK_DEDENT, "DEDENT", lexer->line, 1);
        }
        if (indent != lexer->indent_stack[lexer->indent_level]) {
            py_lexer_add_error(lexer, "Inconsistent dedent at line %d", lexer->line);
        }
    }
    
    lexer->at_line_start = 0;
}

//=============================================================================
// Token Recognition Functions
//=============================================================================

static PythonTokenType py_get_keyword_type(const char* word) {
    for (int i = 0; python_keywords[i].word != NULL; i++) {
        if (strcmp(python_keywords[i].word, word) == 0) {
            return python_keywords[i].type;
        }
    }
    return TOK_IDENTIFIER;
}

static void py_lexer_read_identifier(PythonLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    while (py_is_ident_continue(py_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = py_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    PythonTokenType type = py_get_keyword_type(buffer);
    py_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void py_lexer_read_number(PythonLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    int is_float = 0;
    int is_complex = 0;
    
    // Check for base prefix
    if (py_lexer_peek(lexer) == '0') {
        buffer[i++] = py_lexer_advance(lexer);
        char next = py_lexer_peek(lexer);
        if (next == 'b' || next == 'B') {
            // Binary
            buffer[i++] = py_lexer_advance(lexer);
            while ((py_lexer_peek(lexer) == '0' || py_lexer_peek(lexer) == '1' ||
                    py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = py_lexer_advance(lexer);
            }
        } else if (next == 'o' || next == 'O') {
            // Octal
            buffer[i++] = py_lexer_advance(lexer);
            while (((py_lexer_peek(lexer) >= '0' && py_lexer_peek(lexer) <= '7') ||
                    py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = py_lexer_advance(lexer);
            }
        } else if (next == 'x' || next == 'X') {
            // Hexadecimal
            buffer[i++] = py_lexer_advance(lexer);
            while ((isxdigit(py_lexer_peek(lexer)) || py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = py_lexer_advance(lexer);
            }
        } else if (next == '.') {
            // Float starting with 0.
            is_float = 1;
            buffer[i++] = py_lexer_advance(lexer);
            while ((isdigit(py_lexer_peek(lexer)) || py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = py_lexer_advance(lexer);
            }
        } else {
            // Just 0 or octal
            while (((py_lexer_peek(lexer) >= '0' && py_lexer_peek(lexer) <= '7') ||
                    py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = py_lexer_advance(lexer);
            }
        }
    } else {
        // Decimal
        while ((isdigit(py_lexer_peek(lexer)) || py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = py_lexer_advance(lexer);
        }
        
        if (py_lexer_peek(lexer) == '.' && isdigit(py_lexer_peek_next(lexer))) {
            is_float = 1;
            buffer[i++] = py_lexer_advance(lexer);
            while ((isdigit(py_lexer_peek(lexer)) || py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = py_lexer_advance(lexer);
            }
        }
    }
    
    // Exponent
    if (py_lexer_peek(lexer) == 'e' || py_lexer_peek(lexer) == 'E') {
        is_float = 1;
        buffer[i++] = py_lexer_advance(lexer);
        if (py_lexer_peek(lexer) == '+' || py_lexer_peek(lexer) == '-') {
            buffer[i++] = py_lexer_advance(lexer);
        }
        while ((isdigit(py_lexer_peek(lexer)) || py_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = py_lexer_advance(lexer);
        }
    }
    
    // Imaginary suffix
    if (py_lexer_peek(lexer) == 'j' || py_lexer_peek(lexer) == 'J') {
        is_complex = 1;
        buffer[i++] = py_lexer_advance(lexer);
    }
    
    buffer[i] = '\0';
    py_lexer_add_token(lexer, is_float ? TOK_FLOAT_LITERAL : TOK_INTEGER, buffer, start_line, start_col);
}

static void py_lexer_read_string(PythonLexer* lexer, int is_bytes, int is_raw, int is_formatted) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    // Skip prefix
    if (is_bytes) py_lexer_advance(lexer);  // b
    if (is_raw) py_lexer_advance(lexer);    // r
    if (is_formatted) py_lexer_advance(lexer);  // f
    
    char quote = py_lexer_advance(lexer);  // ' or "
    int is_triple = 0;
    
    // Check for triple quotes
    if (py_lexer_peek(lexer) == quote && py_lexer_peek_next(lexer) == quote) {
        is_triple = 1;
        py_lexer_advance(lexer);
        py_lexer_advance(lexer);
    }
    
    while (i < MAX_STRING_LENGTH - 1) {
        if (is_triple) {
            if (py_lexer_peek(lexer) == quote && 
                py_lexer_peek_next(lexer) == quote &&
                lexer->pos + 2 < lexer->length &&
                lexer->source[lexer->pos + 2] == quote) {
                py_lexer_advance(lexer);
                py_lexer_advance(lexer);
                py_lexer_advance(lexer);
                break;
            }
        } else {
            if (py_lexer_peek(lexer) == quote) {
                py_lexer_advance(lexer);
                break;
            }
            if (py_lexer_peek(lexer) == '\n' || py_lexer_peek(lexer) == '\0') {
                py_lexer_add_error(lexer, "Unterminated string at line %d", start_line);
                break;
            }
        }
        
        if (py_lexer_peek(lexer) == '\\' && !is_raw) {
            py_lexer_advance(lexer);
            char escape = py_lexer_advance(lexer);
            switch (escape) {
                case 'n': buffer[i++] = '\n'; break;
                case 't': buffer[i++] = '\t'; break;
                case 'r': buffer[i++] = '\r'; break;
                case '\\': buffer[i++] = '\\'; break;
                case '"': buffer[i++] = '"'; break;
                case '\'': buffer[i++] = '\''; break;
                case 'x': {
                    char hex[3] = {0};
                    if (isxdigit(py_lexer_peek(lexer))) hex[0] = py_lexer_advance(lexer);
                    if (isxdigit(py_lexer_peek(lexer))) hex[1] = py_lexer_advance(lexer);
                    buffer[i++] = (char)strtol(hex, NULL, 16);
                    break;
                }
                case 'u': {
                    char hex[5] = {0};
                    for (int h = 0; h < 4 && isxdigit(py_lexer_peek(lexer)); h++) {
                        hex[h] = py_lexer_advance(lexer);
                    }
                    buffer[i++] = '?';
                    break;
                }
                case 'U': {
                    char hex[9] = {0};
                    for (int h = 0; h < 8 && isxdigit(py_lexer_peek(lexer)); h++) {
                        hex[h] = py_lexer_advance(lexer);
                    }
                    buffer[i++] = '?';
                    break;
                }
                case 'N': {
                    // \N{name} - named character
                    if (py_lexer_peek(lexer) == '{') {
                        py_lexer_advance(lexer);
                        while (py_lexer_peek(lexer) != '}' && py_lexer_peek(lexer) != '\0') {
                            py_lexer_advance(lexer);
                        }
                        if (py_lexer_peek(lexer) == '}') py_lexer_advance(lexer);
                    }
                    buffer[i++] = '?';
                    break;
                }
                default: buffer[i++] = escape; break;
            }
        } else {
            buffer[i++] = py_lexer_advance(lexer);
        }
    }
    
    buffer[i] = '\0';
    
    PythonTokenType type;
    if (is_triple) {
        type = is_raw ? TOK_TRIPLE_RAW_STRING : TOK_TRIPLE_STRING;
    } else if (is_bytes) {
        type = TOK_BYTES;
    } else if (is_formatted) {
        type = TOK_FORMATTED_STRING;
    } else if (is_raw) {
        type = TOK_RAW_STRING;
    } else {
        type = TOK_STRING;
    }
    py_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void py_lexer_skip_comment(PythonLexer* lexer) {
    while (py_lexer_peek(lexer) != '\n' && py_lexer_peek(lexer) != '\0') {
        py_lexer_advance(lexer);
    }
}

//=============================================================================
// Main Lexer Functions
//=============================================================================

PythonLexer* py_lexer_create(const char* source) {
    PythonLexer* lexer = malloc(sizeof(PythonLexer));
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = malloc(lexer->token_capacity * sizeof(PythonToken));
    lexer->token_count = 0;
    lexer->error_count = 0;
    lexer->indent_stack[0] = 0;
    lexer->indent_level = 0;
    lexer->at_line_start = 1;
    lexer->paren_depth = 0;
    lexer->bracket_depth = 0;
    lexer->brace_depth = 0;
    return lexer;
}

void py_lexer_destroy(PythonLexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

int py_lexer_tokenize(PythonLexer* lexer) {
    while (lexer->pos < lexer->length) {
        int start_line = lexer->line;
        int start_col = lexer->column;
        char c = py_lexer_peek(lexer);
        
        // Handle indentation at line start
        if (lexer->at_line_start && lexer->paren_depth == 0 && 
            lexer->bracket_depth == 0 && lexer->brace_depth == 0) {
            py_lexer_handle_indentation(lexer);
        }
        
        // Skip whitespace
        if (c == ' ' || c == '\t') {
            py_lexer_advance(lexer);
            continue;
        }
        
        // Newline
        if (c == '\n') {
            py_lexer_advance(lexer);
            if (lexer->paren_depth == 0 && lexer->bracket_depth == 0 && lexer->brace_depth == 0) {
                py_lexer_add_token(lexer, TOK_NEWLINE, "NEWLINE", start_line, start_col);
                lexer->at_line_start = 1;
            }
            continue;
        }
        
        // Comments
        if (c == '#') {
            py_lexer_skip_comment(lexer);
            continue;
        }
        
        // Identifiers and keywords
        if (py_is_ident_start(c)) {
            py_lexer_read_identifier(lexer);
            continue;
        }
        
        // Numbers
        if (isdigit(c)) {
            py_lexer_read_number(lexer);
            continue;
        }
        
        // Strings
        if (c == '"' || c == '\'') {
            py_lexer_read_string(lexer, 0, 0, 0);
            continue;
        }
        
        // Prefixed strings
        if (c == 'b' && (py_lexer_peek_next(lexer) == '"' || py_lexer_peek_next(lexer) == '\'')) {
            py_lexer_read_string(lexer, 1, 0, 0);
            continue;
        }
        if (c == 'r' && (py_lexer_peek_next(lexer) == '"' || py_lexer_peek_next(lexer) == '\'')) {
            py_lexer_read_string(lexer, 0, 1, 0);
            continue;
        }
        if (c == 'f' && (py_lexer_peek_next(lexer) == '"' || py_lexer_peek_next(lexer) == '\'')) {
            py_lexer_read_string(lexer, 0, 0, 1);
            continue;
        }
        if ((c == 'b' && py_lexer_peek_next(lexer) == 'r') ||
            (c == 'r' && py_lexer_peek_next(lexer) == 'b')) {
            py_lexer_advance(lexer);
            py_lexer_read_string(lexer, 1, 1, 0);
            continue;
        }
        
        // Operators and delimiters
        switch (c) {
            case '(': 
                py_lexer_add_token(lexer, TOK_LPAREN, "(", start_line, start_col); 
                py_lexer_advance(lexer);
                lexer->paren_depth++;
                break;
            case ')': 
                py_lexer_add_token(lexer, TOK_RPAREN, ")", start_line, start_col); 
                py_lexer_advance(lexer);
                lexer->paren_depth--;
                break;
            case '[': 
                py_lexer_add_token(lexer, TOK_LBRACKET, "[", start_line, start_col); 
                py_lexer_advance(lexer);
                lexer->bracket_depth++;
                break;
            case ']': 
                py_lexer_add_token(lexer, TOK_RBRACKET, "]", start_line, start_col); 
                py_lexer_advance(lexer);
                lexer->bracket_depth--;
                break;
            case '{': 
                py_lexer_add_token(lexer, TOK_LBRACE, "{", start_line, start_col); 
                py_lexer_advance(lexer);
                lexer->brace_depth++;
                break;
            case '}': 
                py_lexer_add_token(lexer, TOK_RBRACE, "}", start_line, start_col); 
                py_lexer_advance(lexer);
                lexer->brace_depth--;
                break;
            case ',': py_lexer_add_token(lexer, TOK_COMMA, ",", start_line, start_col); py_lexer_advance(lexer); break;
            case ';': py_lexer_add_token(lexer, TOK_SEMICOLON, ";", start_line, start_col); py_lexer_advance(lexer); break;
            case '\\': py_lexer_add_token(lexer, TOK_BACKSLASH, "\\", start_line, start_col); py_lexer_advance(lexer); break;
            case '@': {
                // Decorator
                py_lexer_advance(lexer);
                if (py_is_ident_start(py_lexer_peek(lexer))) {
                    int dec_line = lexer->line;
                    int dec_col = lexer->column;
                    char buffer[MAX_TOKEN_TEXT];
                    int i = 0;
                    while (py_is_ident_continue(py_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
                        buffer[i++] = py_lexer_advance(lexer);
                    }
                    buffer[i] = '\0';
                    py_lexer_add_token(lexer, TOK_DECORATOR, buffer, dec_line, dec_col);
                } else {
                    py_lexer_add_token(lexer, TOK_AT, "@", start_line, start_col);
                }
                break;
            }
            
            case '+':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_PLUS_ASSIGN, "+=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_PLUS, "+", start_line, start_col);
                }
                break;
                
            case '-':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_MINUS_ASSIGN, "-=", start_line, start_col);
                } else if (py_lexer_peek(lexer) == '>') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_ARROW, "->", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_MINUS, "-", start_line, start_col);
                }
                break;
                
            case '*':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_STAR_ASSIGN, "*=", start_line, start_col);
                } else if (py_lexer_peek(lexer) == '*') {
                    py_lexer_advance(lexer);
                    if (py_lexer_peek(lexer) == '=') {
                        py_lexer_advance(lexer);
                        py_lexer_add_token(lexer, TOK_DOUBLE_SLASH, "**=", start_line, start_col);
                    } else {
                        py_lexer_add_token(lexer, TOK_DOUBLE_SLASH, "**", start_line, start_col);
                    }
                } else {
                    py_lexer_add_token(lexer, TOK_STAR, "*", start_line, start_col);
                }
                break;
                
            case '/':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '/') {
                    py_lexer_advance(lexer);
                    if (py_lexer_peek(lexer) == '=') {
                        py_lexer_advance(lexer);
                        py_lexer_add_token(lexer, TOK_DOUBLE_SLASH, "//=", start_line, start_col);
                    } else {
                        py_lexer_add_token(lexer, TOK_DOUBLE_SLASH, "//", start_line, start_col);
                    }
                } else if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_SLASH_ASSIGN, "/=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_SLASH, "/", start_line, start_col);
                }
                break;
                
            case '%':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_PERCENT_ASSIGN, "%=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_PERCENT, "%", start_line, start_col);
                }
                break;
                
            case '=':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_EQ, "==", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_ASSIGN, "=", start_line, start_col);
                }
                break;
                
            case '!':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_NE, "!=", start_line, start_col);
                } else {
                    py_lexer_add_error(lexer, "Invalid token '!' at line %d", start_line);
                }
                break;
                
            case '<':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_LE, "<=", start_line, start_col);
                } else if (py_lexer_peek(lexer) == '<') {
                    py_lexer_advance(lexer);
                    if (py_lexer_peek(lexer) == '=') {
                        py_lexer_advance(lexer);
                        py_lexer_add_token(lexer, TOK_LSHIFT, "<<=", start_line, start_col);
                    } else {
                        py_lexer_add_token(lexer, TOK_LSHIFT, "<<", start_line, start_col);
                    }
                } else {
                    py_lexer_add_token(lexer, TOK_LT, "<", start_line, start_col);
                }
                break;
                
            case '>':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_GE, ">=", start_line, start_col);
                } else if (py_lexer_peek(lexer) == '>') {
                    py_lexer_advance(lexer);
                    if (py_lexer_peek(lexer) == '=') {
                        py_lexer_advance(lexer);
                        py_lexer_add_token(lexer, TOK_RSHIFT, ">>=", start_line, start_col);
                    } else {
                        py_lexer_add_token(lexer, TOK_RSHIFT, ">>", start_line, start_col);
                    }
                } else {
                    py_lexer_add_token(lexer, TOK_GT, ">", start_line, start_col);
                }
                break;
                
            case '&':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_AMPERSAND, "&=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_AMPERSAND, "&", start_line, start_col);
                }
                break;
                
            case '|':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_PIPE, "|=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_PIPE, "|", start_line, start_col);
                }
                break;
                
            case '^':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_CARET, "^=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_CARET, "^", start_line, start_col);
                }
                break;
                
            case '~':
                py_lexer_add_token(lexer, TOK_TILDE, "~", start_line, start_col);
                py_lexer_advance(lexer);
                break;
                
            case '.':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '.' && py_lexer_peek_next(lexer) == '.') {
                    py_lexer_advance(lexer);
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_ELLIPSIS, "...", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_DOT, ".", start_line, start_col);
                }
                break;
                
            case ':':
                py_lexer_advance(lexer);
                if (py_lexer_peek(lexer) == '=') {
                    py_lexer_advance(lexer);
                    py_lexer_add_token(lexer, TOK_COLON_ASSIGN, ":=", start_line, start_col);
                } else {
                    py_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col);
                }
                break;
                
            default:
                py_lexer_add_error(lexer, "Unexpected character '%c' at line %d, column %d", c, start_line, start_col);
                py_lexer_advance(lexer);
                break;
        }
    }
    
    // Add final dedents
    while (lexer->indent_level > 0) {
        lexer->indent_level--;
        py_lexer_add_token(lexer, TOK_DEDENT, "DEDENT", lexer->line, 1);
    }
    
    py_lexer_add_token(lexer, TOK_EOF, "EOF", lexer->line, lexer->column);
    return lexer->error_count == 0 ? 0 : -1;
}

const char* py_token_type_to_string(PythonTokenType type) {
    switch (type) {
        // Keywords
        case TOK_FALSE: return "FALSE";
        case TOK_NONE: return "NONE";
        case TOK_TRUE: return "TRUE";
        case TOK_AND: return "AND";
        case TOK_AS: return "AS";
        case TOK_ASSERT: return "ASSERT";
        case TOK_ASYNC: return "ASYNC";
        case TOK_AWAIT: return "AWAIT";
        case TOK_BREAK: return "BREAK";
        case TOK_CLASS: return "CLASS";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_DEF: return "DEF";
        case TOK_DEL: return "DEL";
        case TOK_ELIF: return "ELIF";
        case TOK_ELSE: return "ELSE";
        case TOK_EXCEPT: return "EXCEPT";
        case TOK_FINALLY: return "FINALLY";
        case TOK_FOR: return "FOR";
        case TOK_FROM: return "FROM";
        case TOK_GLOBAL: return "GLOBAL";
        case TOK_IF: return "IF";
        case TOK_IMPORT: return "IMPORT";
        case TOK_IN: return "IN";
        case TOK_IS: return "IS";
        case TOK_LAMBDA: return "LAMBDA";
        case TOK_NONLOCAL: return "NONLOCAL";
        case TOK_NOT: return "NOT";
        case TOK_OR: return "OR";
        case TOK_PASS: return "PASS";
        case TOK_RAISE: return "RAISE";
        case TOK_RETURN: return "RETURN";
        case TOK_TRY: return "TRY";
        case TOK_WHILE: return "WHILE";
        case TOK_WITH: return "WITH";
        case TOK_YIELD: return "YIELD";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_DOUBLE_SLASH: return "DOUBLE_SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_AT: return "AT";
        case TOK_LSHIFT: return "LSHIFT";
        case TOK_RSHIFT: return "RSHIFT";
        case TOK_AMPERSAND: return "AMPERSAND";
        case TOK_PIPE: return "PIPE";
        case TOK_CARET: return "CARET";
        case TOK_TILDE: return "TILDE";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_EQ: return "EQ";
        case TOK_NE: return "NE";
        case TOK_COLON_ASSIGN: return "COLON_ASSIGN";
        
        // Delimiters
        case TOK_LPAREN: return "LPAREN";
        case TOK_RPAREN: return "RPAREN";
        case TOK_LBRACKET: return "LBRACKET";
        case TOK_RBRACKET: return "RBRACKET";
        case TOK_LBRACE: return "LBRACE";
        case TOK_RBRACE: return "RBRACE";
        case TOK_COMMA: return "COMMA";
        case TOK_COLON: return "COLON";
        case TOK_DOT: return "DOT";
        case TOK_SEMICOLON: return "SEMICOLON";
        case TOK_ARROW: return "ARROW";
        case TOK_ELLIPSIS: return "ELLIPSIS";
        case TOK_BACKSLASH: return "BACKSLASH";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_BYTES: return "BYTES";
        case TOK_FORMATTED_STRING: return "FORMATTED_STRING";
        case TOK_RAW_STRING: return "RAW_STRING";
        case TOK_TRIPLE_STRING: return "TRIPLE_STRING";
        case TOK_TRIPLE_RAW_STRING: return "TRIPLE_RAW_STRING";
        
        // Indentation
        case TOK_INDENT: return "INDENT";
        case TOK_DEDENT: return "DEDENT";
        case TOK_NEWLINE: return "NEWLINE";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_COMMENT: return "COMMENT";
        case TOK_DOCSTRING: return "DOCSTRING";
        case TOK_DECORATOR: return "DECORATOR";
        
        default: return "UNKNOWN";
    }
}

void py_lexer_print_tokens(PythonLexer* lexer) {
    printf("\n=== Python Lexer Output ===\n");
    printf("Total tokens: %zu\n\n", lexer->token_count);
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        PythonToken* tok = &lexer->tokens[i];
        printf("[%4zu] %-25s line %3d col %3d  '%s'\n",
               i, py_token_type_to_string(tok->type), tok->line, tok->column, tok->text);
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
#ifdef PYTHON_LEXER_TEST

int main(int argc, char* argv[]) {
    const char* test_code = 
        "\"\"\"\n"
        "A simple Point class example.\n"
        "\"\"\"\n"
        "\n"
        "class Point:\n"
        "    def __init__(self, x, y):\n"
        "        self.x = x\n"
        "        self.y = y\n"
        "    \n"
        "    def distance(self):\n"
        "        import math\n"
        "        return math.sqrt(self.x ** 2 + self.y ** 2)\n"
        "\n"
        "def main():\n"
        "    p = Point(3.0, 4.0)\n"
        "    print(f\"Distance: {p.distance()}\")\n"
        "    \n"
        "    # List comprehension\n"
        "    squares = [x**2 for x in range(10)]\n"
        "    \n"
        "    # Async example\n"
        "    async def fetch():\n"
        "        await asyncio.sleep(1)\n"
        "        return \"done\"\n"
        "\n"
        "if __name__ == \"__main__":\n"
        "    main()\n";
    
    printf("Python Lexer Test\n");
    printf("=================\n\n");
    printf("Input code:\n%s\n", test_code);
    
    PythonLexer* lexer = py_lexer_create(test_code);
    int result = py_lexer_tokenize(lexer);
    
    py_lexer_print_tokens(lexer);
    
    printf("\n=== Result ===\n");
    if (result == 0) {
        printf("SUCCESS: Tokenized %zu tokens with %d errors\n", 
               lexer->token_count, lexer->error_count);
    } else {
        printf("FAILED: %d errors occurred\n", lexer->error_count);
    }
    
    py_lexer_destroy(lexer);
    return result;
}

#endif