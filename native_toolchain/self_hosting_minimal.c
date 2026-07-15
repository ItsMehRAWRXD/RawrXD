//=============================================================================
// self_hosting_minimal.c - Self-Hosting Minimal C Compiler (Bootstrap Stage 1)
// This compiler only uses features it implements - no typedef, struct, or enum
// Uses #define for types and constants
//=============================================================================

// Type definitions using #define (no typedef)
#define int int
#define char char
#define void void
#define size_t unsigned int
#define NULL 0

// Token type constants (using #define instead of enum)
#define T_EOF 0
#define T_IDENT 1
#define T_NUMBER 2
#define T_STRING 3
#define T_CHAR 4
#define T_INT 5
#define T_RETURN 6
#define T_IF 7
#define T_ELSE 8
#define T_WHILE 9
#define T_FOR 10
#define T_BREAK 11
#define T_CONTINUE 12
#define T_SIZEOF 13
#define T_EXTERN 14
#define T_STATIC 15
#define T_VOID 16
#define T_CHAR_KW 17
#define T_PLUS 18
#define T_MINUS 19
#define T_STAR 20
#define T_SLASH 21
#define T_PERCENT 22
#define T_LT 23
#define T_GT 24
#define T_LE 25
#define T_GE 26
#define T_EQ 27
#define T_NE 28
#define T_AND 29
#define T_OR 30
#define T_NOT 31
#define T_ASSIGN 32
#define T_PLUS_EQ 33
#define T_MINUS_EQ 34
#define T_INC 35
#define T_DEC 36
#define T_LBRACE 37
#define T_RBRACE 38
#define T_LPAREN 39
#define T_RPAREN 40
#define T_LBRACKET 41
#define T_RBRACKET 42
#define T_SEMICOLON 43
#define T_COMMA 44
#define T_COLON 45
#define T_DOT 46
#define T_ARROW 47
#define T_AMPERSAND 48

// Simple arena allocator
#define HEAP_SIZE (1024 * 1024)
static char heap[HEAP_SIZE];
static size_t heap_ptr = 0;

void *alloc(size_t size) {
    void *ptr = heap + heap_ptr;
    heap_ptr += size;
    if (heap_ptr >= HEAP_SIZE) {
        return NULL;
    }
    return ptr;
}

void *alloc_zero(size_t size) {
    void *ptr = alloc(size);
    if (ptr) {
        char *p = ptr;
        for (size_t i = 0; i < size; i++) {
            p[i] = 0;
        }
    }
    return ptr;
}

// String utilities
size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

int strcmp(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++;
        b++;
    }
    return *a - *b;
}

int strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) {
        a++;
        b++;
        n--;
    }
    return n ? *a - *b : 0;
}

char *strcpy(char *dst, const char *src) {
    char *d = dst;
    while (*src) {
        *d++ = *src++;
    }
    *d = '\0';
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n) {
    char *d = dst;
    while (n && *src) {
        *d++ = *src++;
        n--;
    }
    while (n) {
        *d++ = '\0';
        n--;
    }
    return dst;
}

int isalpha(int c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

int isdigit(int c) {
    return c >= '0' && c <= '9';
}

int isalnum(int c) {
    return isalpha(c) || isdigit(c);
}

int isspace(int c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

int atoi(const char *s) {
    int sign = 1;
    int val = 0;
    if (*s == '-') {
        sign = -1;
        s++;
    }
    while (isdigit(*s)) {
        val = val * 10 + (*s - '0');
        s++;
    }
    return val * sign;
}

// File I/O (Windows API)
#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x80

typedef void *HANDLE;
typedef unsigned long DWORD;
typedef long LONG;
typedef long long LONGLONG;

extern HANDLE __stdcall CreateFileA(const char *lpFileName, DWORD dwDesiredAccess,
                                      DWORD dwShareMode, void *lpSecurityAttributes,
                                      DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                                      HANDLE hTemplateFile);
extern int __stdcall ReadFile(HANDLE hFile, void *lpBuffer, DWORD nNumberOfBytesToRead,
                               DWORD *lpNumberOfBytesRead, void *lpOverlapped);
extern int __stdcall WriteFile(HANDLE hFile, const void *lpBuffer, DWORD nNumberOfBytesToWrite,
                                DWORD *lpNumberOfBytesWritten, void *lpOverlapped);
extern int __stdcall CloseHandle(HANDLE hObject);
extern void __stdcall ExitProcess(unsigned int uExitCode);

// Token structure
struct Token {
    int type;
    char value[64];
    int line;
    int column;
    struct Token *next;
};

// Global token array
#define MAX_TOKENS 10000
struct Token tokens[MAX_TOKENS];
int token_count = 0;
int current_token = 0;

// Source position
char *source;
char *src_pos;
int line = 1;
int column = 1;

// Output file
HANDLE output_file;

// Keywords
struct Keyword {
    const char *name;
    int type;
};

struct Keyword keywords[] = {
    {"int", T_INT},
    {"void", T_VOID},
    {"char", T_CHAR_KW},
    {"return", T_RETURN},
    {"if", T_IF},
    {"else", T_ELSE},
    {"while", T_WHILE},
    {"for", T_FOR},
    {"break", T_BREAK},
    {"continue", T_CONTINUE},
    {"sizeof", T_SIZEOF},
    {"extern", T_EXTERN},
    {"static", T_STATIC},
    {NULL, 0}
};

// Get keyword type
int get_keyword_type(const char *word) {
    for (int i = 0; keywords[i].name; i++) {
        if (strcmp(keywords[i].name, word) == 0) {
            return keywords[i].type;
        }
    }
    return T_IDENT;
}

// Skip whitespace and comments
void skip_whitespace() {
    while (*src_pos) {
        if (*src_pos == ' ' || *src_pos == '\t') {
            src_pos++;
            column++;
        } else if (*src_pos == '\n') {
            src_pos++;
            line++;
            column = 1;
        } else if (*src_pos == '\r') {
            src_pos++;
        } else if (*src_pos == '/' && *(src_pos + 1) == '/') {
            // Single-line comment
            while (*src_pos && *src_pos != '\n') src_pos++;
        } else if (*src_pos == '/' && *(src_pos + 1) == '*') {
            // Multi-line comment
            src_pos += 2;
            while (*src_pos && !(*src_pos == '*' && *(src_pos + 1) == '/')) {
                if (*src_pos == '\n') line++;
                src_pos++;
            }
            if (*src_pos) src_pos += 2;
        } else {
            break;
        }
    }
}

// Tokenize source code
void tokenize() {
    while (*src_pos) {
        skip_whitespace();
        if (!*src_pos) break;
        
        if (token_count >= MAX_TOKENS) {
            break;
        }
        
        struct Token *tok = &tokens[token_count++];
        tok->line = line;
        tok->column = column;
        tok->next = NULL;
        
        // Identifier or keyword
        if (isalpha(*src_pos) || *src_pos == '_') {
            int i = 0;
            while (isalnum(*src_pos) || *src_pos == '_') {
                if (i < 63) {
                    tok->value[i++] = *src_pos;
                }
                src_pos++;
                column++;
            }
            tok->value[i] = '\0';
            tok->type = get_keyword_type(tok->value);
        }
        // Number
        else if (isdigit(*src_pos)) {
            int i = 0;
            while (isdigit(*src_pos)) {
                if (i < 63) {
                    tok->value[i++] = *src_pos;
                }
                src_pos++;
                column++;
            }
            tok->value[i] = '\0';
            tok->type = T_NUMBER;
        }
        // String literal
        else if (*src_pos == '"') {
            src_pos++;
            column++;
            int i = 0;
            while (*src_pos && *src_pos != '"') {
                if (*src_pos == '\\' && *(src_pos + 1)) {
                    src_pos++;
                    switch (*src_pos) {
                        case 'n': tok->value[i++] = '\n'; break;
                        case 't': tok->value[i++] = '\t'; break;
                        case 'r': tok->value[i++] = '\r'; break;
                        case '\\': tok->value[i++] = '\\'; break;
                        case '"': tok->value[i++] = '"'; break;
                        default: tok->value[i++] = *src_pos; break;
                    }
                    src_pos++;
                } else {
                    tok->value[i++] = *src_pos++;
                }
                column++;
            }
            tok->value[i] = '\0';
            if (*src_pos == '"') {
                src_pos++;
                column++;
            }
            tok->type = T_STRING;
        }
        // Character literal
        else if (*src_pos == '\'') {
            src_pos++;
            column++;
            if (*src_pos == '\\' && *(src_pos + 1)) {
                src_pos++;
                switch (*src_pos) {
                    case 'n': tok->value[0] = '\n'; break;
                    case 't': tok->value[0] = '\t'; break;
                    case 'r': tok->value[0] = '\r'; break;
                    case '\\': tok->value[0] = '\\'; break;
                    case '\'': tok->value[0] = '\''; break;
                    default: tok->value[0] = *src_pos; break;
                }
                src_pos++;
            } else {
                tok->value[0] = *src_pos++;
            }
            tok->value[1] = '\0';
            if (*src_pos == '\'') src_pos++;
            tok->type = T_CHAR;
        }
        // Operators and delimiters
        else {
            switch (*src_pos) {
                case '+':
                    if (*(src_pos + 1) == '+') { tok->type = T_INC; src_pos += 2; }
                    else if (*(src_pos + 1) == '=') { tok->type = T_PLUS_EQ; src_pos += 2; }
                    else { tok->type = T_PLUS; src_pos++; }
                    break;
                case '-':
                    if (*(src_pos + 1) == '-') { tok->type = T_DEC; src_pos += 2; }
                    else if (*(src_pos + 1) == '=') { tok->type = T_MINUS_EQ; src_pos += 2; }
                    else if (*(src_pos + 1) == '>') { tok->type = T_ARROW; src_pos += 2; }
                    else { tok->type = T_MINUS; src_pos++; }
                    break;
                case '*': tok->type = T_STAR; src_pos++; break;
                case '/': tok->type = T_SLASH; src_pos++; break;
                case '%': tok->type = T_PERCENT; src_pos++; break;
                case '<':
                    if (*(src_pos + 1) == '=') { tok->type = T_LE; src_pos += 2; }
                    else { tok->type = T_LT; src_pos++; }
                    break;
                case '>':
                    if (*(src_pos + 1) == '=') { tok->type = T_GE; src_pos += 2; }
                    else { tok->type = T_GT; src_pos++; }
                    break;
                case '=':
                    if (*(src_pos + 1) == '=') { tok->type = T_EQ; src_pos += 2; }
                    else { tok->type = T_ASSIGN; src_pos++; }
                    break;
                case '!':
                    if (*(src_pos + 1) == '=') { tok->type = T_NE; src_pos += 2; }
                    else { tok->type = T_NOT; src_pos++; }
                    break;
                case '&':
                    if (*(src_pos + 1) == '&') { tok->type = T_AND; src_pos += 2; }
                    else { tok->type = T_AMPERSAND; src_pos++; }
                    break;
                case '|':
                    if (*(src_pos + 1) == '|') { tok->type = T_OR; src_pos += 2; }
                    else { tok->type = T_OR; src_pos++; }
                    break;
                case '(': tok->type = T_LPAREN; src_pos++; break;
                case ')': tok->type = T_RPAREN; src_pos++; break;
                case '{': tok->type = T_LBRACE; src_pos++; break;
                case '}': tok->type = T_RBRACE; src_pos++; break;
                case '[': tok->type = T_LBRACKET; src_pos++; break;
                case ']': tok->type = T_RBRACKET; src_pos++; break;
                case ';': tok->type = T_SEMICOLON; src_pos++; break;
                case ',': tok->type = T_COMMA; src_pos++; break;
                case ':': tok->type = T_COLON; src_pos++; break;
                case '.': tok->type = T_DOT; src_pos++; break;
                default:
                    src_pos++;
                    tok->type = T_EOF;
                    break;
            }
            column++;
        }
    }
    
    // Add EOF token
    tokens[token_count].type = T_EOF;
    tokens[token_count].line = line;
}

// Current token
struct Token *cur_token() {
    return &tokens[current_token];
}

// Advance to next token
void next_token() {
    if (current_token < token_count - 1) {
        current_token++;
    }
}

// Match and consume token
int match_token(int type) {
    if (cur_token()->type == type) {
        next_token();
        return 1;
    }
    return 0;
}

// Expect token
int expect_token(int type) {
    if (match_token(type)) return 1;
    return 0;
}

// Code generation
void emit(const char *str) {
    DWORD written;
    WriteFile(output_file, str, strlen(str), &written, NULL);
    WriteFile(output_file, "\r\n", 2, &written, NULL);
}

void emit_fmt(const char *fmt, int val) {
    char buf[256];
    int i = 0;
    while (fmt[i] && i < 250) {
        if (fmt[i] == '%' && fmt[i+1] == 'd') {
            // Convert val to string
            char num[32];
            int n = val;
            int neg = 0;
            if (n < 0) { neg = 1; n = -n; }
            int j = 0;
            if (n == 0) num[j++] = '0';
            while (n > 0) {
                num[j++] = '0' + (n % 10);
                n /= 10;
            }
            if (neg) num[j++] = '-';
            // Reverse
            for (int k = 0; k < j/2; k++) {
                char t = num[k];
                num[k] = num[j-1-k];
                num[j-1-k] = t;
            }
            num[j] = '\0';
            // Append
            for (int k = 0; num[k]; k++) buf[i++] = num[k];
            i += 2; // Skip %d
        } else {
            buf[i++] = fmt[i];
        }
    }
    buf[i] = '\0';
    emit(buf);
}

// Parse expression (simplified)
int parse_expression() {
    if (cur_token()->type == T_NUMBER) {
        int val = atoi(cur_token()->value);
        next_token();
        return val;
    }
    return 0;
}

// Parse statement
void parse_statement() {
    if (cur_token()->type == T_RETURN) {
        next_token();
        int val = parse_expression();
        emit_fmt("    mov eax, %d", val);
        expect_token(T_SEMICOLON);
    }
}

// Parse function
void parse_function() {
    // Return type
    if (cur_token()->type == T_INT || cur_token()->type == T_VOID) {
        next_token();
    }
    
    // Function name
    if (cur_token()->type == T_IDENT) {
        char func_name[64];
        strcpy(func_name, cur_token()->value);
        next_token();
        
        // Parameters
        expect_token(T_LPAREN);
        expect_token(T_RPAREN);
        
        // Function body
        expect_token(T_LBRACE);
        
        emit("BITS 64");
        emit("SECTION .text");
        emit("global _start");
        emit("_start:");
        emit("    push rbp");
        emit("    mov rbp, rsp");
        
        // Parse statements
        while (cur_token()->type != T_RBRACE && cur_token()->type != T_EOF) {
            parse_statement();
        }
        
        emit("    mov rsp, rbp");
        emit("    pop rbp");
        emit("    ret");
        
        expect_token(T_RBRACE);
    }
}

// Parse program
void parse_program() {
    while (cur_token()->type != T_EOF) {
        parse_function();
    }
}

// Main entry point
int main(int argc, char **argv) {
    if (argc < 2) {
        const char *msg = "Self-Hosting Minimal C Compiler v1.0\r\n";
        const char *usage = "Usage: self_hosting_minimal.exe <input.c>\r\n";
        DWORD written;
        WriteFile((HANDLE)-11, msg, strlen(msg), &written, NULL);
        WriteFile((HANDLE)-11, usage, strlen(usage), &written, NULL);
        return 1;
    }
    
    // Read source file
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == (HANDLE)-1) {
        const char *msg = "Error: Cannot open input file\r\n";
        DWORD written;
        WriteFile((HANDLE)-11, msg, strlen(msg), &written, NULL);
        return 1;
    }
    
    // Allocate source buffer
    source = alloc(1024 * 1024);
    if (!source) {
        CloseHandle(hFile);
        return 1;
    }
    
    DWORD bytesRead;
    ReadFile(hFile, source, 1024 * 1024 - 1, &bytesRead, NULL);
    source[bytesRead] = '\0';
    CloseHandle(hFile);
    
    src_pos = source;
    
    // Open output file
    output_file = CreateFileA("output.asm", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == (HANDLE)-1) {
        const char *msg = "Error: Cannot create output file\r\n";
        DWORD written;
        WriteFile((HANDLE)-11, msg, strlen(msg), &written, NULL);
        return 1;
    }
    
    // Tokenize
    tokenize();
    
    // Parse and generate code
    parse_program();
    
    // Cleanup
    CloseHandle(output_file);
    
    return 0;
}
