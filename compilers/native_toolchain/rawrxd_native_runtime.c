/*
 * RAWRXD NATIVE RUNTIME LIBRARY
 * Complete C runtime implementation - no MS CRT dependency
 * Supports: x86 (32-bit), x64 (64-bit), x32 (ILP32)
 */

#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* ============================================================================
 * MEMORY FUNCTIONS
 * ============================================================================ */

void* memset(void* dest, int c, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    while (count--) *p++ = (unsigned char)c;
    return dest;
}

void* memcpy(void* dest, const void* src, size_t count) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    while (count--) *d++ = *s++;
    return dest;
}

void* memmove(void* dest, const void* src, size_t count) {
    unsigned char* d = (unsigned char*)dest;
    const unsigned char* s = (const unsigned char*)src;
    if (d < s) {
        while (count--) *d++ = *s++;
    } else {
        d += count;
        s += count;
        while (count--) *--d = *--s;
    }
    return dest;
}

int memcmp(const void* buf1, const void* buf2, size_t count) {
    const unsigned char* p1 = (const unsigned char*)buf1;
    const unsigned char* p2 = (const unsigned char*)buf2;
    while (count--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++; p2++;
    }
    return 0;
}

void* memchr(const void* buf, int c, size_t count) {
    const unsigned char* p = (const unsigned char*)buf;
    while (count--) {
        if (*p == (unsigned char)c) return (void*)p;
        p++;
    }
    return NULL;
}

/* ============================================================================
 * STRING FUNCTIONS
 * ============================================================================ */

size_t strlen(const char* str) {
    const char* s = str;
    while (*s) s++;
    return s - str;
}

int strcmp(const char* str1, const char* str2) {
    while (*str1 && *str1 == *str2) { str1++; str2++; }
    return *(unsigned char*)str1 - *(unsigned char*)str2;
}

int strncmp(const char* str1, const char* str2, size_t count) {
    while (count && *str1 && *str1 == *str2) {
        str1++; str2++; count--;
    }
    return count ? (*(unsigned char*)str1 - *(unsigned char*)str2) : 0;
}

char* strcpy(char* dest, const char* src) {
    char* d = dest;
    while ((*d++ = *src++));
    return dest;
}

char* strncpy(char* dest, const char* src, size_t count) {
    char* d = dest;
    while (count && (*d++ = *src++)) count--;
    if (count) while (--count) *d++ = '\0';
    return dest;
}

char* strcat(char* dest, const char* src) {
    char* d = dest;
    while (*d) d++;
    while ((*d++ = *src++));
    return dest;
}

char* strncat(char* dest, const char* src, size_t count) {
    char* d = dest;
    while (*d) d++;
    while (count-- && (*d++ = *src++));
    if (!count) *d = '\0';
    return dest;
}

char* strchr(const char* str, int c) {
    while (*str && *str != c) str++;
    return *str == c ? (char*)str : NULL;
}

char* strrchr(const char* str, int c) {
    const char* last = NULL;
    while (*str) {
        if (*str == c) last = str;
        str++;
    }
    return (char*)last;
}

char* strstr(const char* str, const char* substr) {
    if (!*substr) return (char*)str;
    while (*str) {
        const char* s1 = str;
        const char* s2 = substr;
        while (*s1 && *s2 && *s1 == *s2) { s1++; s2++; }
        if (!*s2) return (char*)str;
        str++;
    }
    return NULL;
}

/* ============================================================================
 * CHARACTER FUNCTIONS
 * ============================================================================ */

int isspace(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; }
int isdigit(int c) { return c >= '0' && c <= '9'; }
int isalpha(int c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
int isalnum(int c) { return isalpha(c) || isdigit(c); }
int isupper(int c) { return c >= 'A' && c <= 'Z'; }
int islower(int c) { return c >= 'a' && c <= 'z'; }
int isxdigit(int c) { return isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
int isprint(int c) { return c >= 0x20 && c < 0x7F; }
int toupper(int c) { return islower(c) ? c - 'a' + 'A' : c; }
int tolower(int c) { return isupper(c) ? c - 'A' + 'a' : c; }

/* ============================================================================
 * CONVERSION FUNCTIONS
 * ============================================================================ */

int atoi(const char* str) {
    int sign = 1, result = 0;
    while (isspace(*str)) str++;
    if (*str == '-') { sign = -1; str++; }
    else if (*str == '+') str++;
    while (isdigit(*str)) result = result * 10 + (*str++ - '0');
    return sign * result;
}

long atol(const char* str) {
    long sign = 1, result = 0;
    while (isspace(*str)) str++;
    if (*str == '-') { sign = -1; str++; }
    else if (*str == '+') str++;
    while (isdigit(*str)) result = result * 10 + (*str++ - '0');
    return sign * result;
}

long long atoll(const char* str) {
    long long sign = 1, result = 0;
    while (isspace(*str)) str++;
    if (*str == '-') { sign = -1; str++; }
    else if (*str == '+') str++;
    while (isdigit(*str)) result = result * 10 + (*str++ - '0');
    return sign * result;
}

unsigned long strtoul(const char* str, char** endptr, int base) {
    unsigned long result = 0;
    while (isspace(*str)) str++;
    if (base == 0) {
        base = 10;
        if (*str == '0') {
            base = 8;
            str++;
            if (*str == 'x' || *str == 'X') { base = 16; str++; }
        }
    }
    while (isxdigit(*str)) {
        int digit = isdigit(*str) ? *str - '0' : toupper(*str) - 'A' + 10;
        if (digit >= base) break;
        result = result * base + digit;
        str++;
    }
    if (endptr) *endptr = (char*)str;
    return result;
}

long long strtoll(const char* str, char** endptr, int base) {
    long long sign = 1, result = 0;
    while (isspace(*str)) str++;
    if (*str == '-') { sign = -1; str++; }
    else if (*str == '+') str++;
    if (base == 0) {
        base = 10;
        if (*str == '0') {
            base = 8;
            str++;
            if (*str == 'x' || *str == 'X') { base = 16; str++; }
        }
    }
    while (isxdigit(*str)) {
        int digit = isdigit(*str) ? *str - '0' : toupper(*str) - 'A' + 10;
        if (digit >= base) break;
        result = result * base + digit;
        str++;
    }
    if (endptr) *endptr = (char*)str;
    return sign * result;
}

unsigned long long strtoull(const char* str, char** endptr, int base) {
    unsigned long long result = 0;
    while (isspace(*str)) str++;
    if (base == 0) {
        base = 10;
        if (*str == '0') {
            base = 8;
            str++;
            if (*str == 'x' || *str == 'X') { base = 16; str++; }
        }
    }
    while (isxdigit(*str)) {
        int digit = isdigit(*str) ? *str - '0' : toupper(*str) - 'A' + 10;
        if (digit >= base) break;
        result = result * base + digit;
        str++;
    }
    if (endptr) *endptr = (char*)str;
    return result;
}

/* ============================================================================
 * FORMATTED OUTPUT HELPERS
 * ============================================================================ */

static char* itoa_internal(long long value, char* str, int base, int uppercase) {
    char* p = str;
    int negative = 0;
    if (value < 0 && base == 10) { negative = 1; value = -value; }
    do {
        int digit = value % base;
        *p++ = digit < 10 ? '0' + digit : (uppercase ? 'A' : 'a') + digit - 10;
        value /= base;
    } while (value);
    if (negative) *p++ = '-';
    *p = '\0';
    /* Reverse */
    char* start = str;
    char* end = p - 1;
    while (start < end) { char t = *start; *start++ = *end; *end-- = t; }
    return str;
}

static char* utoa_internal(unsigned long long value, char* str, int base, int uppercase) {
    char* p = str;
    do {
        int digit = value % base;
        *p++ = digit < 10 ? '0' + digit : (uppercase ? 'A' : 'a') + digit - 10;
        value /= base;
    } while (value);
    *p = '\0';
    /* Reverse */
    char* start = str;
    char* end = p - 1;
    while (start < end) { char t = *start; *start++ = *end; *end-- = t; }
    return str;
}

/* ============================================================================
 * FILE I/O (Minimal implementation using Windows API)
 * ============================================================================ */

#define FILE_HANDLE_VALID 0x12345678

typedef struct {
    HANDLE hFile;
    int valid;
    int eof;
    int error;
} FILE_INTERNAL;

static FILE_INTERNAL stdin_internal = {0};
static FILE_INTERNAL stdout_internal = {0};
static FILE_INTERNAL stderr_internal = {0};

/* Use different names to avoid conflicts with stdio.h macros */
FILE* __stdin = (FILE*)&stdin_internal;
FILE* __stdout = (FILE*)&stdout_internal;
FILE* __stderr = (FILE*)&stderr_internal;

void _init_stdio(void) {
    stdin_internal.hFile = GetStdHandle(STD_INPUT_HANDLE);
    stdin_internal.valid = FILE_HANDLE_VALID;
    stdout_internal.hFile = GetStdHandle(STD_OUTPUT_HANDLE);
    stdout_internal.valid = FILE_HANDLE_VALID;
    stderr_internal.hFile = GetStdHandle(STD_ERROR_HANDLE);
    stderr_internal.valid = FILE_HANDLE_VALID;
}

int fputs(const char* str, FILE* stream) {
    FILE_INTERNAL* f = (FILE_INTERNAL*)stream;
    if (!f || f->valid != FILE_HANDLE_VALID) return EOF;
    DWORD written;
    size_t len = strlen(str);
    WriteFile(f->hFile, str, (DWORD)len, &written, NULL);
    return written == len ? 0 : EOF;
}

int puts(const char* str) {
    if (fputs(str, stdout) == EOF) return EOF;
    return fputs("\n", stdout);
}

int fputc(int c, FILE* stream) {
    char ch = (char)c;
    FILE_INTERNAL* f = (FILE_INTERNAL*)stream;
    if (!f || f->valid != FILE_HANDLE_VALID) return EOF;
    DWORD written;
    WriteFile(f->hFile, &ch, 1, &written, NULL);
    return written == 1 ? c : EOF;
}

int putchar(int c) { return fputc(c, stdout); }

int fgetc(FILE* stream) {
    FILE_INTERNAL* f = (FILE_INTERNAL*)stream;
    if (!f || f->valid != FILE_HANDLE_VALID) return EOF;
    char ch;
    DWORD read;
    if (!ReadFile(f->hFile, &ch, 1, &read, NULL) || read == 0) {
        f->eof = 1;
        return EOF;
    }
    return (unsigned char)ch;
}

int getchar(void) { return fgetc(stdin); }

char* fgets(char* str, int n, FILE* stream) {
    FILE_INTERNAL* f = (FILE_INTERNAL*)stream;
    if (!f || f->valid != FILE_HANDLE_VALID) return NULL;
    int i = 0;
    while (i < n - 1) {
        int c = fgetc(stream);
        if (c == EOF) break;
        str[i++] = (char)c;
        if (c == '\n') break;
    }
    if (i == 0) return NULL;
    str[i] = '\0';
    return str;
}

/* ============================================================================
 * FORMATTED OUTPUT
 * ============================================================================ */

typedef struct {
    char* buf;
    size_t pos;
    size_t size;
    FILE* file;
    int count;
} PrintContext;

static void print_char(PrintContext* ctx, char c) {
    if (ctx->file) {
        fputc(c, ctx->file);
    } else if (ctx->buf && ctx->pos < ctx->size - 1) {
        ctx->buf[ctx->pos++] = c;
    }
    ctx->count++;
}

static void print_string(PrintContext* ctx, const char* s, int width, int precision, int left) {
    int len = (int)strlen(s);
    if (precision >= 0 && len > precision) len = precision;
    int pad = width - len;
    if (!left) while (pad-- > 0) print_char(ctx, ' ');
    while (len-- > 0) print_char(ctx, *s++);
    if (left) while (pad-- > 0) print_char(ctx, ' ');
}

static void print_int(PrintContext* ctx, long long val, int base, int width, int precision, int left, int show_sign, int space, int alt, int upper) {
    char buf[64];
    if (val < 0 && base == 10) {
        print_char(ctx, '-');
        val = -val;
        width--;
    } else if (show_sign) {
        print_char(ctx, '+');
        width--;
    } else if (space) {
        print_char(ctx, ' ');
        width--;
    }
    if (alt && base == 16) { print_char(ctx, '0'); print_char(ctx, upper ? 'X' : 'x'); width -= 2; }
    if (alt && base == 8 && val != 0) { print_char(ctx, '0'); width--; }
    itoa_internal(val, buf, base, upper);
    int len = (int)strlen(buf);
    if (precision > len) width -= (precision - len);
    if (!left) while (width-- > len) print_char(ctx, ' ');
    while (precision-- > len) print_char(ctx, '0');
    print_string(ctx, buf, 0, -1, 0);
    if (left) while (width-- >= len) print_char(ctx, ' ');
}

static void print_uint(PrintContext* ctx, unsigned long long val, int base, int width, int precision, int left, int alt, int upper) {
    char buf[64];
    if (alt && base == 16) { print_char(ctx, '0'); print_char(ctx, upper ? 'X' : 'x'); width -= 2; }
    if (alt && base == 8 && val != 0) { print_char(ctx, '0'); width--; }
    utoa_internal(val, buf, base, upper);
    int len = (int)strlen(buf);
    if (precision > len) width -= (precision - len);
    if (!left) while (width-- > len) print_char(ctx, ' ');
    while (precision-- > len) print_char(ctx, '0');
    print_string(ctx, buf, 0, -1, 0);
    if (left) while (width-- >= len) print_char(ctx, ' ');
}

static int vsnprintf_internal(PrintContext* ctx, const char* format, va_list args) {
    const char* p = format;
    while (*p) {
        if (*p != '%') {
            print_char(ctx, *p++);
            continue;
        }
        p++;
        int left = 0, show_sign = 0, space = 0, alt = 0, zero_pad = 0;
        int width = 0, precision = -1;
        int length = 0; /* 0=none, 1=h, 2=hh, 3=l, 4=ll, 5=z, 6=j, 7=t, 8=L */
        
        /* Flags */
        while (*p == '-' || *p == '+' || *p == ' ' || *p == '#' || *p == '0') {
            if (*p == '-') left = 1;
            else if (*p == '+') show_sign = 1;
            else if (*p == ' ') space = 1;
            else if (*p == '#') alt = 1;
            else if (*p == '0') zero_pad = 1;
            p++;
        }
        /* Width */
        if (*p == '*') { width = va_arg(args, int); p++; }
        else while (isdigit(*p)) width = width * 10 + (*p++ - '0');
        /* Precision */
        if (*p == '.') {
            p++;
            precision = 0;
            if (*p == '*') { precision = va_arg(args, int); p++; }
            else while (isdigit(*p)) precision = precision * 10 + (*p++ - '0');
        }
        /* Length modifier */
        if (*p == 'h') { length = 1; p++; if (*p == 'h') { length = 2; p++; } }
        else if (*p == 'l') { length = 3; p++; if (*p == 'l') { length = 4; p++; } }
        else if (*p == 'z') { length = 5; p++; }
        else if (*p == 'j') { length = 6; p++; }
        else if (*p == 't') { length = 7; p++; }
        else if (*p == 'L') { length = 8; p++; }
        
        /* Conversion specifier */
        switch (*p++) {
            case 'd':
            case 'i': {
                long long val;
                if (length == 4) val = va_arg(args, long long);
                else if (length == 3) val = va_arg(args, long);
                else val = va_arg(args, int);
                print_int(ctx, val, 10, width, precision, left, show_sign, space, 0, 0);
                break;
            }
            case 'u': {
                unsigned long long val;
                if (length == 4) val = va_arg(args, unsigned long long);
                else if (length == 3) val = va_arg(args, unsigned long);
                else val = va_arg(args, unsigned int);
                print_uint(ctx, val, 10, width, precision, left, 0, 0);
                break;
            }
            case 'o': {
                unsigned long long val;
                if (length == 4) val = va_arg(args, unsigned long long);
                else if (length == 3) val = va_arg(args, unsigned long);
                else val = va_arg(args, unsigned int);
                print_uint(ctx, val, 8, width, precision, left, alt, 0);
                break;
            }
            case 'x':
            case 'X': {
                unsigned long long val;
                if (length == 4) val = va_arg(args, unsigned long long);
                else if (length == 3) val = va_arg(args, unsigned long);
                else val = va_arg(args, unsigned int);
                print_uint(ctx, val, 16, width, precision, left, alt, *(p-1) == 'X');
                break;
            }
            case 'p': {
                void* val = va_arg(args, void*);
                print_uint(ctx, (unsigned long long)val, 16, width, precision, left, 1, 0);
                break;
            }
            case 'c': {
                char val = (char)va_arg(args, int);
                if (!left) while (--width > 0) print_char(ctx, ' ');
                print_char(ctx, val);
                if (left) while (--width > 0) print_char(ctx, ' ');
                break;
            }
            case 's': {
                const char* val = va_arg(args, const char*);
                if (!val) val = "(null)";
                print_string(ctx, val, width, precision, left);
                break;
            }
            case 'n': {
                int* val = va_arg(args, int*);
                *val = ctx->count;
                break;
            }
            case '%':
                print_char(ctx, '%');
                break;
            default:
                print_char(ctx, '%');
                print_char(ctx, *(p-1));
                break;
        }
    }
    if (ctx->buf && ctx->pos < ctx->size) ctx->buf[ctx->pos] = '\0';
    return ctx->count;
}

int vsnprintf(char* buf, size_t size, const char* format, va_list args) {
    PrintContext ctx = {0};
    ctx.buf = buf;
    ctx.size = size;
    return vsnprintf_internal(&ctx, format, args);
}

int snprintf(char* buf, size_t size, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf, size, format, args);
    va_end(args);
    return ret;
}

int sprintf(char* buf, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(buf, (size_t)-1, format, args);
    va_end(args);
    return ret;
}

int vfprintf(FILE* stream, const char* format, va_list args) {
    PrintContext ctx = {0};
    ctx.file = stream;
    return vsnprintf_internal(&ctx, format, args);
}

int fprintf(FILE* stream, const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stream, format, args);
    va_end(args);
    return ret;
}

int printf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    int ret = vfprintf(stdout, format, args);
    va_end(args);
    return ret;
}

/* ============================================================================
 * HEAP MEMORY
 * ============================================================================ */

static HANDLE g_heap = NULL;

void* malloc(size_t size) {
    if (!g_heap) g_heap = GetProcessHeap();
    return HeapAlloc(g_heap, 0, size);
}

void* calloc(size_t num, size_t size) {
    size_t total = num * size;
    void* p = malloc(total);
    if (p) memset(p, 0, total);
    return p;
}

void* realloc(void* ptr, size_t size) {
    if (!g_heap) g_heap = GetProcessHeap();
    if (!ptr) return malloc(size);
    if (size == 0) { free(ptr); return NULL; }
    return HeapReAlloc(g_heap, 0, ptr, size);
}

void free(void* ptr) {
    if (!g_heap) g_heap = GetProcessHeap();
    if (ptr) HeapFree(g_heap, 0, ptr);
}

/* ============================================================================
 * PROGRAM STARTUP/EXIT
 * ============================================================================ */

extern int main(int argc, char* argv[]);

static void parse_command_line(char* cmdline, int* argc, char** argv, int max_args) {
    *argc = 0;
    char* p = cmdline;
    while (*p && *argc < max_args) {
        while (isspace(*p)) p++;
        if (!*p) break;
        argv[(*argc)++] = p;
        if (*p == '"') {
            p++;
            while (*p && *p != '"') p++;
            if (*p == '"') *p++ = '\0';
        } else {
            while (*p && !isspace(*p)) p++;
            if (*p) *p++ = '\0';
        }
    }
}

#ifdef _WIN64
void __cdecl WinMainCRTStartup(void) {
    _init_stdio();
    char cmdline[32768];
    char* argv[256];
    int argc;
    
    LPWSTR wcmdline = GetCommandLineW();
    WideCharToMultiByte(CP_ACP, 0, wcmdline, -1, cmdline, sizeof(cmdline), NULL, NULL);
    parse_command_line(cmdline, &argc, argv, 256);
    
    int ret = main(argc, argv);
    ExitProcess((UINT)ret);
}

void __cdecl mainCRTStartup(void) {
    WinMainCRTStartup();
}
#else
void __cdecl WinMainCRTStartup(void) {
    _init_stdio();
    char cmdline[32768];
    char* argv[256];
    int argc;
    
    LPWSTR wcmdline = GetCommandLineW();
    WideCharToMultiByte(CP_ACP, 0, wcmdline, -1, cmdline, sizeof(cmdline), NULL, NULL);
    parse_command_line(cmdline, &argc, argv, 256);
    
    int ret = main(argc, argv);
    ExitProcess((UINT)ret);
}

void __cdecl mainCRTStartup(void) {
    WinMainCRTStartup();
}
#endif

/* ============================================================================
 * ENTRY POINT
 * ============================================================================ */

#ifdef _WIN64
#pragma comment(linker, "/ENTRY:mainCRTStartup")
#else
#pragma comment(linker, "/ENTRY:mainCRTStartup")
#endif
