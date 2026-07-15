/*
 * Native Runtime Library - Replaces MS CRT
 * Provides: startup, memory, I/O, string operations
 * No Microsoft CRT dependencies
 */

#include <windows.h>
#include <stdint.h>
#include <stddef.h>

#define EOF (-1)

// ============================================================================
// Startup Code (replaces crt0.obj)
// ============================================================================

// Entry point called by the OS
void __cdecl mainCRTStartup(void);

// User-defined main
extern int main(int argc, char **argv);

// Command line parsing
static char *cmdline_args[256];
static int cmdline_argc = 0;

static void parse_cmdline(void) {
    wchar_t *wcmd = GetCommandLineW();
    static char cmdline[32768];
    
    // Convert to narrow
    WideCharToMultiByte(CP_UTF8, 0, wcmd, -1, cmdline, sizeof(cmdline), NULL, NULL);
    
    char *p = cmdline;
    char *arg_start = NULL;
    int in_quotes = 0;
    
    while (*p) {
        // Skip leading whitespace
        while (*p && (*p == ' ' || *p == '\t')) p++;
        if (!*p) break;
        
        arg_start = p;
        in_quotes = 0;
        
        // Parse argument
        while (*p) {
            if (*p == '"') {
                in_quotes = !in_quotes;
                p++;
            } else if (!in_quotes && (*p == ' ' || *p == '\t')) {
                break;
            } else {
                p++;
            }
        }
        
        // Null terminate and store
        if (*p) *p++ = '\0';
        
        // Remove quotes from stored arg
        char *arg = arg_start;
        char *dst = arg_start;
        while (*arg) {
            if (*arg != '"') *dst++ = *arg;
            arg++;
        }
        *dst = '\0';
        
        if (cmdline_argc < 256) {
            cmdline_args[cmdline_argc++] = arg_start;
        }
    }
}

void __cdecl mainCRTStartup(void) {
    // Initialize heap
    // (Windows heap is already available via GetProcessHeap)
    
    // Parse command line
    parse_cmdline();
    
    // Call user main
    int result = main(cmdline_argc, cmdline_args);
    
    // Exit process
    ExitProcess(result);
}

// For GUI apps
void __cdecl WinMainCRTStartup(void) {
    parse_cmdline();
    
    // Get hInstance from PEB
    HINSTANCE hInstance = GetModuleHandle(NULL);
    
    // Call user WinMain
    extern int WinMain(HINSTANCE, HINSTANCE, LPSTR, int);
    int result = WinMain(hInstance, NULL, cmdline_argc > 1 ? cmdline_args[1] : "", SW_SHOWDEFAULT);
    
    ExitProcess(result);
}

// ============================================================================
// Memory Management
// ============================================================================

static HANDLE process_heap = NULL;

static void init_heap(void) {
    if (!process_heap) {
        process_heap = GetProcessHeap();
    }
}

void *native_malloc(size_t size) {
    init_heap();
    return HeapAlloc(process_heap, 0, size);
}

void *native_calloc(size_t num, size_t size) {
    init_heap();
    size_t total = num * size;
    void *p = HeapAlloc(process_heap, HEAP_ZERO_MEMORY, total);
    return p;
}

void *native_realloc(void *ptr, size_t size) {
    init_heap();
    if (!ptr) return HeapAlloc(process_heap, 0, size);
    if (size == 0) {
        HeapFree(process_heap, 0, ptr);
        return NULL;
    }
    return HeapReAlloc(process_heap, 0, ptr, size);
}

void native_free(void *ptr) {
    if (ptr && process_heap) {
        HeapFree(process_heap, 0, ptr);
    }
}

// ============================================================================
// String Operations
// ============================================================================

size_t native_strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

int native_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

int native_strncmp(const char *s1, const char *s2, size_t n) {
    while (n && *s1 && (*s1 == *s2)) {
        s1++;
        s2++;
        n--;
    }
    if (n == 0) return 0;
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}

char *native_strcpy(char *dst, const char *src) {
    char *d = dst;
    while ((*d++ = *src++));
    return dst;
}

char *native_strncpy(char *dst, const char *src, size_t n) {
    char *d = dst;
    while (n && (*d++ = *src++)) n--;
    if (n) while (--n) *d++ = '\0';
    return dst;
}

char *native_strcat(char *dst, const char *src) {
    char *d = dst;
    while (*d) d++;
    while ((*d++ = *src++));
    return dst;
}

void *native_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *native_memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

int native_memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;
    while (n--) {
        if (*p1 != *p2) return *p1 - *p2;
        p1++;
        p2++;
    }
    return 0;
}

// ============================================================================
// I/O Operations (Windows API only)
// ============================================================================

static HANDLE stdout_handle = NULL;
static HANDLE stderr_handle = NULL;
static HANDLE stdin_handle = NULL;

static void init_stdio(void) {
    if (!stdout_handle) {
        stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
        stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
        stdin_handle = GetStdHandle(STD_INPUT_HANDLE);
    }
}

int native_puts(const char *s) {
    init_stdio();
    DWORD written;
    WriteFile(stdout_handle, s, native_strlen(s), &written, NULL);
    WriteFile(stdout_handle, "\r\n", 2, &written, NULL);
    return 1;
}

int native_printf(const char *fmt, ...) {
    // Simplified printf - just output the format string for now
    // Full implementation would parse format specifiers
    init_stdio();
    DWORD written;
    WriteFile(stdout_handle, fmt, native_strlen(fmt), &written, NULL);
    return written;
}

int native_fprintf(void *file, const char *fmt, ...) {
    init_stdio();
    HANDLE h = (file == (void*)2) ? stderr_handle : stdout_handle;
    DWORD written;
    WriteFile(h, fmt, native_strlen(fmt), &written, NULL);
    return written;
}

// Forward declaration
char *native_strchr(const char *s, int c);

// ============================================================================
// File Operations
// ============================================================================

void *native_fopen(const char *path, const char *mode) {
    DWORD access = 0;
    DWORD creation = 0;
    
    if (native_strchr(mode, 'r')) {
        access = GENERIC_READ;
        creation = OPEN_EXISTING;
    }
    if (native_strchr(mode, 'w')) {
        access = GENERIC_WRITE;
        creation = CREATE_ALWAYS;
    }
    if (native_strchr(mode, 'a')) {
        access = GENERIC_WRITE;
        creation = OPEN_ALWAYS;
    }
    if (native_strchr(mode, '+')) {
        access = GENERIC_READ | GENERIC_WRITE;
    }
    
    HANDLE h = CreateFileA(path, access, FILE_SHARE_READ, NULL, creation, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    
    // For append mode, seek to end
    if (native_strchr(mode, 'a')) {
        SetFilePointer(h, 0, NULL, FILE_END);
    }
    
    return h;
}

size_t native_fread(void *ptr, size_t size, size_t count, void *stream) {
    DWORD bytes_read;
    DWORD total = size * count;
    if (!ReadFile(stream, ptr, total, &bytes_read, NULL)) return 0;
    return bytes_read / size;
}

size_t native_fwrite(const void *ptr, size_t size, size_t count, void *stream) {
    DWORD bytes_written;
    DWORD total = size * count;
    if (!WriteFile(stream, ptr, total, &bytes_written, NULL)) return 0;
    return bytes_written / size;
}

int native_fclose(void *stream) {
    return CloseHandle(stream) ? 0 : EOF;
}

int native_fseek(void *stream, long offset, int origin) {
    DWORD method = FILE_BEGIN;
    if (origin == 1) method = FILE_CURRENT;
    if (origin == 2) method = FILE_END;
    return SetFilePointer(stream, offset, NULL, method) == INVALID_SET_FILE_POINTER ? -1 : 0;
}

long native_ftell(void *stream) {
    return SetFilePointer(stream, 0, NULL, FILE_CURRENT);
}

// ============================================================================
// Helper: strchr
// ============================================================================

char *native_strchr(const char *s, int c) {
    while (*s) {
        if (*s == c) return (char *)s;
        s++;
    }
    return NULL;
}

// ============================================================================
// Entry point exports
// ============================================================================

#pragma comment(linker, "/ENTRY:mainCRTStartup")
