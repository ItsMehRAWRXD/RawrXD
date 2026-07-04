#include <windows.h>
#include <stdint.h>

#define CLI_BUFFER_CHUNK_SIZE 4096
#define ERROR_VULKAN_LOG_OUT  0x80000001

// Simulate our custom Sovereign Arena allocation boundary
struct SovereignArena {
    uint8_t* base_ptr;
    size_t   capacity;
    size_t   bump_offset;
};

void* ArenaAlloc(SovereignArena* arena, size_t size) {
    if (arena->bump_offset + size > arena->capacity) return nullptr;
    void* ptr = arena->base_ptr + arena->bump_offset;
    arena->bump_offset += (size + 7) & ~7; // 8-byte alignment
    return ptr;
}

// Global Handle Redirection Helpers
void WriteToStderr(const char* message, size_t length) {
    HANDLE hStderr = GetStdHandle(STD_ERROR_HANDLE);
    DWORD bytesWritten;
    WriteFile(hStderr, message, (DWORD)length, &bytesWritten, NULL);
}

// Comprehensive Ingestion Entry
bool IngestStandardInput(SovereignArena* output_arena, uint8_t** out_buffer, size_t* out_size) {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin == INVALID_HANDLE_VALUE) {
        WriteToStderr("[ERROR] Invalid standard input handle.\n", 39);
        return false;
    }

    DWORD dwFileType = GetFileType(hStdin);
    dwFileType &= ~FILE_TYPE_REMOTE; // Stripping remote node flags

    // Determine absolute footprint or stream state
    bool isPipe = (dwFileType == FILE_TYPE_PIPE);
    bool isDisk = (dwFileType == FILE_TYPE_DISK);
    
    if (!isPipe && !isDisk) {
        // TTY Interactive mode detected; drop back to REPL sequence
        return false;
    }

    // Allocate an initial chunk matrix inside our Sovereign Arena
    size_t allocated_size = CLI_BUFFER_CHUNK_SIZE * 4;
    uint8_t* dynamic_buffer = (uint8_t*)ArenaAlloc(output_arena, allocated_size);
    size_t total_bytes_read = 0;

    uint8_t chunk_scratch[CLI_BUFFER_CHUNK_SIZE];
    DWORD bytes_read_this_pass = 0;
    
    // UTF-8 residue state tracking for mid-boundary code splits
    uint8_t residue_buffer[4];
    size_t residue_count = 0;

    while (true) {
        if (isPipe) {
            DWORD bytes_available = 0;
            // Check kernel-side pipe buffer layout before committing to a read
            if (!PeekNamedPipe(hStdin, NULL, 0, NULL, &bytes_available, NULL)) {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE) {
                    break; // Cleaner EOF sequence from sending process
                }
                WriteToStderr("[ERROR] Stdin pipe validation fault.\n", 37);
                return false;
            }

            if (bytes_available == 0) {
                // Yield the execution quantum slightly to prevent thread thrashing
                Sleep(1);
                continue;
            }
        }

        // Execute raw Win32 read operation
        BOOL read_success = ReadFile(
            hStdin, 
            chunk_scratch, 
            CLI_BUFFER_CHUNK_SIZE, 
            &bytes_read_this_pass, 
            NULL
        );

        if (!read_success) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE) {
                break; // Canonical pipe teardown closure
            }
            WriteToStderr("[ERROR] Unrecoverable ReadFile kernel exception.\n", 49);
            return false;
        }

        if (bytes_read_this_pass == 0) {
            break; // Standard EOF termination
        }

        // Dynamically resize arena tracking space if we run up against boundaries
        if (total_bytes_read + bytes_read_this_pass > allocated_size) {
            size_t next_allocation = allocated_size * 2;
            uint8_t* expanded_arena_space = (uint8_t*)ArenaAlloc(output_arena, next_allocation);
            if (!expanded_arena_space) {
                WriteToStderr("[FATAL] Sovereign Arena OOM on CLI buffer ingestion.\n", 53);
                return false;
            }
            // Copy older state into current progressive arena slice
            MoveMemory(expanded_arena_space, dynamic_buffer, total_bytes_read);
            dynamic_buffer = expanded_arena_space;
            allocated_size = next_allocation;
        }

        // Move scratch space memory chunks into stable arena tracking
        MoveMemory(dynamic_buffer + total_bytes_read, chunk_scratch, bytes_read_this_pass);
        total_bytes_read += bytes_read_this_pass;
    }

    *out_buffer = dynamic_buffer;
    *out_size = total_bytes_read;
    return true;
}

// Console mode preservation for TTY handling
static DWORD g_dwOriginalConsoleMode = 0;
static BOOL g_bConsoleModeCaptured = FALSE;

void CaptureConsoleMode() {
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hStdin != INVALID_HANDLE_VALUE) {
        GetConsoleMode(hStdin, &g_dwOriginalConsoleMode);
        g_bConsoleModeCaptured = TRUE;
    }
}

void RestoreConsoleMode() {
    if (g_bConsoleModeCaptured) {
        HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
        if (hStdin != INVALID_HANDLE_VALUE) {
            SetConsoleMode(hStdin, g_dwOriginalConsoleMode);
        }
    }
}

// Exception-safe wrapper
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_BREAK_EVENT) {
        RestoreConsoleMode();
        return TRUE;
    }
    return FALSE;
}

// Entry point for CLI headless mode
extern "C" int RawrXD_CliHeadlessEntry() {
    // Set up console mode restoration on exit
    CaptureConsoleMode();
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);
    
    // Initialize Sovereign Arena for CLI buffer (64KB)
    static uint8_t arena_storage[65536];
    SovereignArena arena = {
        arena_storage,
        sizeof(arena_storage),
        0
    };
    
    uint8_t* buffer = nullptr;
    size_t size = 0;
    
    // Attempt pipe/disk ingestion
    if (IngestStandardInput(&arena, &buffer, &size)) {
        // Success - buffer contains piped data
        // TODO: Pass to transformer inference
        WriteToStderr("[INFO] Pipe ingestion complete: ", 32);
        char size_buf[32];
        size_t len = 0;
        // Simple itoa for size
        size_t temp = size;
        do {
            size_buf[len++] = '0' + (temp % 10);
            temp /= 10;
        } while (temp > 0);
        // Reverse
        for (size_t i = 0; i < len / 2; i++) {
            char t = size_buf[i];
            size_buf[i] = size_buf[len - 1 - i];
            size_buf[len - 1 - i] = t;
        }
        size_buf[len++] = ' ';
        size_buf[len++] = 'b';
        size_buf[len++] = 'y';
        size_buf[len++] = 't';
        size_buf[len++] = 'e';
        size_buf[len++] = 's';
        size_buf[len++] = '\n';
        WriteToStderr(size_buf, len);
        
        // Output clean payload to stdout
        HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD written;
        WriteFile(hStdout, buffer, (DWORD)size, &written, NULL);
        
        RestoreConsoleMode();
        return 0;
    } else {
        // TTY mode - REPL will handle
        WriteToStderr("[INFO] TTY mode detected - launching REPL...\n", 45);
        RestoreConsoleMode();
        return 1; // Signal REPL mode
    }
}
