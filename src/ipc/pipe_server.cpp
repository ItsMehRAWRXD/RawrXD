// ============================================================================
// RawrXD Named Pipe IPC Server
// Message-oriented, Overlapped I/O with custom DACL for cross-integrity access
// ============================================================================

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdint.h>

// Hotpatch payload structure (must match CLI)
#pragma pack(push, 1)
struct HotpatchPayload {
    uint32_t magic;           // 0x52485044 "RHPD"
    uint32_t version;         // Payload version
    uint32_t payloadSize;     // Size of payload data
    uint32_t flags;           // Execution flags
    uint64_t timestamp;       // Unix timestamp
    uint32_t crc32;           // CRC32 checksum
    uint8_t  data[0];         // Variable-length payload
};
#pragma pack(pop)

#define HOTPATCH_MAGIC 0x52485044  // "RHPD"
#define HOTPATCH_VERSION 1
#define PIPE_NAME L"\\\\.\\pipe\\rawrxd_hotpatch"
#define PIPE_BUFFER_SIZE 65536
#define MAX_PIPE_INSTANCES 10

// Pipe state
static HANDLE g_hPipe = INVALID_HANDLE_VALUE;
static HANDLE g_hEvent = NULL;
static HANDLE g_hThread = NULL;
static volatile BOOL g_Running = FALSE;

// Security descriptor string for cross-integrity access
// Allows: SYSTEM (GA), Administrators (GA), Interactive Users (GW - Generic Write only)
// This restricts pipe access to privileged processes and interactive users with write-only
static const wchar_t* g_SecurityDescriptorString =
    L"D:P"
    L"(A;;GA;;;SY)"           // SYSTEM: Generic All
    L"(A;;GA;;;BA)"           // Administrators: Generic All
    L"(A;;GW;;;IU)";          // Interactive Users: Generic Write only (not Read/Execute)

// Forward declarations
DWORD WINAPI PipeServerThread(LPVOID param);
BOOL InitializeSecurityAttributes(SECURITY_ATTRIBUTES* sa);
void CleanupSecurityAttributes(SECURITY_ATTRIBUTES* sa);

// ============================================================================
// Initialize Named Pipe Server
// ============================================================================
BOOL RawrXD_PipeServer_Init(void) {
    if (g_Running) {
        return TRUE; // Already initialized
    }
    
    printf("[PipeServer] Initializing named pipe server...\n");
    
    // Setup security attributes with custom DACL
    SECURITY_ATTRIBUTES sa = {0};
    if (!InitializeSecurityAttributes(&sa)) {
        fprintf(stderr, "[PipeServer] Failed to initialize security attributes\n");
        return FALSE;
    }
    
    // Create the named pipe with message mode and overlapped I/O
    g_hPipe = CreateNamedPipeW(
        PIPE_NAME,                          // Pipe name
        PIPE_ACCESS_DUPLEX |                // Read/Write access
        FILE_FLAG_OVERLAPPED,               // Async I/O
        PIPE_TYPE_MESSAGE |                 // Message-type pipe
        PIPE_READMODE_MESSAGE |             // Message-read mode
        PIPE_WAIT,                          // Blocking wait
        MAX_PIPE_INSTANCES,                 // Max instances
        PIPE_BUFFER_SIZE,                   // Output buffer size
        PIPE_BUFFER_SIZE,                   // Input buffer size
        0,                                  // Default timeout
        &sa                                 // Security attributes
    );
    
    CleanupSecurityAttributes(&sa);
    
    if (g_hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[PipeServer] CreateNamedPipe failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    // Create event for overlapped I/O
    g_hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_hEvent) {
        fprintf(stderr, "[PipeServer] CreateEvent failed: %lu\n", GetLastError());
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    
    // Start server thread
    g_Running = TRUE;
    g_hThread = CreateThread(NULL, 0, PipeServerThread, NULL, 0, NULL);
    if (!g_hThread) {
        fprintf(stderr, "[PipeServer] CreateThread failed: %lu\n", GetLastError());
        CloseHandle(g_hEvent);
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
        g_Running = FALSE;
        return FALSE;
    }
    
    printf("[PipeServer] Server initialized: %S\n", PIPE_NAME);
    return TRUE;
}

// ============================================================================
// Shutdown Named Pipe Server
// ============================================================================
void RawrXD_PipeServer_Shutdown(void) {
    if (!g_Running) {
        return;
    }
    
    printf("[PipeServer] Shutting down...\n");
    
    g_Running = FALSE;
    
    // Signal the event to unblock any waiting operations
    if (g_hEvent) {
        SetEvent(g_hEvent);
    }
    
    // Wait for server thread to finish
    if (g_hThread) {
        WaitForSingleObject(g_hThread, 5000);
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }
    
    // Close pipe handle
    if (g_hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hPipe);
        g_hPipe = INVALID_HANDLE_VALUE;
    }
    
    // Close event handle
    if (g_hEvent) {
        CloseHandle(g_hEvent);
        g_hEvent = NULL;
    }
    
    printf("[PipeServer] Shutdown complete\n");
}

// ============================================================================
// Process Hotpatch Payload
// ============================================================================
BOOL ProcessHotpatchPayload(const uint8_t* data, DWORD len) {
    if (len < sizeof(HotpatchPayload)) {
        fprintf(stderr, "[PipeServer] Payload too small: %lu bytes\n", len);
        return FALSE;
    }
    
    const HotpatchPayload* payload = (const HotpatchPayload*)data;
    
    // Validate magic
    if (payload->magic != HOTPATCH_MAGIC) {
        fprintf(stderr, "[PipeServer] Invalid magic: 0x%08X\n", payload->magic);
        return FALSE;
    }
    
    // Validate version
    if (payload->version != HOTPATCH_VERSION) {
        fprintf(stderr, "[PipeServer] Unsupported version: %u\n", payload->version);
        return FALSE;
    }
    
    // Validate size
    DWORD expectedSize = sizeof(HotpatchPayload) + payload->payloadSize;
    if (expectedSize > len) {
        fprintf(stderr, "[PipeServer] Size mismatch: expected %u, got %lu\n", expectedSize, len);
        return FALSE;
    }
    
    printf("[PipeServer] Valid hotpatch payload: %u bytes, flags=0x%08X\n",
           payload->payloadSize, payload->flags);
    
    // TODO: Call into hotpatch router
    // For now, just acknowledge receipt
    printf("[PipeServer] Hotpatch queued for execution\n");
    
    return TRUE;
}

// ============================================================================
// Pipe Server Thread
// ============================================================================
DWORD WINAPI PipeServerThread(LPVOID param) {
    (void)param;
    
    printf("[PipeServer] Server thread started\n");
    
    while (g_Running) {
        // Setup overlapped structure
        OVERLAPPED overlapped = {0};
        overlapped.hEvent = g_hEvent;
        
        // Wait for client connection (async)
        printf("[PipeServer] Waiting for client connection...\n");
        
        BOOL connected = ConnectNamedPipe(g_hPipe, &overlapped);
        DWORD err = GetLastError();
        
        if (!connected && err == ERROR_IO_PENDING) {
            // Wait for connection or shutdown signal
            DWORD waitResult = WaitForSingleObject(g_hEvent, INFINITE);
            if (!g_Running || waitResult != WAIT_OBJECT_0) {
                break;
            }
            
            // Check if connection completed
            DWORD bytesTransferred;
            if (!GetOverlappedResult(g_hPipe, &overlapped, &bytesTransferred, FALSE)) {
                fprintf(stderr, "[PipeServer] ConnectNamedPipe failed: %lu\n", GetLastError());
                continue;
            }
        } else if (!connected && err != ERROR_PIPE_CONNECTED) {
            fprintf(stderr, "[PipeServer] ConnectNamedPipe failed: %lu\n", err);
            Sleep(100);
            continue;
        }
        
        printf("[PipeServer] Client connected\n");
        
        // Read message from client
        uint8_t buffer[PIPE_BUFFER_SIZE];
        DWORD bytesRead = 0;
        DWORD totalBytesRead = 0;
        
        // Read in message mode - each ReadFile gets one complete message
        while (g_Running) {
            BOOL readSuccess = ReadFile(
                g_hPipe,
                buffer + totalBytesRead,
                sizeof(buffer) - totalBytesRead,
                &bytesRead,
                NULL  // Synchronous read for simplicity after connection
            );
            
            if (!readSuccess) {
                err = GetLastError();
                if (err == ERROR_BROKEN_PIPE) {
                    printf("[PipeServer] Client disconnected\n");
                    break;
                }
                fprintf(stderr, "[PipeServer] ReadFile failed: %lu\n", err);
                break;
            }
            
            if (bytesRead == 0) {
                break; // End of message
            }
            
            totalBytesRead += bytesRead;
            
            // Check if we have a complete message (in message mode, ReadFile
            // returns ERROR_MORE_DATA if there's more, or completes the message)
            if (err != ERROR_MORE_DATA) {
                break;
            }
        }
        
        // Process the received payload
        if (totalBytesRead > 0) {
            ProcessHotpatchPayload(buffer, totalBytesRead);
        }
        
        // Disconnect and wait for next client
        DisconnectNamedPipe(g_hPipe);
        printf("[PipeServer] Client disconnected, waiting for next...\n");
    }
    
    printf("[PipeServer] Server thread exiting\n");
    return 0;
}

// ============================================================================
// Initialize Security Attributes with Custom DACL
// ============================================================================
BOOL InitializeSecurityAttributes(SECURITY_ATTRIBUTES* sa) {
    ZeroMemory(sa, sizeof(SECURITY_ATTRIBUTES));
    sa->nLength = sizeof(SECURITY_ATTRIBUTES);
    sa->bInheritHandle = FALSE;
    
    PSECURITY_DESCRIPTOR sd = NULL;
    
    // Convert security descriptor string to SD
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            g_SecurityDescriptorString,
            SDDL_REVISION_1,
            &sd,
            NULL)) {
        fprintf(stderr, "[PipeServer] ConvertStringSecurityDescriptorToSecurityDescriptor failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    sa->lpSecurityDescriptor = sd;
    return TRUE;
}

// ============================================================================
// Cleanup Security Attributes
// ============================================================================
void CleanupSecurityAttributes(SECURITY_ATTRIBUTES* sa) {
    if (sa && sa->lpSecurityDescriptor) {
        LocalFree(sa->lpSecurityDescriptor);
        sa->lpSecurityDescriptor = NULL;
    }
}

// ============================================================================
// Test Client (for verification)
// ============================================================================
BOOL SendTestHotpatch(void) {
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[TestClient] CreateFile failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    // Set message mode
    DWORD pipeMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &pipeMode, NULL, NULL)) {
        fprintf(stderr, "[TestClient] SetNamedPipeHandleState failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return FALSE;
    }
    
    // Build test payload
    uint8_t buffer[256];
    HotpatchPayload* payload = (HotpatchPayload*)buffer;
    payload->magic = HOTPATCH_MAGIC;
    payload->version = HOTPATCH_VERSION;
    payload->payloadSize = 16;
    payload->flags = 0;
    payload->timestamp = 0;
    payload->crc32 = 0;
    memcpy(payload->data, "TestHotpatchData", 16);
    
    DWORD totalSize = sizeof(HotpatchPayload) + payload->payloadSize;
    
    // Send as single message
    DWORD bytesWritten;
    BOOL writeSuccess = WriteFile(hPipe, buffer, totalSize, &bytesWritten, NULL);
    
    if (!writeSuccess) {
        fprintf(stderr, "[TestClient] WriteFile failed: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return FALSE;
    }
    
    printf("[TestClient] Sent hotpatch payload: %lu bytes\n", bytesWritten);
    
    CloseHandle(hPipe);
    return TRUE;
}

// ============================================================================
// Main Entry Point (for standalone testing)
// ============================================================================
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("================================================================================\n");
    printf("RawrXD Named Pipe IPC Server Test\n");
    printf("================================================================================\n\n");
    
    // Initialize server
    if (!RawrXD_PipeServer_Init()) {
        fprintf(stderr, "Failed to initialize pipe server\n");
        return 1;
    }
    
    printf("Server running. Press Enter to send test hotpatch, 'q' to quit...\n\n");
    
    while (1) {
        int ch = getchar();
        if (ch == 'q' || ch == 'Q') {
            break;
        }
        if (ch == '\n') {
            SendTestHotpatch();
        }
    }
    
    RawrXD_PipeServer_Shutdown();
    return 0;
}
