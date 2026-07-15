// ============================================================================
// RawrXD Named Pipe IPC Server - Multi-Instance Version
// Supports concurrent clients with proper instance pooling
// ============================================================================

#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdint.h>

// Hotpatch payload
#pragma pack(push, 1)
struct HotpatchPayload {
    uint32_t magic;
    uint32_t version;
    uint32_t payloadSize;
    uint32_t flags;
    uint64_t timestamp;
    uint32_t crc32;
    uint8_t  data[0];
};
#pragma pack(pop)

#define HOTPATCH_MAGIC 0x52485044
#define PIPE_NAME L"\\\\.\\pipe\\rawrxd_hotpatch"
#define PIPE_BUFFER_SIZE 65536
#define MAX_PIPE_INSTANCES 10

// Per-instance state
struct PipeInstance {
    HANDLE hPipe;
    OVERLAPPED overlapped;
    HANDLE hEvent;
    BOOL pendingIO;
    uint8_t buffer[PIPE_BUFFER_SIZE];
    DWORD bytesRead;
    BOOL connected;
};

static PipeInstance g_Instances[MAX_PIPE_INSTANCES];
static volatile BOOL g_Running = FALSE;
static HANDLE g_hThreads[MAX_PIPE_INSTANCES];
static SECURITY_ATTRIBUTES g_SecurityAttr = {0};
static PSECURITY_DESCRIPTOR g_SecurityDesc = NULL;

// Security descriptor for cross-integrity access
static const wchar_t* g_SDString = 
    L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";

// Forward declarations
DWORD WINAPI InstanceThread(LPVOID param);
BOOL InitSecurity(void);
void CleanupSecurity(void);
BOOL CreatePipeInstance(PipeInstance* inst);
void ClosePipeInstance(PipeInstance* inst);
BOOL ProcessPayload(const uint8_t* data, DWORD len);

// ============================================================================
// Initialize Security
// ============================================================================
BOOL InitSecurity(void) {
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        g_SDString, SDDL_REVISION_1, &g_SecurityDesc, NULL);
}

void CleanupSecurity(void) {
    if (g_SecurityDesc) {
        LocalFree(g_SecurityDesc);
        g_SecurityDesc = NULL;
    }
}

// ============================================================================
// Initialize Server
// ============================================================================
BOOL RawrXD_PipeServer_Init(void) {
    if (g_Running) return TRUE;
    
    printf("[PipeServer] Initializing multi-instance server...\n");
    
    if (!InitSecurity()) {
        fprintf(stderr, "[PipeServer] Security init failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    g_SecurityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    g_SecurityAttr.lpSecurityDescriptor = g_SecurityDesc;
    g_SecurityAttr.bInheritHandle = FALSE;
    
    // Create all instances
    for (int i = 0; i < MAX_PIPE_INSTANCES; i++) {
        ZeroMemory(&g_Instances[i], sizeof(PipeInstance));
        g_Instances[i].overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        g_Instances[i].hEvent = g_Instances[i].overlapped.hEvent;
        
        if (!CreatePipeInstance(&g_Instances[i])) {
            fprintf(stderr, "[PipeServer] Failed to create instance %d\n", i);
            return FALSE;
        }
        
        // Start thread for this instance
        g_hThreads[i] = CreateThread(NULL, 0, InstanceThread, &g_Instances[i], 0, NULL);
        if (!g_hThreads[i]) {
            fprintf(stderr, "[PipeServer] Failed to create thread %d\n", i);
            return FALSE;
        }
    }
    
    g_Running = TRUE;
    printf("[PipeServer] %d instances ready: %S\n", MAX_PIPE_INSTANCES, PIPE_NAME);
    return TRUE;
}

// ============================================================================
// Create Pipe Instance
// ============================================================================
BOOL CreatePipeInstance(PipeInstance* inst) {
    inst->hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        MAX_PIPE_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        &g_SecurityAttr
    );
    
    if (inst->hPipe == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[PipeServer] CreateNamedPipe failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    inst->connected = FALSE;
    inst->pendingIO = FALSE;
    return TRUE;
}

// ============================================================================
// Instance Thread
// ============================================================================
DWORD WINAPI InstanceThread(LPVOID param) {
    PipeInstance* inst = (PipeInstance*)param;
    DWORD bytesTransferred;
    BOOL success;
    
    printf("[PipeServer] Instance thread started\n");
    
    while (g_Running) {
        // Wait for connection
        if (!inst->connected && !inst->pendingIO) {
            success = ConnectNamedPipe(inst->hPipe, &inst->overlapped);
            DWORD err = GetLastError();
            
            if (!success && err == ERROR_IO_PENDING) {
                inst->pendingIO = TRUE;
            } else if (!success && err == ERROR_PIPE_CONNECTED) {
                inst->connected = TRUE;
                inst->pendingIO = FALSE;
            } else if (!success) {
                fprintf(stderr, "[PipeServer] ConnectNamedPipe failed: %lu\n", err);
                Sleep(100);
                continue;
            }
        }
        
        // Wait for I/O completion
        if (inst->pendingIO) {
            DWORD waitResult = WaitForSingleObject(inst->hEvent, 100);
            if (!g_Running) break;
            if (waitResult != WAIT_OBJECT_0) continue;
            
            success = GetOverlappedResult(inst->hPipe, &inst->overlapped, &bytesTransferred, FALSE);
            inst->pendingIO = FALSE;
            
            if (!success) {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                    // Client disconnected, reset and wait for new connection
                    DisconnectNamedPipe(inst->hPipe);
                    inst->connected = FALSE;
                    continue;
                }
                fprintf(stderr, "[PipeServer] GetOverlappedResult failed: %lu\n", err);
                continue;
            }
            
            if (!inst->connected) {
                inst->connected = TRUE;
                printf("[PipeServer] Client connected\n");
            }
        }
        
        // Read message
        if (inst->connected) {
            inst->bytesRead = 0;
            success = ReadFile(inst->hPipe, inst->buffer, sizeof(inst->buffer), 
                              &inst->bytesRead, &inst->overlapped);
            
            if (!success && GetLastError() == ERROR_IO_PENDING) {
                inst->pendingIO = TRUE;
                continue;
            }
            
            if (!success) {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE) {
                    printf("[PipeServer] Client disconnected\n");
                    DisconnectNamedPipe(inst->hPipe);
                    inst->connected = FALSE;
                }
                continue;
            }
            
            // Process received data
            if (inst->bytesRead > 0) {
                ProcessPayload(inst->buffer, inst->bytesRead);
            }
        }
    }
    
    return 0;
}

// ============================================================================
// Process Payload
// ============================================================================
BOOL ProcessPayload(const uint8_t* data, DWORD len) {
    if (len < sizeof(HotpatchPayload)) {
        fprintf(stderr, "[PipeServer] Payload too small: %lu\n", len);
        return FALSE;
    }
    
    const HotpatchPayload* payload = (const HotpatchPayload*)data;
    
    if (payload->magic != HOTPATCH_MAGIC) {
        fprintf(stderr, "[PipeServer] Invalid magic: 0x%08X\n", payload->magic);
        return FALSE;
    }
    
    printf("[PipeServer] Hotpatch: %u bytes, flags=0x%08X\n",
           payload->payloadSize, payload->flags);
    return TRUE;
}

// ============================================================================
// Shutdown
// ============================================================================
void RawrXD_PipeServer_Shutdown(void) {
    if (!g_Running) return;
    
    printf("[PipeServer] Shutting down...\n");
    g_Running = FALSE;
    
    // Signal all events
    for (int i = 0; i < MAX_PIPE_INSTANCES; i++) {
        if (g_Instances[i].hEvent) {
            SetEvent(g_Instances[i].hEvent);
        }
    }
    
    // Wait for threads
    WaitForMultipleObjects(MAX_PIPE_INSTANCES, g_hThreads, TRUE, 5000);
    
    // Cleanup
    for (int i = 0; i < MAX_PIPE_INSTANCES; i++) {
        if (g_hThreads[i]) CloseHandle(g_hThreads[i]);
        if (g_Instances[i].hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_Instances[i].hPipe);
        }
        if (g_Instances[i].hEvent) CloseHandle(g_Instances[i].hEvent);
    }
    
    CleanupSecurity();
    printf("[PipeServer] Shutdown complete\n");
}

// ============================================================================
// Main (for testing)
// ============================================================================
int main(int argc, char* argv[]) {
    (void)argc; (void)argv;
    
    printf("================================================================================\n");
    printf("RawrXD Multi-Instance Named Pipe Server\n");
    printf("================================================================================\n\n");
    
    if (!RawrXD_PipeServer_Init()) {
        fprintf(stderr, "Failed to initialize\n");
        return 1;
    }
    
    printf("Server running. Press Enter to quit...\n");
    getchar();
    
    RawrXD_PipeServer_Shutdown();
    return 0;
}
