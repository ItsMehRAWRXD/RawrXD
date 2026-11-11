// ============================================================================
// RawrXD Pipe Server Integration
// Multi-instance named pipe server with hotpatch router integration
// ============================================================================

#include "rawrxd_pipe_server.h"
#include <sddl.h>
#include <stdio.h>
#include <string.h>

// External ASM exports from hotpatch router
extern "C" {
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, void* gpuFence);
    uint64_t RawrXD_CheckEpochSwap(void);
    uint64_t RawrXD_WaitForHotpatchComplete(uint32_t timeoutMs);
    uint64_t RawrXD_InitHotpatchSystem(void);
    uint64_t RawrXD_ForceSyncHotpatch(void* modelDescriptor);
    
    extern volatile uint64_t g_EpochCounter;
    extern volatile uint64_t g_HotpatchCount;
}

// Hotpatch payload structure
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

#define HOTPATCH_MAGIC 0x52485044
#define HOTPATCH_VERSION 1
#define PIPE_NAME L"\\\\.\\pipe\\rawrxd_hotpatch"
#define PIPE_BUFFER_SIZE 65536
#define MAX_PIPE_INSTANCES 4  // Sweet spot for hotpatch server

// Per-instance state
struct PipeInstance {
    HANDLE hPipe;
    OVERLAPPED overlapped;
    HANDLE hEvent;
    BOOL pendingIO;
    uint8_t buffer[PIPE_BUFFER_SIZE];
    DWORD bytesRead;
    BOOL connected;
    int instanceId;
};

// Server state
static struct {
    PipeInstance instances[MAX_PIPE_INSTANCES];
    HANDLE hThreads[MAX_PIPE_INSTANCES];
    volatile BOOL running;
    volatile BOOL initialized;
    SECURITY_ATTRIBUTES securityAttr;
    PSECURITY_DESCRIPTOR securityDesc;
    uint64_t totalReceived;
    uint64_t totalProcessed;
    CRITICAL_SECTION statsLock;
} g_Server = {0};

// Security descriptor for cross-integrity access
static const wchar_t* g_SDString = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";

// Forward declarations
static DWORD WINAPI InstanceThread(LPVOID param);
static BOOL CreatePipeInstance(PipeInstance* inst, int id);
static void ClosePipeInstance(PipeInstance* inst);
static BOOL ProcessHotpatchPayload(const uint8_t* data, DWORD len);

// ============================================================================
// Initialize Security
// ============================================================================
static BOOL InitSecurity(void) {
    if (g_Server.securityDesc) return TRUE; // Already initialized
    
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            g_SDString, SDDL_REVISION_1, &g_Server.securityDesc, NULL)) {
        fprintf(stderr, "[PipeServer] Security init failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    g_Server.securityAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    g_Server.securityAttr.lpSecurityDescriptor = g_Server.securityDesc;
    g_Server.securityAttr.bInheritHandle = FALSE;
    
    return TRUE;
}

static void CleanupSecurity(void) {
    if (g_Server.securityDesc) {
        LocalFree(g_Server.securityDesc);
        g_Server.securityDesc = NULL;
    }
}

// ============================================================================
// Initialize Pipe Server
// ============================================================================
BOOL RawrXD_PipeServer_Init(void) {
    if (g_Server.initialized) return TRUE;
    if (g_Server.running) return TRUE;
    
    fprintf(stderr, "[PipeServer] Initializing hotpatch IPC server...\n");
    
    // Initialize hotpatch system first
    uint64_t initResult = RawrXD_InitHotpatchSystem();
    if (initResult != 0) {
        fprintf(stderr, "[PipeServer] Hotpatch system init failed: %llu\n", initResult);
        return FALSE;
    }
    
    // Initialize security
    if (!InitSecurity()) {
        return FALSE;
    }
    
    // Initialize critical section for stats
    InitializeCriticalSection(&g_Server.statsLock);
    
    // Create all instances
    g_Server.running = TRUE;
    
    for (int i = 0; i < MAX_PIPE_INSTANCES; i++) {
        ZeroMemory(&g_Server.instances[i], sizeof(PipeInstance));
        g_Server.instances[i].instanceId = i;
        g_Server.instances[i].overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        g_Server.instances[i].hEvent = g_Server.instances[i].overlapped.hEvent;
        
        if (!g_Server.instances[i].hEvent) {
            fprintf(stderr, "[PipeServer] Failed to create event for instance %d\n", i);
            goto cleanup;
        }
        
        if (!CreatePipeInstance(&g_Server.instances[i], i)) {
            fprintf(stderr, "[PipeServer] Failed to create instance %d\n", i);
            goto cleanup;
        }
        
        // Start thread for this instance
        g_Server.hThreads[i] = CreateThread(NULL, 0, InstanceThread, &g_Server.instances[i], 0, NULL);
        if (!g_Server.hThreads[i]) {
            fprintf(stderr, "[PipeServer] Failed to create thread %d\n", i);
            goto cleanup;
        }
    }
    
    g_Server.initialized = TRUE;
    fprintf(stderr, "[PipeServer] %d instances ready: %S\n", MAX_PIPE_INSTANCES, PIPE_NAME);
    return TRUE;
    
cleanup:
    RawrXD_PipeServer_Shutdown();
    return FALSE;
}

// ============================================================================
// Create Pipe Instance
// ============================================================================
static BOOL CreatePipeInstance(PipeInstance* inst, int id) {
    (void)id;
    inst->hPipe = CreateNamedPipeW(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        MAX_PIPE_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        &g_Server.securityAttr
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
static DWORD WINAPI InstanceThread(LPVOID param) {
    PipeInstance* inst = (PipeInstance*)param;
    DWORD bytesTransferred;
    BOOL success;
    
    fprintf(stderr, "[PipeServer] Instance %d thread started\n", inst->instanceId);
    
    while (g_Server.running) {
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
                fprintf(stderr, "[PipeServer] Instance %d: ConnectNamedPipe failed: %lu\n", 
                        inst->instanceId, err);
                Sleep(100);
                continue;
            }
        }
        
        // Wait for I/O completion
        if (inst->pendingIO) {
            DWORD waitResult = WaitForSingleObject(inst->hEvent, 100);
            if (!g_Server.running) break;
            if (waitResult != WAIT_OBJECT_0) continue;
            
            success = GetOverlappedResult(inst->hPipe, &inst->overlapped, &bytesTransferred, FALSE);
            inst->pendingIO = FALSE;
            
            if (!success) {
                DWORD err = GetLastError();
                if (err == ERROR_BROKEN_PIPE || err == ERROR_PIPE_NOT_CONNECTED) {
                    DisconnectNamedPipe(inst->hPipe);
                    inst->connected = FALSE;
                    continue;
                }
                fprintf(stderr, "[PipeServer] Instance %d: GetOverlappedResult failed: %lu\n", 
                        inst->instanceId, err);
                continue;
            }
            
            if (!inst->connected) {
                inst->connected = TRUE;
                fprintf(stderr, "[PipeServer] Instance %d: Client connected\n", inst->instanceId);
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
                    fprintf(stderr, "[PipeServer] Instance %d: Client disconnected\n", inst->instanceId);
                    DisconnectNamedPipe(inst->hPipe);
                    inst->connected = FALSE;
                }
                continue;
            }
            
            // Process received data
            if (inst->bytesRead > 0) {
                EnterCriticalSection(&g_Server.statsLock);
                g_Server.totalReceived++;
                LeaveCriticalSection(&g_Server.statsLock);
                
                if (ProcessHotpatchPayload(inst->buffer, inst->bytesRead)) {
                    EnterCriticalSection(&g_Server.statsLock);
                    g_Server.totalProcessed++;
                    LeaveCriticalSection(&g_Server.statsLock);
                }
            }
        }
    }
    
    fprintf(stderr, "[PipeServer] Instance %d thread exiting\n", inst->instanceId);
    return 0;
}

// ============================================================================
// Process Hotpatch Payload
// ============================================================================
static BOOL ProcessHotpatchPayload(const uint8_t* data, DWORD len) {
    if (len < sizeof(HotpatchPayload)) {
        fprintf(stderr, "[PipeServer] Payload too small: %lu\n", len);
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
    
    fprintf(stderr, "[PipeServer] Hotpatch: %u bytes, flags=0x%08X\n",
            payload->payloadSize, payload->flags);
    
    // Create model descriptor from payload
    struct alignas(64) ModelDescriptor {
        uint64_t magic;
        uint64_t version;
        uint64_t modelId;
        uint64_t weightsPtr;
        uint64_t weightsSize;
        uint64_t metadataPtr;
        uint32_t metadataSize;
        uint32_t flags;
        uint64_t reserved[4];
    };
    
    static ModelDescriptor desc = {};
    desc.magic = 0x524157524D444C00ULL;  // "RAWRMDL\0"
    desc.version = payload->version;
    desc.modelId = payload->timestamp;
    desc.flags = payload->flags;
    desc.metadataPtr = (uint64_t)payload->data;
    desc.metadataSize = payload->payloadSize;
    
    // Request hotpatch through ASM router
    uint64_t result = RawrXD_RequestHotpatch(&desc, nullptr);
    
    switch (result) {
        case 0:
            fprintf(stderr, "[PipeServer] Hotpatch requested successfully\n");
            break;
        case 1:
            fprintf(stderr, "[PipeServer] Hotpatch already pending\n");
            return FALSE;
        case 2:
            fprintf(stderr, "[PipeServer] Inference active, hotpatch deferred\n");
            return FALSE;
        default:
            fprintf(stderr, "[PipeServer] Unknown error: %llu\n", result);
            return FALSE;
    }
    
    // Wait for completion
    uint64_t waitResult = RawrXD_WaitForHotpatchComplete(5000);
    if (waitResult == 0) {
        fprintf(stderr, "[PipeServer] Hotpatch completed. Epoch: %llu, Count: %llu\n",
                g_EpochCounter, g_HotpatchCount);
        return TRUE;
    } else {
        fprintf(stderr, "[PipeServer] Hotpatch timeout\n");
        return FALSE;
    }
}

// ============================================================================
// Shutdown
// ============================================================================
void RawrXD_PipeServer_Shutdown(void) {
    if (!g_Server.running && !g_Server.initialized) return;
    
    fprintf(stderr, "[PipeServer] Shutting down...\n");
    g_Server.running = FALSE;
    
    // Cancel all pending I/O
    for (int i = 0; i < MAX_PIPE_INSTANCES; i++) {
        if (g_Server.instances[i].hPipe != INVALID_HANDLE_VALUE) {
            CancelIoEx(g_Server.instances[i].hPipe, &g_Server.instances[i].overlapped);
        }
        if (g_Server.instances[i].hEvent) {
            SetEvent(g_Server.instances[i].hEvent);
        }
    }
    
    // Wait for threads
    WaitForMultipleObjects(MAX_PIPE_INSTANCES, g_Server.hThreads, TRUE, 5000);
    
    // Cleanup
    for (int i = 0; i < MAX_PIPE_INSTANCES; i++) {
        if (g_Server.hThreads[i]) CloseHandle(g_Server.hThreads[i]);
        if (g_Server.instances[i].hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_Server.instances[i].hPipe);
        }
        if (g_Server.instances[i].hEvent) CloseHandle(g_Server.instances[i].hEvent);
    }
    
    DeleteCriticalSection(&g_Server.statsLock);
    CleanupSecurity();
    
    g_Server.initialized = FALSE;
    fprintf(stderr, "[PipeServer] Shutdown complete\n");
}

// ============================================================================
// Public API
// ============================================================================
BOOL RawrXD_PipeServer_IsRunning(void) {
    return g_Server.running;
}

BOOL RawrXD_PipeServer_ProcessPayload(const uint8_t* data, DWORD len) {
    return ProcessHotpatchPayload(data, len);
}

void RawrXD_PipeServer_GetStats(uint64_t* totalReceived, uint64_t* totalProcessed) {
    EnterCriticalSection(&g_Server.statsLock);
    if (totalReceived) *totalReceived = g_Server.totalReceived;
    if (totalProcessed) *totalProcessed = g_Server.totalProcessed;
    LeaveCriticalSection(&g_Server.statsLock);
}
