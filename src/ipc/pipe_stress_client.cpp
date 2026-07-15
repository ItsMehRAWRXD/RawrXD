// ============================================================================
// Named Pipe IPC Multi-Client Stress Test
// Spawns concurrent clients to hammer the pipe server
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <process.h>

#define NUM_CLIENTS 10
#define ITERATIONS_PER_CLIENT 100
#define PIPE_NAME L"\\\\.\\pipe\\rawrxd_hotpatch"

// Statistics
volatile LONG g_SuccessCount = 0;
volatile LONG g_FailCount = 0;
volatile LONG g_TotalBytes = 0;

// Hotpatch payload
#pragma pack(push, 1)
struct HotpatchPayload {
    uint32_t magic;
    uint32_t version;
    uint32_t payloadSize;
    uint32_t flags;
    uint64_t timestamp;
    uint32_t crc32;
    uint8_t data[64];
};
#pragma pack(pop)

#define HOTPATCH_MAGIC 0x52485044

DWORD WINAPI ClientThread(LPVOID param) {
    int clientId = (int)(size_t)param;
    
    for (int i = 0; i < ITERATIONS_PER_CLIENT; i++) {
        // Connect to pipe
        HANDLE hPipe = CreateFileW(
            PIPE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, 0, NULL
        );
        
        if (hPipe == INVALID_HANDLE_VALUE) {
            InterlockedIncrement(&g_FailCount);
            Sleep(10);
            continue;
        }
        
        // Set message mode
        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(hPipe, &mode, NULL, NULL);
        
        // Build payload
        HotpatchPayload payload = {0};
        payload.magic = HOTPATCH_MAGIC;
        payload.version = 1;
        payload.payloadSize = 64;
        payload.flags = clientId;
        payload.timestamp = GetTickCount64();
        
        sprintf_s((char*)payload.data, 64, "Client%d_Iter%d", clientId, i);
        
        // Send
        DWORD written;
        BOOL ok = WriteFile(hPipe, &payload, sizeof(payload), &written, NULL);
        
        if (ok && written == sizeof(payload)) {
            InterlockedIncrement(&g_SuccessCount);
            InterlockedAdd(&g_TotalBytes, written);
        } else {
            InterlockedIncrement(&g_FailCount);
        }
        
        CloseHandle(hPipe);
        
        // Small delay to allow interleaving
        if (i % 10 == 0) Sleep(1);
    }
    
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    (void)argc; (void)argv;
    
    wprintf(L"================================================================================\n");
    wprintf(L"Named Pipe IPC Multi-Client Stress Test\n");
    wprintf(L"================================================================================\n");
    wprintf(L"Clients: %d, Iterations per client: %d\n\n", NUM_CLIENTS, ITERATIONS_PER_CLIENT);
    
    HANDLE threads[NUM_CLIENTS];
    DWORD startTime = GetTickCount();
    
    // Spawn all clients
    for (int i = 0; i < NUM_CLIENTS; i++) {
        threads[i] = CreateThread(NULL, 0, ClientThread, (LPVOID)(size_t)i, 0, NULL);
    }
    
    // Wait for completion
    WaitForMultipleObjects(NUM_CLIENTS, threads, TRUE, 60000);
    
    DWORD elapsed = GetTickCount() - startTime;
    
    // Cleanup
    for (int i = 0; i < NUM_CLIENTS; i++) {
        CloseHandle(threads[i]);
    }
    
    // Results
    wprintf(L"\n================================================================================\n");
    wprintf(L"Stress Test Complete\n");
    wprintf(L"================================================================================\n");
    wprintf(L"Successful: %ld\n", g_SuccessCount);
    wprintf(L"Failed: %ld\n", g_FailCount);
    wprintf(L"Total bytes: %ld\n", g_TotalBytes);
    wprintf(L"Elapsed: %lu ms\n", elapsed);
    wprintf(L"Throughput: %.2f payloads/sec\n", (g_SuccessCount * 1000.0) / elapsed);
    wprintf(L"================================================================================\n");
    
    return (g_FailCount == 0) ? 0 : 1;
}
