/*===========================================================================
 * SovereignRuntimeTestClient.cpp
 * Test client for shared memory runtime
 *===========================================================================*/

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "SovereignSharedMemoryServer.hpp"

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Sovereign Runtime Test Client\n");
    printf("========================================\n\n");
    
    // Open shared memory
    HANDLE hSharedMem = OpenFileMappingW(
        FILE_MAP_ALL_ACCESS,
        FALSE,
        L"RawrXD_SharedMem_Alpha"
    );
    
    if (!hSharedMem) {
        printf("ERROR: Failed to open shared memory (0x%08X)\n", GetLastError());
        printf("Make sure SovereignRuntime.exe is running first!\n");
        return 1;
    }
    
    printf("[Client] Connected to shared memory\n");
    
    // Map view
    RawrXD::Runtime::SovereignSharedBlock* pBlock = 
        (RawrXD::Runtime::SovereignSharedBlock*)MapViewOfFile(
            hSharedMem,
            FILE_MAP_ALL_ACCESS,
            0, 0,
            sizeof(RawrXD::Runtime::SovereignSharedBlock)
        );
    
    if (!pBlock) {
        printf("ERROR: Failed to map view\n");
        CloseHandle(hSharedMem);
        return 1;
    }
    
    // Open events
    HANDLE hRequestEvent = OpenEventW(EVENT_MODIFY_STATE | SYNCHRONIZE, 
                                       FALSE, L"RawrXD_RequestEvent");
    HANDLE hResponseEvent = OpenEventW(SYNCHRONIZE, FALSE, L"RawrXD_ResponseEvent");
    
    if (!hRequestEvent || !hResponseEvent) {
        printf("ERROR: Failed to open events\n");
        return 1;
    }
    
    printf("[Client] Events opened\n");
    printf("[Client] Ready to send requests\n\n");
    
    // Test loop
    int testNum = 1;
    while (testNum <= 3) {
        printf("--- Test %d ---\n", testNum);
        
        // Prepare request
        RawrXD::Runtime::SovereignRequest req = {};
        req.requestId = testNum;
        req.timestamp = GetTickCount64();
        req.maxTokens = 32;
        req.temperature = 0.7f;
        req.topP = 0.9f;
        req.topK = 40;
        req.stream = FALSE;
        
        snprintf(req.prompt, sizeof(req.prompt), 
                "Test prompt number %d: Hello, world!", testNum);
        
        // Wait for any pending request
        int retries = 1000;
        while (pBlock->requestReady.load() == 1 && retries-- > 0) {
            Sleep(1);
        }
        
        if (pBlock->requestReady.load() == 1) {
            printf("  ERROR: Request slot busy\n");
            Sleep(100);
            continue;
        }
        
        // Submit request
        printf("  Sending: '%s'\n", req.prompt);
        pBlock->request = req;
        pBlock->requestReady.store(1);
        
        // Signal runtime
        SetEvent(hRequestEvent);
        
        // Wait for response
        printf("  Waiting for response...\n");
        DWORD waitResult = WaitForSingleObject(hResponseEvent, 5000);
        
        if (waitResult == WAIT_OBJECT_0) {
            if (pBlock->responseReady.load() == 1) {
                auto& resp = pBlock->response;
                printf("  Response received:\n");
                printf("    Request ID: %llu\n", resp.requestId);
                printf("    Status: %d\n", resp.status);
                printf("    Tokens: %u\n", resp.tokenCount);
                printf("    Latency: %u ms\n", resp.latencyMs);
                printf("    TPS: %.1f\n", resp.tps);
                printf("    Text: '%s'\n", resp.text);
                
                // Mark consumed
                pBlock->responseReady.store(0);
            } else {
                printf("  ERROR: Response event signaled but not ready\n");
            }
        } else if (waitResult == WAIT_TIMEOUT) {
            printf("  ERROR: Timeout waiting for response\n");
        } else {
            printf("  ERROR: Wait failed (0x%08X)\n", waitResult);
        }
        
        printf("\n");
        testNum++;
        Sleep(100);  // Brief pause between tests
    }
    
    // Print final stats
    printf("=== Final Statistics ===\n");
    printf("Requests Received:  %llu\n", pBlock->stats.requestsReceived);
    printf("Responses Sent:     %llu\n", pBlock->stats.responsesSent);
    printf("Errors:             %llu\n", pBlock->stats.errors);
    printf("Total Tokens:       %llu\n", pBlock->stats.totalTokens);
    printf("Total Latency:      %llu ms\n", pBlock->stats.totalLatencyMs);
    
    // Cleanup
    UnmapViewOfFile(pBlock);
    CloseHandle(hSharedMem);
    CloseHandle(hRequestEvent);
    CloseHandle(hResponseEvent);
    
    printf("\n[Client] Test complete\n");
    return 0;
}
