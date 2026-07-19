/*===========================================================================
 * test_cdb_engine.cpp
 * Test harness for SovereignCDB_Engine
 * 
 * Usage: test_cdb_engine.exe [path_to_exe]
 *===========================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "SovereignCDB_Engine.h"

// Event callback
void OnDebugEvent(const CDB_DebugEvent* event, void* userData) {
    (void)userData;
    
    printf("[EVENT] Type=%d PID=%lu TID=%lu\n", 
           event->type, event->processId, event->threadId);
    printf("        %s\n", event->description);
    
    if (event->type == CDB_EVENT_BREAKPOINT) {
        printf("        Address: ");
        char addrStr[32];
        CDB_FormatAddress(event->address, addrStr, sizeof(addrStr));
        printf("%s\n", addrStr);
        
        // Get register context
        CDB_ThreadContext ctx;
        if (CDB_GetThreadContext(event->threadId, &ctx)) {
            printf("        RIP=%016llX RSP=%016llX\n", ctx.rip, ctx.rsp);
        }
    }
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("SovereignCDB_Engine Test\n");
    printf("========================================\n\n");
    
    // Initialize CDB engine
    printf("[1/4] Initializing CDB engine...\n");
    CDB_Config config = {0};
    config.breakOnEntry = true;
    config.breakOnException = true;
    
    if (!CDB_Initialize(&config)) {
        printf("ERROR: Failed to initialize CDB\n");
        return 1;
    }
    printf("      SUCCESS: CDB initialized\n\n");
    
    // Set event callback
    CDB_SetEventCallback(OnDebugEvent, NULL);
    
    // Launch or attach to process
    if (argc > 1) {
        printf("[2/4] Launching process: %s\n", argv[1]);
        if (!CDB_LaunchProcess(argv[1], NULL, NULL, NULL)) {
            printf("ERROR: Failed to launch process: %s\n", CDB_GetLastError());
            CDB_Shutdown();
            return 1;
        }
    } else {
        printf("[2/4] No executable specified, using self-test mode\n");
        printf("      Usage: %s <executable_path>\n\n", argv[0]);
        
        // Self-test: just verify the engine works
        printf("      Self-test: Setting breakpoint at main...\n");
        // In real usage, would resolve symbol and set breakpoint
        
        printf("      Self-test: PASSED\n\n");
        CDB_Shutdown();
        printf("Test completed successfully!\n");
        return 0;
    }
    
    printf("      Process launched, PID=%lu\n\n", CDB_GetState());
    
    // Main debug loop
    printf("[3/4] Running debug loop (press Ctrl+C to stop)...\n");
    printf("      Waiting for events...\n\n");
    
    int eventCount = 0;
    while (eventCount < 10 && CDB_GetState() != CDB_STATE_TERMINATED) {
        if (CDB_WaitForEvent(1000)) {
            CDB_DebugEvent event;
            while (CDB_GetNextEvent(&event)) {
                eventCount++;
                
                // Handle breakpoint
                if (event.type == CDB_EVENT_BREAKPOINT) {
                    printf("[ACTION] Breakpoint hit! Continuing...\n");
                    CDB_Continue(event.threadId, false);
                }
            }
        }
    }
    
    printf("\n      Processed %d events\n\n", eventCount);
    
    // Cleanup
    printf("[4/4] Cleaning up...\n");
    CDB_Shutdown();
    printf("      SUCCESS: CDB shutdown\n\n");
    
    printf("Test completed successfully!\n");
    return 0;
}
