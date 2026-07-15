// ============================================================================
// RawrXD Pipe Server Test Harness
// Standalone test for the integrated pipe server + hotpatch router
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include "rawrxd_pipe_server.h"

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    printf("================================================================================\n");
    printf("RawrXD Pipe Server + Hotpatch Router Integration Test\n");
    printf("================================================================================\n\n");
    
    // Initialize pipe server
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
            // Send test payload via direct API
            uint8_t testPayload[] = {
                0x44, 0x48, 0x50, 0x52,  // "RHPD" magic (0x52485044 in little-endian)
                0x01, 0x00, 0x00, 0x00,  // version 1
                0x10, 0x00, 0x00, 0x00,  // 16 bytes payload
                0x00, 0x00, 0x00, 0x00,  // flags
                0x00, 0x00, 0x00, 0x00,  // timestamp (low)
                0x00, 0x00, 0x00, 0x00,  // timestamp (high)
                0x00, 0x00, 0x00, 0x00,  // CRC32
                // Payload data: "TestHotpatch!"
                0x54, 0x65, 0x73, 0x74, 0x48, 0x6F, 0x74, 0x70,
                0x61, 0x74, 0x63, 0x68, 0x21, 0x00, 0x00, 0x00
            };
            
            printf("Sending test hotpatch payload...\n");
            if (RawrXD_PipeServer_ProcessPayload(testPayload, sizeof(testPayload))) {
                printf("Test hotpatch processed successfully\n");
            } else {
                printf("Test hotpatch failed\n");
            }
            
            // Show stats
            uint64_t received, processed;
            RawrXD_PipeServer_GetStats(&received, &processed);
            printf("Stats: %llu received, %llu processed\n\n", received, processed);
        }
    }
    
    RawrXD_PipeServer_Shutdown();
    printf("\nShutdown complete\n");
    return 0;
}
