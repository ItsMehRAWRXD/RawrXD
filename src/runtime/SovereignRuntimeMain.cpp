/*===========================================================================
 * SovereignRuntimeMain.cpp
 * Standalone runtime server executable
 * 
 * Usage: SovereignRuntime.exe [--service]
 *===========================================================================*/

#include "SovereignSharedMemoryServer.hpp"
#include <windows.h>
#include <stdio.h>
#include <signal.h>

RawrXD::Runtime::SovereignSharedMemoryServer* g_server = nullptr;

void SignalHandler(int sig) {
    printf("\n[SovereignRuntime] Signal %d received, shutting down...\n", sig);
    if (g_server) {
        g_server->Shutdown();
    }
    exit(0);
}

void PrintBanner() {
    printf("========================================\n");
    printf("  RawrXD Sovereign Runtime Server\n");
    printf("  Version 1.0.0 (Alpha)\n");
    printf("========================================\n");
    printf("\n");
    printf("Backend:    Deep2 (Simulated)\n");
    printf("Quant:      Q4_K_M\n");
    printf("Kernel:     AVX512\n");
    printf("IPC:        Shared Memory (Zero-Copy)\n");
    printf("Protocol:   Request/Response Events\n");
    printf("\n");
}

void PrintUsage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  --service    Run as Windows service\n");
    printf("  --name NAME  Shared memory name (default: RawrXD_SharedMem_Alpha)\n");
    printf("  --help       Show this help\n");
    printf("\n");
    printf("Commands (while running):\n");
    printf("  't' - Show telemetry\n");
    printf("  'q' - Quit\n");
    printf("\n");
}

void PrintTelemetry(RawrXD::Runtime::SovereignSharedMemoryServer* server) {
    auto telem = server->GetTelemetry();
    
    printf("\n");
    printf("=== Runtime Telemetry ===\n");
    printf("Requests Received:  %llu\n", telem.requestsReceived);
    printf("Responses Sent:     %llu\n", telem.responsesSent);
    printf("Errors:             %llu\n", telem.errors);
    printf("Total Tokens:       %llu\n", telem.totalTokens);
    printf("Avg Latency:        %.2f ms\n", telem.avgLatencyMs);
    printf("Avg TPS:            %.2f\n", telem.avgTps);
    printf("=========================\n");
    printf("\n");
}

int main(int argc, char* argv[]) {
    // Parse arguments
    bool serviceMode = false;
    const wchar_t* sharedMemName = L"RawrXD_SharedMem_Alpha";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--service") == 0) {
            serviceMode = true;
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            // Convert to wide string (simplified)
            sharedMemName = L"RawrXD_SharedMem_Alpha";  // Would convert argv[i+1]
            i++;
        } else if (strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    PrintBanner();
    
    // Set up signal handlers
    signal(SIGINT, SignalHandler);
    signal(SIGTERM, SignalHandler);
    
    // Create server
    RawrXD::Runtime::SovereignSharedMemoryServer server;
    g_server = &server;
    
    // Initialize
    printf("[SovereignRuntime] Initializing...\n");
    if (!server.Initialize(sharedMemName)) {
        printf("[SovereignRuntime] FAILED to initialize\n");
        return 1;
    }
    
    // Start worker
    printf("[SovereignRuntime] Starting worker thread...\n");
    if (!server.StartWorker()) {
        printf("[SovereignRuntime] FAILED to start worker\n");
        return 1;
    }
    
    printf("[SovereignRuntime] READY - Waiting for requests\n");
    printf("[SovereignRuntime] Press 't' for telemetry, 'q' to quit\n");
    printf("\n");
    
    // Main loop
    if (!serviceMode) {
        // Interactive mode
        while (true) {
            if (_kbhit()) {
                char c = _getch();
                if (c == 'q' || c == 'Q') {
                    break;
                } else if (c == 't' || c == 'T') {
                    PrintTelemetry(&server);
                }
            }
            Sleep(10);
        }
    } else {
        // Service mode - just wait for signals
        printf("[SovereignRuntime] Running in service mode\n");
        while (server.IsWorkerActive()) {
            Sleep(1000);
        }
    }
    
    // Shutdown
    printf("\n[SovereignRuntime] Shutting down...\n");
    server.Shutdown();
    printf("[SovereignRuntime] Exited cleanly\n");
    
    return 0;
}
