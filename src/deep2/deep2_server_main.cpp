// ============================================================================
// deep2_server_main.cpp - RawrXD Deep2 Local AI Runtime
// Sovereign AI inference server - localhost only
// OpenAI-compatible API for IDE integration
// ============================================================================

#include "Deep2LocalServer.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

void PrintBanner() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                              ║\n");
    printf("║   RawrXD Deep2 - Sovereign Local AI Runtime                  ║\n");
    printf("║   Private AI inference - No cloud, no data leaves machine  ║\n");
    printf("║                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void PrintUsage(const char* program) {
    printf("Usage: %s [options]\n\n", program);
    printf("Options:\n");
    printf("  --model <path>       Path to GGUF model file (required)\n");
    printf("  --port <port>        Port to listen on (default: 11442)\n");
    printf("  --host <host>        Host to bind to (default: 127.0.0.1)\n");
    printf("  --help               Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --model models/llama-3.1-8b-q4.gguf\n", program);
    printf("  %s --model models/codestral.gguf --port 8080\n", program);
    printf("\n");
    printf("IDE Configuration:\n");
    printf("  VS Code/Cursor:\n");
    printf("    Provider: OpenAI Compatible\n");
    printf("    Base URL: http://localhost:11442\n");
    printf("    Model: deep2-local\n");
    printf("\n");
}

int main(int argc, char** argv) {
    PrintBanner();

    // Parse arguments
    std::string modelPath;
    int port = 11442;
    std::string host = "127.0.0.1";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            modelPath = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (modelPath.empty()) {
        printf("ERROR: No model specified. Use --model <path>\n\n");
        PrintUsage(argv[0]);
        return 1;
    }

    printf("[Deep2] Starting local AI runtime...\n");
    printf("[Deep2] Model: %s\n", modelPath.c_str());
    printf("[Deep2] Endpoint: http://%s:%d\n", host.c_str(), port);
    printf("[Deep2] API: OpenAI-compatible (v1/chat/completions)\n\n");

    // Create and initialize server
    Deep2::Deep2LocalServer server;
    
    if (!server.Initialize(modelPath, port, host)) {
        printf("ERROR: Failed to initialize Deep2 server\n");
        printf("Check that the model file exists and is a valid GGUF\n");
        return 1;
    }

    printf("[Deep2] Server initialized successfully\n");
    printf("[Deep2] Ready for connections\n\n");

    // Run server (blocking)
    server.Run();

    return 0;
}
