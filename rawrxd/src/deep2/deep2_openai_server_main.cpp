// ============================================================================
// deep2_openai_server_main.cpp
// Standalone executable: Deep2 OpenAI-compatible local model server
//
// Usage:
//   deep2_server.exe --model F:\models\qwen2.5-coder-32b-q4_k_m.gguf [--port 11435]
//
// Environment:
//   DEEP2_MODEL_PATH    default model to load
//   DEEP2_SERVER_PORT   default port (default 11435)
//   DEEP2_MAX_SEQ_LEN   context window size (default 4096)
// ============================================================================

#include "deep2_openai_server.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <csignal>
#include <cstdlib>

static Deep2::OpenAIServer* g_server = nullptr;

static void signalHandler(int sig) {
    std::fprintf(stderr, "\n[server] Caught signal %d, shutting down...\n", sig);
    if (g_server) g_server->stop();
}

static void printUsage(const char* prog) {
    std::fprintf(stderr,
        "Deep2 OpenAI-Compatible Local Model Server\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --model <path>    Path to GGUF model file (required)\n"
        "  --port  <n>       HTTP port (default: 11435)\n"
        "  --threads <n>     CPU thread count (default: auto)\n"
        "  --vulkan          Enable Vulkan GPU acceleration\n"
        "  --help            Show this message\n"
        "\n"
        "Environment:\n"
        "  DEEP2_MODEL_PATH  Default model path\n"
        "  DEEP2_SERVER_PORT Default port\n"
        "\n"
        "Examples:\n"
        "  %s --model F:\\\\models\\\\Qwen2.5-Coder-32B-Q4_K_M.gguf\n"
        "  %s --model C:\\\\models\\\\model.gguf --port 8080 --vulkan\n",
        prog, prog, prog);
}

int main(int argc, char** argv) {
    const char* prog = (argc > 0) ? argv[0] : "deep2_server";

    std::string modelPath;
    uint16_t    port = 11435;
    bool        vulkan = false;
    int         numThreads = 0;

    // Environment defaults
    if (const char* envModel = std::getenv("DEEP2_MODEL_PATH")) {
        modelPath = envModel;
    }
    if (const char* envPort = std::getenv("DEEP2_SERVER_PORT")) {
        port = static_cast<uint16_t>(std::atoi(envPort));
    }

    // Parse args
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            modelPath = argv[++i];
        } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            numThreads = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--vulkan") == 0) {
            vulkan = true;
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            printUsage(prog);
            return 0;
        } else {
            std::fprintf(stderr, "[server] Unknown option: %s\n", argv[i]);
            printUsage(prog);
            return 1;
        }
    }

    if (modelPath.empty()) {
        std::fprintf(stderr, "[server] ERROR: --model is required\n");
        printUsage(prog);
        return 1;
    }

    std::fprintf(stderr,
        "=============================================\n"
        "  Deep2 OpenAI-Compatible Local Model Server\n"
        "=============================================\n");

    Deep2::OpenAIServer server;
    g_server = &server;

    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    // Load model
    std::fprintf(stderr, "[server] Loading model: %s\n", modelPath.c_str());
    if (!server.loadModel(modelPath)) {
        std::fprintf(stderr, "[server] FATAL: Could not load model.\n");
        return 1;
    }

    // Enable Vulkan if requested
    if (vulkan) {
        server.engine().enableVulkan(true);
        std::fprintf(stderr, "[server] Vulkan GPU acceleration enabled.\n");
    }

    // Set thread count
    if (numThreads > 0) {
        // Note: engine config already applied in loadModel; this would require re-init
        // For now just log it
        std::fprintf(stderr, "[server] Thread count override requested: %d\n", numThreads);
    }

    // Logging callback
    server.setRequestLogCallback([](const std::string& method,
                                    const std::string& path,
                                    int statusCode,
                                    double elapsedMs) {
        std::fprintf(stderr, "[%s %s] %d  %.2f ms\n",
                     method.c_str(), path.c_str(), statusCode, elapsedMs);
    });

    // Start server
    if (!server.run(port)) {
        std::fprintf(stderr, "[server] FATAL: Could not start server on port %d\n", port);
        return 1;
    }

    std::fprintf(stderr,
        "[server] Ready.   Endpoint: http://127.0.0.1:%d/v1/chat/completions\n"
        "[server] Press Ctrl+C to stop.\n",
        port);

    // Block until stopped
    while (server.isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::fprintf(stderr, "[server] Shutdown complete.\n");
    return 0;
}
