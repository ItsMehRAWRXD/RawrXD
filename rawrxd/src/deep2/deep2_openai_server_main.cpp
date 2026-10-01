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
// RAWRXD_B82_IDE_TOOL_POPULATION_001: the real sandboxed tool authority the IDE
// routes dispatch through (InstallBuiltinTools + ToolPolicy allowlist).
#include "agentic/AgentToolRegistry.h"
#include <windows.h>
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
        "  --model <path>      Path to GGUF model file (required)\n"
        "  --port  <n>         HTTP port (default: 11435)\n"
        "  --host  <ip>        Bind address (default: 127.0.0.1). Use 0.0.0.0 for LAN (requires --auth-token)\n"
        "  --auth-token <tok>  Bearer token for /v1/* routes (required when --host is not 127.0.0.1)\n"
        "  --threads <n>       CPU thread count (default: auto)\n"
        "  --vulkan            Enable Vulkan GPU acceleration\n"
        "  --help              Show this message\n"
        "\n"
        "Environment:\n"
        "  DEEP2_MODEL_PATH    Default model path\n"
        "  DEEP2_SERVER_PORT   Default port\n"
        "\n"
        "Examples:\n"
        "  %s --model F:\\\\models\\\\Qwen2.5-Coder-32B-Q4_K_M.gguf\n"
        "  %s --model C:\\\\models\\\\model.gguf --port 8080 --vulkan\n"
        "  %s --model model.gguf --host 0.0.0.0 --auth-token secret123\n",
        prog, prog, prog, prog);
}

int main(int argc, char** argv) {
    const char* prog = (argc > 0) ? argv[0] : "deep2_server";

    std::string modelPath;
    uint16_t    port = 11435;
    bool        vulkan = false;
    int         numThreads = 0;
    std::string listenAddr = "127.0.0.1"; // DEEP2_SERVER_BIND_AUTHORITY_001
    std::string authToken;                // required for non-loopback binds

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
        } else if (std::strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            listenAddr = argv[++i];
        } else if (std::strcmp(argv[i], "--auth-token") == 0 && i + 1 < argc) {
            authToken = argv[++i];
        } else if (std::strcmp(argv[i], "--listen") == 0 && i + 1 < argc) {
            // Legacy alias for --host (kept for the AWS drop's deploy scripts).
            listenAddr = argv[++i];
        } else if (std::strcmp(argv[i], "--auth") == 0 && i + 1 < argc) {
            // Legacy alias for --auth-token.
            authToken = argv[++i];
        } else if (std::strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            numThreads = std::atoi(argv[++i]);
        } else if (std::strcmp(argv[i], "--vulkan") == 0) {
            vulkan = true;
        } else if (std::strcmp(argv[i], "--build-info") == 0) {
#ifdef RAWRXD_BUILD_SHA
            std::printf("build_git_sha=%s\nsource_dirty=%d\nbuild_timestamp=%s\nbuild_config=%s\n",
                        RAWRXD_BUILD_SHA, RAWRXD_BUILD_DIRTY,
                        RAWRXD_BUILD_TS, RAWRXD_BUILD_CONFIG);
#else
            std::printf("build_git_sha=unknown\n");
#endif
            return 0;
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

    // DEEP2_SERVER_BIND_AUTHORITY_001: non-loopback bind requires auth.
    if (listenAddr != "127.0.0.1" && listenAddr != "localhost" && authToken.empty()) {
        std::fprintf(stderr,
            "[server] ERROR: non-loopback bind (--listen %s) requires --auth <token>\n"
            "[server] Loopback-only is the default. Use --listen 0.0.0.0 --auth <token> for LAN.\n",
            listenAddr.c_str());
        return 1;
    }

    std::fprintf(stderr,
        "=============================================\n"
        "  Deep2 OpenAI-Compatible Local Model Server\n"
        "=============================================\n");

    // RAWRXD_B82_IDE_TOOL_POPULATION_001: populate the tool authority the IDE
    // routes dispatch through.
    //
    // The authority is rawrxd::agentic::ToolRegistry
    // (include/agentic/AgentToolRegistry.h) -- the REAL sandboxed one, with
    // InstallBuiltinTools() providing read_file, write_file, list_directory and
    // search_code behind a ToolPolicy that has allowedRoots, output caps and an
    // execute timeout.
    //
    // NOT RawrXD::Agent::ToolRegistry (src/agentic/ToolRegistry.h). That one is a
    // stub whose RegisterTool was never called before this session, so it was
    // always empty and InvokeTool always returned "". An ad-hoc implementation
    // was written against it and then REMOVED rather than shipped: it duplicated
    // this authority with a weaker design (no output cap, no execute timeout,
    // hand-rolled escaping). One authority, the existing one.
    {
        using namespace rawrxd::agentic;
        ToolRegistry& reg = ToolRegistry::Instance();
        reg.InstallBuiltinTools();

        // RAWRXD_TOOL_POLICY_001: DefaultDenyAll() means "no filesystem tool is
        // enabled". That is the correct safe default, but it makes every route
        // answer "denied by policy", so the set of enabled tools is stated
        // explicitly at startup rather than left implicit.
        ToolPolicy pol = ToolPolicy::DefaultDenyAll();
        const char* root = std::getenv("RAWRXD_TOOL_ROOT");
        if (!root || !*root) {
            char cwd[MAX_PATH] = {0};
            root = (GetCurrentDirectoryA(MAX_PATH, cwd) > 0) ? cwd : ".";
        }
        pol.allowedRoots.push_back(root);
        pol.allowWrite   = (std::getenv("RAWRXD_TOOL_ALLOW_WRITE")   != nullptr);
        pol.allowExecute = (std::getenv("RAWRXD_TOOL_ALLOW_EXECUTE") != nullptr);
        reg.SetPolicy(pol);

        std::fprintf(stderr,
            "[server] tool authority: builtins installed, root=%s write=%s execute=%s\n",
            root, pol.allowWrite ? "on" : "off", pol.allowExecute ? "on" : "off");
    }

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

    // Run (blocks until SIGINT/SIGTERM). Non-loopback requires auth (checked above).
    if (!server.run(port, listenAddr, authToken)) {
        std::fprintf(stderr, "[server] FATAL: server failed to start.\n");
        return 1;
    }

    std::fprintf(stderr,
        "[server] Ready.   Endpoint: http://%s:%d/v1/chat/completions\n"
        "[server] Press Ctrl+C to stop.\n",
        listenAddr.c_str(), port);

    // Block until stopped
    while (server.isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::fprintf(stderr, "[server] Shutdown complete.\n");
    return 0;
}
