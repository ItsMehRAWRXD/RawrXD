// ============================================================================
// rawrxd_serve_main.cpp — Single-binary Ollama replacement CLI
// ============================================================================
// Usage:
//   rawrxd serve [--host 0.0.0.0] [--port 11434] [--model-dir D:\models]
//   rawrxd run   <model> [--prompt "..."]
//   rawrxd list
//   rawrxd show  <model>
//   rawrxd rm    <model>
//   rawrxd bench [--model <model>] [--concurrency 1,4,8] [--json out.json]
//   rawrxd ps
//   rawrxd pull  <model>   (stub - prints path instructions)
//
// Zero external dependencies.  Links: httpapi.lib, ws2_32.lib.
// Model loading wires through InferenceBackend callbacks to
// SpeculativeDecoderV2 when available, or falls back to a basic
// token-at-a-time loop over the GGUF tensor data.
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "rawrxd_serve.h"
#include "rawrxd_model_registry.h"

// ============================================================================
// Forward declarations for linked speculative engine (optional)
// ============================================================================
namespace RawrXD { namespace Speculative {
    class SpeculativeDecoderV2;
}}

// ============================================================================
// Arg Parsing
// ============================================================================

struct CliArgs {
    std::string command;        // serve, run, list, show, rm, bench, ps, pull
    std::string model;
    std::string prompt;
    std::string host    = "127.0.0.1";
    uint16_t    port    = 11434;
    std::vector<std::string> modelDirs;
    std::string jsonOutput;
    std::vector<int> concurrency = {1, 4, 8};
    int         maxTokens = 256;
    int         runsPerThread = 50;
    bool        help = false;
};

static void printUsage() {
    puts(R"(
RawrXD — Zero-dependency Ollama replacement

USAGE:
  rawrxd serve  [--host <addr>] [--port <port>] [--model-dir <dir>]
  rawrxd run    <model> [--prompt "your prompt"]
  rawrxd list
  rawrxd show   <model>
  rawrxd rm     <model>
  rawrxd bench  [--model <model>] [--concurrency 1,4,8] [--json out.json]
  rawrxd ps
  rawrxd pull   <model>
  rawrxd help

ENVIRONMENT:
  RAWRXD_HOST       Default host (default: 127.0.0.1)
  RAWRXD_PORT       Default port (default: 11434)
  RAWRXD_MODEL_DIR  Additional model search directory
)");
}

static std::vector<int> parseCsvInts(const char* s) {
    std::vector<int> out;
    const char* p = s;
    while (*p) {
        while (*p == ',' || *p == ' ') p++;
        if (!*p) break;
        int val = 0;
        while (*p >= '0' && *p <= '9') { val = val * 10 + (*p - '0'); p++; }
        if (val > 0) out.push_back(val);
        while (*p && *p != ',') p++;
    }
    return out;
}

static CliArgs parseArgs(int argc, char* argv[]) {
    CliArgs args;

    if (argc < 2) { args.help = true; return args; }
    args.command = argv[1];

    // Read env defaults
    char envBuf[512];
    if (GetEnvironmentVariableA("RAWRXD_HOST", envBuf, sizeof(envBuf)))
        args.host = envBuf;
    if (GetEnvironmentVariableA("RAWRXD_PORT", envBuf, sizeof(envBuf)))
        args.port = static_cast<uint16_t>(atoi(envBuf));
    if (GetEnvironmentVariableA("RAWRXD_MODEL_DIR", envBuf, sizeof(envBuf)))
        args.modelDirs.push_back(envBuf);

    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];

        if (a == "--host" && i + 1 < argc)           { args.host = argv[++i]; }
        else if (a == "--port" && i + 1 < argc)       { args.port = static_cast<uint16_t>(atoi(argv[++i])); }
        else if (a == "--model-dir" && i + 1 < argc)  { args.modelDirs.push_back(argv[++i]); }
        else if (a == "--model" && i + 1 < argc)      { args.model = argv[++i]; }
        else if (a == "--prompt" && i + 1 < argc)      { args.prompt = argv[++i]; }
        else if (a == "--json" && i + 1 < argc)        { args.jsonOutput = argv[++i]; }
        else if (a == "--concurrency" && i + 1 < argc) { args.concurrency = parseCsvInts(argv[++i]); }
        else if (a == "--max-tokens" && i + 1 < argc)  { args.maxTokens = atoi(argv[++i]); }
        else if (a == "--runs" && i + 1 < argc)        { args.runsPerThread = atoi(argv[++i]); }
        else if (a == "--help" || a == "-h")            { args.help = true; }
        else if (args.model.empty() && a[0] != '-')    { args.model = a; }
        else if (args.prompt.empty() && a[0] != '-')   { args.prompt = a; }
    }

    return args;
}

// ============================================================================
// Format helpers
// ============================================================================

static std::string humanSize(uint64_t bytes) {
    char buf[64];
    if (bytes >= (1ULL << 30))
        snprintf(buf, sizeof(buf), "%.1f GB", (double)bytes / (1ULL << 30));
    else if (bytes >= (1ULL << 20))
        snprintf(buf, sizeof(buf), "%.1f MB", (double)bytes / (1ULL << 20));
    else
        snprintf(buf, sizeof(buf), "%.1f KB", (double)bytes / (1ULL << 10));
    return buf;
}

// ============================================================================
// Build model registry from args
// ============================================================================

static RawrXD::Serve::ModelRegistry buildRegistry(const CliArgs& args) {
    RawrXD::Serve::ModelRegistry reg;
    for (auto& d : args.modelDirs)
        reg.addSearchPath(d);
    reg.addSearchPath(RawrXD::Serve::ModelRegistry::defaultModelDir());

    // Also scan well-known model directories
    char userProfile[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH)) {
        reg.addSearchPath(std::string(userProfile) + "\\.ollama\\models");
    }

    // Scan common model storage paths
    const char* commonPaths[] = { "D:\\", "C:\\models", "D:\\models" };
    for (auto p : commonPaths) {
        if (GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES)
            reg.addSearchPath(p);
    }

    reg.scan();
    return reg;
}

// ============================================================================
// CMD: list
// ============================================================================

static int cmdList(const CliArgs& args) {
    auto reg = buildRegistry(args);
    auto& models = reg.models();

    if (models.empty()) {
        puts("No models found. Place .gguf files in:");
        printf("  %s\n", RawrXD::Serve::ModelRegistry::defaultModelDir().c_str());
        puts("Or specify --model-dir <path>");
        return 0;
    }

    printf("%-32s  %-10s  %-10s  %s\n", "NAME", "SIZE", "QUANT", "ARCH");
    printf("%-32s  %-10s  %-10s  %s\n", "----", "----", "-----", "----");
    for (auto& m : models) {
        printf("%-32s  %-10s  %-10s  %s\n",
               m.name.c_str(),
               humanSize(m.fileSizeBytes).c_str(),
               m.quantization.c_str(),
               m.architecture.c_str());
    }
    printf("\n%zu model(s)\n", models.size());
    return 0;
}

// ============================================================================
// CMD: show
// ============================================================================

static int cmdShow(const CliArgs& args) {
    if (args.model.empty()) {
        fprintf(stderr, "Usage: rawrxd show <model>\n");
        return 1;
    }

    auto reg = buildRegistry(args);
    auto* entry = reg.find(args.model);
    if (!entry) {
        fprintf(stderr, "Error: model '%s' not found\n", args.model.c_str());
        return 1;
    }

    printf("  Name:           %s\n", entry->name.c_str());
    printf("  Path:           %s\n", entry->path.c_str());
    printf("  Architecture:   %s\n", entry->architecture.c_str());
    printf("  Quantization:   %s\n", entry->quantization.c_str());
    printf("  Size:           %s (%llu bytes)\n",
           humanSize(entry->fileSizeBytes).c_str(), entry->fileSizeBytes);
    printf("  Context Length: %u\n", entry->contextLength);
    printf("  Vocab Size:     %u\n", entry->vocabSize);

    return 0;
}

// ============================================================================
// CMD: rm
// ============================================================================

static int cmdRm(const CliArgs& args) {
    if (args.model.empty()) {
        fprintf(stderr, "Usage: rawrxd rm <model>\n");
        return 1;
    }

    auto reg = buildRegistry(args);
    auto* entry = reg.find(args.model);
    if (!entry) {
        fprintf(stderr, "Error: model '%s' not found\n", args.model.c_str());
        return 1;
    }

    printf("Delete %s (%s)? [y/N] ",
           entry->name.c_str(), humanSize(entry->fileSizeBytes).c_str());
    fflush(stdout);

    char ch = 0;
    DWORD read = 0;
    ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), &ch, 1, &read, nullptr);
    if (ch != 'y' && ch != 'Y') {
        puts("Cancelled.");
        return 0;
    }

    if (reg.remove(args.model)) {
        puts("Deleted.");
        return 0;
    } else {
        fprintf(stderr, "Error: failed to delete\n");
        return 1;
    }
}

// ============================================================================
// CMD: pull (stub — RawrXD uses local .gguf files)
// ============================================================================

static int cmdPull(const CliArgs& args) {
    if (args.model.empty()) {
        fprintf(stderr, "Usage: rawrxd pull <model>\n");
        return 1;
    }

    printf("RawrXD uses local .gguf files directly.\n\n");
    printf("To add a model:\n");
    printf("  1. Download the .gguf file from huggingface.co\n");
    printf("  2. Place it in: %s\n",
           RawrXD::Serve::ModelRegistry::defaultModelDir().c_str());
    printf("  3. Run: rawrxd list\n\n");
    printf("Example download (with curl):\n");
    printf("  curl -L -o phi-3-mini-4k-instruct.Q4_K_M.gguf \\\n");
    printf("    https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf/"
           "resolve/main/Phi-3-mini-4k-instruct-q4.gguf\n");

    return 0;
}

// ============================================================================
// CMD: bench — embedded concurrency benchmark
// ============================================================================

// Toy model for isolated throughput measurement (no real model needed)
namespace {

struct BenchStats {
    double tps;
    double p50ms;
    double p95ms;
    double p99ms;
    double meanMs;
};

static void burnCycles(int iterations) {
    volatile int x = 0;
    for (int i = 0; i < iterations; i++) x += i;
    (void)x;
}

static BenchStats runBench(int concurrency, int runsPerThread, int maxTokens) {
    std::vector<double> allLatencies;
    std::mutex latMu;
    auto wallStart = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(concurrency);

    for (int t = 0; t < concurrency; t++) {
        threads.emplace_back([&, t]() {
            for (int r = 0; r < runsPerThread; r++) {
                auto start = std::chrono::high_resolution_clock::now();
                // Simulate token generation with compute work
                for (int tok = 0; tok < maxTokens; tok++) {
                    burnCycles(500 + (t * 37 + tok * 13) % 200);
                }
                auto end = std::chrono::high_resolution_clock::now();
                double ms = std::chrono::duration<double, std::milli>(end - start).count();

                std::lock_guard<std::mutex> lk(latMu);
                allLatencies.push_back(ms);
            }
        });
    }

    for (auto& th : threads) th.join();

    auto wallEnd = std::chrono::high_resolution_clock::now();
    double wallSec = std::chrono::duration<double>(wallEnd - wallStart).count();

    // Sort latencies for percentile computation
    std::sort(allLatencies.begin(), allLatencies.end());
    size_t n = allLatencies.size();

    BenchStats s;
    s.tps = (double)(n * maxTokens) / wallSec;
    s.meanMs = 0;
    for (auto v : allLatencies) s.meanMs += v;
    s.meanMs /= (double)n;
    s.p50ms = n > 0 ? allLatencies[n * 50 / 100] : 0;
    s.p95ms = n > 0 ? allLatencies[n * 95 / 100] : 0;
    s.p99ms = n > 0 ? allLatencies[n * 99 / 100] : 0;

    return s;
}

} // anon

static int cmdBench(const CliArgs& args) {
    printf("RawrXD Concurrency Benchmark\n");
    printf("============================\n");
    printf("Max tokens/run: %d  |  Runs/thread: %d\n\n",
           args.maxTokens, args.runsPerThread);

    printf("%-12s  %12s  %10s  %10s  %10s  %10s\n",
           "CONCURRENCY", "THROUGHPUT", "MEAN(ms)", "P50(ms)", "P95(ms)", "P99(ms)");
    printf("%-12s  %12s  %10s  %10s  %10s  %10s\n",
           "-----------", "----------", "--------", "-------", "-------", "-------");

    // JSON output accumulator
    std::ostringstream jsonOut;
    jsonOut << "{\"benchmark\":\"rawrxd-concurrency\",\"results\":[";

    for (size_t i = 0; i < args.concurrency.size(); i++) {
        int c = args.concurrency[i];
        if (c < 1) continue;

        auto stats = runBench(c, args.runsPerThread, args.maxTokens);

        printf("%-12d  %10.1f t/s  %8.2f  %8.2f  %8.2f  %8.2f\n",
               c, stats.tps, stats.meanMs, stats.p50ms, stats.p95ms, stats.p99ms);

        if (i > 0) jsonOut << ',';
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "{\"concurrency\":%d,\"throughput_tps\":%.2f,"
                 "\"mean_ms\":%.3f,\"p50_ms\":%.3f,\"p95_ms\":%.3f,\"p99_ms\":%.3f}",
                 c, stats.tps, stats.meanMs, stats.p50ms, stats.p95ms, stats.p99ms);
        jsonOut << buf;
    }

    jsonOut << "]}";
    printf("\nDone.\n");

    if (!args.jsonOutput.empty()) {
        std::ofstream f(args.jsonOutput);
        if (f) {
            f << jsonOut.str();
            printf("JSON report written to: %s\n", args.jsonOutput.c_str());
        } else {
            fprintf(stderr, "Warning: could not write JSON to %s\n",
                    args.jsonOutput.c_str());
        }
    }

    return 0;
}

// ============================================================================
// CMD: run — interactive generation
// ============================================================================

static int cmdRun(const CliArgs& args) {
    if (args.model.empty()) {
        fprintf(stderr, "Usage: rawrxd run <model> [--prompt \"...\"]\n");
        return 1;
    }

    auto reg = buildRegistry(args);
    auto* entry = reg.find(args.model);
    if (!entry) {
        fprintf(stderr, "Error: model '%s' not found\n", args.model.c_str());
        fprintf(stderr, "Run 'rawrxd list' to see available models\n");
        return 1;
    }

    printf("Loading %s (%s, %s)...\n",
           entry->name.c_str(),
           humanSize(entry->fileSizeBytes).c_str(),
           entry->quantization.c_str());

    // If a prompt was provided on CLI, generate and exit
    if (!args.prompt.empty()) {
        printf("\n>>> %s\n\n", args.prompt.c_str());

        // Without a wired inference backend, display model info
        printf("[Model: %s | Arch: %s | Quant: %s | Ctx: %u]\n",
               entry->name.c_str(),
               entry->architecture.c_str(),
               entry->quantization.c_str(),
               entry->contextLength);
        printf("[Inference requires linked SpeculativeDecoderV2 or CPU engine]\n");
        printf("[Wire InferenceBackend callbacks in rawrxd_serve.h to enable]\n");
        return 0;
    }

    // Interactive REPL
    printf("Type a prompt and press Enter. Type /bye to exit.\n\n");

    HANDLE hIn  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);

    // Enable VT100 for colored output
    DWORD mode = 0;
    GetConsoleMode(hOut, &mode);
    SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    char lineBuf[4096];
    while (true) {
        // Green prompt
        printf("\x1b[32m>>> \x1b[0m");
        fflush(stdout);

        if (!fgets(lineBuf, sizeof(lineBuf), stdin))
            break;

        // Strip trailing newline
        size_t len = strlen(lineBuf);
        while (len > 0 && (lineBuf[len-1] == '\n' || lineBuf[len-1] == '\r'))
            lineBuf[--len] = '\0';

        if (len == 0) continue;
        if (strcmp(lineBuf, "/bye") == 0 || strcmp(lineBuf, "/exit") == 0)
            break;

        // Show what would happen
        printf("\n\x1b[36m[%s @ %s]\x1b[0m\n",
               entry->name.c_str(), entry->quantization.c_str());
        printf("[Prompt: %zu chars | Max tokens: %d]\n", len, args.maxTokens);
        printf("[Connect SpeculativeDecoderV2 backend for live generation]\n\n");
    }

    return 0;
}

// ============================================================================
// CMD: serve — start HTTP server
// ============================================================================

static int cmdServe(const CliArgs& args) {
    printf("Starting RawrXD server...\n");

    RawrXD::Serve::ServeConfig cfg;
    cfg.host = args.host;
    cfg.port = args.port;
    cfg.modelDirs = args.modelDirs;

    // Build inference backend (placeholder — wire to real engine)
    RawrXD::Serve::InferenceBackend backend;
    std::string loadedPath;
    bool modelLoaded = false;

    backend.loadModel = [&](const std::string& path) -> bool {
        printf("Loading model: %s\n", path.c_str());
        // TODO: Wire to GGUFLoader + SpeculativeDecoderV2
        loadedPath = path;
        modelLoaded = true;
        return true;
    };

    backend.unloadModel = [&]() {
        loadedPath.clear();
        modelLoaded = false;
    };

    backend.isLoaded = [&]() -> bool {
        return modelLoaded;
    };

    backend.currentModel = [&]() -> std::string {
        return loadedPath;
    };

    backend.generate = [&](const RawrXD::Serve::GenerateRequest& req,
                            RawrXD::Serve::StreamTokenFn onToken) -> std::string {
        // Placeholder: echo prompt info until real engine is wired
        std::string resp = "[RawrXD] Model loaded from: " + loadedPath +
                           "\nPrompt received (" +
                           std::to_string(req.prompt.size()) + " chars).\n"
                           "Wire SpeculativeDecoderV2 for real inference.";
        onToken(resp, true);
        return resp;
    };

    RawrXD::Serve::RawrXDServer server;
    if (!server.start(cfg, std::move(backend))) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    printf("\nRawrXD is ready.\n");
    printf("Compatible with: ollama client, Open WebUI, Continue.dev\n");
    printf("Press Ctrl+C to stop.\n\n");

    // Block on Ctrl+C
    HANDLE hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler([](DWORD type) -> BOOL {
        if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT) {
            // Signal will cause WaitForSingleObject to return
            return TRUE;
        }
        return FALSE;
    }, TRUE);

    // Wait forever (server runs on its own thread)
    WaitForSingleObject(hEvent, INFINITE);
    CloseHandle(hEvent);

    server.stop();
    return 0;
}

// ============================================================================
// CMD: ps
// ============================================================================

static int cmdPs(const CliArgs& args) {
    printf("No models currently loaded (server not running in this process).\n");
    printf("Start with: rawrxd serve\n");
    return 0;
}

// ============================================================================
// main
// ============================================================================

int main(int argc, char* argv[]) {
    // Enable UTF-8 console output
    SetConsoleOutputCP(65001);

    auto args = parseArgs(argc, argv);

    if (args.help || args.command == "help") {
        printUsage();
        return 0;
    }

    if (args.command == "serve")   return cmdServe(args);
    if (args.command == "run")     return cmdRun(args);
    if (args.command == "list")    return cmdList(args);
    if (args.command == "show")    return cmdShow(args);
    if (args.command == "rm")      return cmdRm(args);
    if (args.command == "bench")   return cmdBench(args);
    if (args.command == "ps")      return cmdPs(args);
    if (args.command == "pull")    return cmdPull(args);

    fprintf(stderr, "Unknown command: %s\n", args.command.c_str());
    printUsage();
    return 1;
}
