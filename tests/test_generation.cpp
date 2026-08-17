// ============================================================================
// test_generation.cpp — End-to-End Generation Test
// ============================================================================

#include <cstdio>
#include <cstring>
#include <chrono>
#include <windows.h>
#include "../src/deep2/RawrXDInferenceAdapter.hpp"
#include "../src/deep2/Deep2Bridge.hpp"
#include "../src/deep2/InferenceSession.hpp"
#include "../src/deep2/ModelRegistry.hpp"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr) do { \
    printf("  [TEST] %-45s ... ", name); \
    if (expr) { printf("PASSED\n"); g_passed++; } \
    else { printf("FAILED\n"); g_failed++; } \
} while(0)

int main() {
    printf("========================================\n");
    printf("  RawrXD Generation Test Suite\n");
    printf("========================================\n\n");

    // Test Deep2Bridge
    auto& bridge = rawr::Deep2Bridge::Get();
    rawr::EngineConfig cfg;
    cfg.modelPath = "test.gguf";
    cfg.contextSize = 2048;
    cfg.temperature = 0.7f;

    // Resolve GGUF fixture relative to executable location (not CWD).
    // This makes the test deterministic regardless of how it is launched.
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = exePath;
    auto lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos) exeDir = exeDir.substr(0, lastSlash);

    const char* kModelPath = nullptr;
    const char* candidates[] = {
        "gemma3-1b-Q2_K.gguf",                    // beside executable
        "../../../gemma3-1b-Q2_K.gguf",             // from build-ninja/tests/
        "../../gemma3-1b-Q2_K.gguf",              // from build-ninja/bin/
    };
    std::string resolvedPath;
    for (const char* cand : candidates) {
        resolvedPath = exeDir + "\\" + cand;
        // Normalize mixed separators
        for (auto& c : resolvedPath) if (c == '/') c = '\\';
        FILE* f = fopen(resolvedPath.c_str(), "rb");
        if (f) { fclose(f); kModelPath = cand; break; }
    }
    if (!kModelPath) {
        printf("  [WARN] No GGUF model found; generation tests will use synthetic fallback\n");
        kModelPath = "gemma3-1b-Q2_K.gguf";
    } else {
        printf("  [INFO] Using GGUF fixture: %s\n", resolvedPath.c_str());
    }

    TEST("Bridge initialize", bridge.Initialize(cfg));
    TEST("Bridge status ready", bridge.GetStatus() == rawr::EngineStatus::Ready);

    // Test model loading
    TEST("Bridge load model", bridge.LoadModel(kModelPath));
    TEST("Bridge model loaded", bridge.IsModelLoaded());

    // Test generation
    bool tokensReceived = false;
    TEST("Bridge generate", bridge.Generate("Hello", 
        [&](const char*, uint32_t) { tokensReceived = true; },
        [](const char*) {}));
    TEST("Bridge tokens received", tokensReceived);

    // Test metrics
    auto metrics = bridge.GetMetrics();
    TEST("Bridge metrics non-zero", metrics.totalTokens > 0);

    // Test InferenceSession
    rawr::InferenceSession session(1);
    session.Start("test-model");
    TEST("Session active", session.IsActive());
    TEST("Session ID", session.GetId() == 1);

    session.AddMessage("user", "Hello");
    session.AddMessage("assistant", "Hi there!");
    TEST("Session history", session.GetHistory().size() == 2);

    session.RecordTokens(100);
    TEST("Session token count", session.GetTokenCount() == 100);

    // Test ModelRegistry
    auto& registry = rawr::ModelRegistry::Get();
    uint32_t modelId = registry.RegisterModel("test.gguf", "test-model");
    TEST("Model registered", modelId > 0);

    registry.SetModelLoaded(modelId, true);
    TEST("Model loaded in registry", registry.GetLoadedCount() == 1);

    registry.AddSession(modelId);
    TEST("Model has session", registry.GetModel(modelId)->activeSessions == 1);

    // Test RawrXDInferenceAdapter
    auto& adapter = rawr::RawrXDInferenceAdapter::Get();
    TEST("Adapter initialize", adapter.Initialize());
    TEST("Adapter not model loaded after initialize", !adapter.IsModelLoaded());

    bool streamed = false;
    TEST("Adapter generate without model", !adapter.Generate("test prompt",
        [&](const char*, uint32_t) { streamed = true; }));
    TEST("Adapter no stream without model", !streamed);

    TEST("Adapter load model", adapter.LoadModel(kModelPath));
    TEST("Adapter model loaded", adapter.IsModelLoaded());

    streamed = false;
    TEST("Adapter generate with model", adapter.Generate("test prompt",
        [&](const char*, uint32_t) { streamed = true; }));
    TEST("Adapter streamed tokens", streamed);

    auto stats = adapter.GetStats();
    TEST("Adapter stats non-zero", stats.totalTokens > 0);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n", g_passed, g_failed, g_passed + g_failed);
    printf("========================================\n");

    bridge.Shutdown();
    adapter.Shutdown();
    return g_failed > 0 ? 1 : 0;
}
