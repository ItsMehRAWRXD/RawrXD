// ============================================================================
// test_generation.cpp — End-to-End Generation Test
// ============================================================================

#include <cstdio>
#include <cstring>
#include <chrono>
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

    TEST("Bridge initialize", bridge.Initialize(cfg));
    TEST("Bridge status ready", bridge.GetStatus() == rawr::EngineStatus::Ready);

    // Test model loading
    TEST("Bridge load model", bridge.LoadModel("test.gguf"));
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

    bool streamed = false;
    TEST("Adapter generate", adapter.Generate("test prompt",
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
