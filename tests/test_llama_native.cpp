// ============================================================================
// test_llama_native.cpp — LlamaNative Backend Smoke Test
// Validates that LlamaNativeBridge can load llama.dll and generate tokens
// ============================================================================

#include <cstdio>
#include <cstring>
#include <windows.h>
#include "../src/deep2/Deep2Bridge.hpp"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr) do { \
    printf("  [TEST] %-45s ... ", name); \
    if (expr) { printf("PASSED\n"); g_passed++; } \
    else { printf("FAILED\n"); g_failed++; } \
} while(0)

int main() {
    printf("========================================\n");
    printf("  LlamaNative Backend Smoke Test\n");
    printf("========================================\n\n");

    // Resolve GGUF fixture relative to executable location
    char exePath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    std::string exeDir = exePath;
    auto lastSlash = exeDir.find_last_of("\\/");
    if (lastSlash != std::string::npos) exeDir = exeDir.substr(0, lastSlash);

    const char* kModelPath = nullptr;
    const char* candidates[] = {
        "gemma3-1b-Q2_K.gguf",
        "../../../gemma3-1b-Q2_K.gguf",
        "../../gemma3-1b-Q2_K.gguf",
        "D:/rawrxd/gemma3-1b-Q2_K.gguf",
    };
    std::string resolvedPath;
    for (const char* cand : candidates) {
        resolvedPath = exeDir + "\\" + cand;
        for (auto& c : resolvedPath) if (c == '/') c = '\\';
        FILE* f = fopen(resolvedPath.c_str(), "rb");
        if (f) { fclose(f); kModelPath = resolvedPath.c_str(); break; }
    }
    if (!kModelPath) {
        printf("  [WARN] No GGUF model found; skipping model load test\n");
    } else {
        printf("  [INFO] Using GGUF fixture: %s\n", resolvedPath.c_str());
    }

    // Check if llama.dll is available before attempting initialization
    std::wstring llamaDllPath = std::wstring(exeDir.begin(), exeDir.end()) + L"\\llama.dll";
    bool llamaDllAvailable = (GetFileAttributesW(llamaDllPath.c_str()) != INVALID_FILE_ATTRIBUTES);
    if (!llamaDllAvailable) {
        // Also check in PATH
        HMODULE hTest = LoadLibraryW(L"llama.dll");
        if (hTest) {
            llamaDllAvailable = true;
            FreeLibrary(hTest);
        }
    }

    if (!llamaDllAvailable) {
        printf("  [WARN] llama.dll not found. Skipping LlamaNative backend test.\n");
        printf("         Place llama.dll + ggml.dll in the executable directory to enable.\n");
        printf("\n========================================\n");
        printf("  Results: SKIPPED (llama.dll unavailable)\n");
        printf("========================================\n");
        return 0;  // Skip, not fail
    }

    // Test Deep2Bridge with LlamaNative backend
    auto& bridge = rawr::Deep2Bridge::Get();
    bridge.SetBackend(rawr::InferenceBackend::LlamaNative);

    rawr::EngineConfig cfg;
    cfg.modelPath = kModelPath ? kModelPath : "test.gguf";
    cfg.contextSize = 2048;
    cfg.temperature = 0.7f;
    cfg.useGPU = true;

    TEST("Bridge initialize (LlamaNative)", bridge.Initialize(cfg));
    TEST("Bridge status ready", bridge.GetStatus() == rawr::EngineStatus::Ready);
    TEST("Bridge backend is LlamaNative", bridge.GetBackend() == rawr::InferenceBackend::LlamaNative);

    if (kModelPath) {
        TEST("Bridge load model", bridge.LoadModel(kModelPath));
        TEST("Bridge model loaded", bridge.IsModelLoaded());

        bool tokensReceived = false;
        TEST("Bridge generate", bridge.Generate("Hello", 
            [&](const char*, uint32_t) { tokensReceived = true; },
            [](const char* msg) { printf("\n    [ERROR] %s\n", msg); }));
        TEST("Bridge tokens received", tokensReceived);

        auto metrics = bridge.GetMetrics();
        TEST("Bridge metrics non-zero", metrics.totalTokens > 0);
    }

    bridge.Shutdown();

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n", g_passed, g_failed, g_passed + g_failed);
    printf("========================================\n");

    return g_failed > 0 ? 1 : 0;
}
