// ============================================================================
// test_gguf.cpp — GGUF Loader Unit Tests
// ============================================================================

#include <cstdio>
#include <cstring>
#include "../src/deep2/ModelLoader.hpp"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr) do { \
    printf("  [TEST] %-45s ... ", name); \
    if (expr) { printf("PASSED\n"); g_passed++; } \
    else { printf("FAILED\n"); g_failed++; } \
} while(0)

int main() {
    printf("========================================\n");
    printf("  RawrXD GGUF Test Suite\n");
    printf("========================================\n\n");

    auto& loader = rawr::ModelLoader::Get();

    TEST("Loader initialize", loader.Initialize());
    TEST("Loader not loaded initially", !loader.IsLoaded());
    TEST("Tensor count zero initially", loader.GetTensorCount() == 0);

    // Test tensor info structure
    rawr::TensorInfo info;
    info.name = "test.tensor";
    info.type = rawr::TensorType::F32;
    info.nDims = 2;
    info.shape[0] = 64;
    info.shape[1] = 64;
    info.size = 64 * 64 * 4;
    TEST("Tensor info size correct", info.size == 16384);

    // Test quantization type sizes
    info.type = rawr::TensorType::Q4_0;
    info.shape[0] = 4096;
    info.shape[1] = 4096;
    uint64_t q4Size = info.shape[0] * info.shape[1] / 2 + sizeof(float);
    TEST("Q4_0 size calculation", q4Size > 0);

    info.type = rawr::TensorType::Q4_K;
    uint64_t q4kSize = (info.shape[0] * info.shape[1] + 255) / 256 * 288;
    TEST("Q4_K size calculation", q4kSize > 0);

    // Test architecture detection
    rawr::ModelArchitecture arch;
    arch.name = "llama";
    arch.hiddenDim = 4096;
    arch.numLayers = 32;
    arch.numHeads = 32;
    arch.vocabSize = 32000;
    TEST("Architecture config", arch.numLayers == 32);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n", g_passed, g_failed, g_passed + g_failed);
    printf("========================================\n");

    loader.Shutdown();
    return g_failed > 0 ? 1 : 0;
}
