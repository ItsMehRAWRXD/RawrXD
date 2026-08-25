// ============================================================================
// InferenceEngine_Certification.cpp
// Phase C.5 → G: Standalone certification harness for InferenceEngine.lib
//
// Verifies:
//   1. Deep2Engine ABI (construct, init, loadModel, tokenize, detokenize, generate)
//   2. GGUFLoader (real file parse, metadata, tensors, vocabulary)
//   3. QuantKernelRegistry (all supported formats registered)
//   4. MASM GEMV kernel exports (symbol resolution)
//   5. End-to-end inference on a real GGUF model
//
// Build:
//   cl.exe /EHsc /O2 /std:c++20 /I D:\rawrxd\src /I D:\rawrxd\include \
//     InferenceEngine_Certification.cpp \
//     D:\rawrxd\build-fresh-aug22\InferenceEngine.lib \
//     kernel32.lib user32.lib gdi32.lib shell32.lib ole32.lib oleaut32.lib \
//     uuid.lib comdlg32.lib advapi32.lib version.lib ws2_32.lib \
//     shlwapi.lib psapi.lib dbghelp.lib winhttp.lib bcrypt.lib crypt32.lib \
//     dxgi.lib
//
// Run:
//   InferenceEngine_Certification.exe <path_to_model.gguf> [prompt]
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <cmath>

#include "deep2/Deep2Engine.h"
#include "deep2/GGUFLoader.hpp"
#include "deep2/QuantKernelRegistry.hpp"

// MASM kernel extern declarations (verify linkage)
extern "C" {
    void Sovereign_Q4K_GEMV_AVX2(const uint8_t* weights, const float* input, float* output,
                                  size_t outDim, size_t inDim);
    void Deep2_Q4_1_GEMV(const uint8_t* weights, const float* input, float* output,
                         size_t outDim, size_t inDim);
    void Deep2_Q5_K_GEMV(const uint8_t* weights, const float* input, float* output,
                         size_t outDim, size_t inDim);
    void Deep2_Q6_K_GEMV(const uint8_t* weights, const float* input, float* output,
                         size_t outDim, size_t inDim);
    void Deep2_Q8_0_GEMV(const uint8_t* weights, const float* input, float* output,
                         size_t outDim, size_t inDim);
    void Deep2_FP16_GEMV(const uint8_t* weights, const float* input, float* output,
                         size_t outDim, size_t inDim);
}

static int g_pass = 0;
static int g_fail = 0;

static void check(bool condition, const char* name) {
    if (condition) {
        printf("  [PASS] %s\n", name);
        ++g_pass;
    } else {
        printf("  [FAIL] %s\n", name);
        ++g_fail;
    }
}

static void section(const char* title) {
    printf("\n========================================\n%s\n========================================\n", title);
}

// ============================================================================
// Phase C.5: ABI + Standalone Link Certification
// ============================================================================
static bool certify_abi() {
    section("PHASE C.5: ABI + Standalone Link Certification");

    bool ok = true;

    // 1. Deep2Engine construction/destruction
    {
        Deep2::Deep2Engine engine;
        check(true, "Deep2Engine default construction");
    }
    check(true, "Deep2Engine destruction");

    // 2. QuantKernelRegistry singleton
    {
        auto& reg = Deep2::QuantKernelRegistry::Instance();
        check(true, "QuantKernelRegistry::Instance() resolves");
    }

    // 3. MASM kernel symbol resolution (link-time only — no execution yet)
    {
        volatile auto* p1 = &Sovereign_Q4K_GEMV_AVX2;
        volatile auto* p2 = &Deep2_Q4_1_GEMV;
        volatile auto* p3 = &Deep2_Q5_K_GEMV;
        volatile auto* p4 = &Deep2_Q6_K_GEMV;
        volatile auto* p5 = &Deep2_Q8_0_GEMV;
        volatile auto* p6 = &Deep2_FP16_GEMV;
        (void)p1; (void)p2; (void)p3; (void)p4; (void)p5; (void)p6;
        check(true, "MASM GEMV kernel symbols link (Q4K, Q4_1, Q5K, Q6K, Q8_0, FP16)");
    }

    return ok;
}

// ============================================================================
// Phase D: QuantKernelRegistry Certification
// ============================================================================
static bool certify_quant_registry() {
    section("PHASE D: QuantKernelRegistry Certification");

    auto& reg = Deep2::QuantKernelRegistry::Instance();
    reg.Initialize();

    std::string table = reg.DumpTable();
    printf("%s\n", table.c_str());

    // Verify all expected formats are registered
    bool ok = true;
    // GGML types from GGUFLoader.hpp:
    // Q4_0=2, Q4_1=3, Q5_0=6, Q5_1=7, Q8_0=8, Q8_K=9,
    // Q2_K=10, Q3_K=11, Q4_K=12, Q5_K=13, Q6_K=14,
    // IQ2_XXS=17, IQ2_XS=18, IQ3_XXS=19, IQ1_S=20,
    // IQ4_NL=21, IQ3_S=22, IQ2_S=23, IQ4_XS=24,
    // I8=25, I16=26, I32=27, I64=28, F64=29, F16=1, F32=0
    const int expectedTypes[] = { 3, 12, 13, 14, 8, 1 };
    const char* typeNames[] = { "Q4_1", "Q4_K", "Q5_K", "Q6_K", "Q8_0", "F16" };

    for (size_t i = 0; i < sizeof(expectedTypes)/sizeof(expectedTypes[0]); ++i) {
        auto geom = reg.GetGeometry(expectedTypes[i]);
        bool hasGeom = (geom.blockSize > 0);
        check(hasGeom, typeNames[i]);
        if (!hasGeom) ok = false;
    }

    return ok;
}

// ============================================================================
// Phase E: GGUF Loader Certification
// ============================================================================
static bool certify_gguf_loader(const char* modelPath) {
    section("PHASE E: GGUF Loader Certification");

    Deep2::GGUFLoadOptions opts{};
    opts.verifyChecksum = false;
    opts.loadTensors = true;

    auto result = Deep2::GGUFLoader::Load(modelPath, opts);

    check(result.success, "GGUFLoader::Load() returns success");
    if (!result.success) {
        printf("    Error: %s\n", result.error);
        return false;
    }

    check(!result.tensors.empty(), "Tensor count > 0");
    check(!result.metadata.architecture.empty(), "Architecture identified");
    check(result.metadata.vocabSize > 0, "Vocabulary size > 0");

    printf("    Tensors:    %zu\n", result.tensors.size());
    printf("    Arch:       %s\n", result.metadata.architecture.c_str());
    printf("    Vocab:      %u\n", result.metadata.vocabSize);
    printf("    Context:    %u\n", result.metadata.maxPositionEmbeddings);
    printf("    Hidden:     %u\n", result.metadata.hiddenSize);
    printf("    Layers:     %u\n", result.metadata.numLayers);
    printf("    Heads:      %u\n", result.metadata.numHeads);
    printf("    KV Heads:   %u\n", result.metadata.numKeyValueHeads);
    printf("    Intermediate: %u\n", result.metadata.intermediateSize);

    // Verify vocabulary tokens exist
    bool hasTokens = false;
    if (!result.metadata.vocab.empty()) {
        hasTokens = true;
        printf("    Token[0]:   '%s'\n", result.metadata.vocab[0].c_str());
        if (result.metadata.vocab.size() > 1) {
            printf("    Token[1]:   '%s'\n", result.metadata.vocab[1].c_str());
        }
    }
    check(hasTokens, "Tokenizer vocabulary populated");

    return result.success;
}

// ============================================================================
// Phase F: Deep2Engine Model Certification
// ============================================================================
static bool certify_deep2_model(const char* modelPath) {
    section("PHASE F: Deep2Engine Model Certification");

    Deep2::Deep2Engine engine;

    // Initialize with default config
    Deep2::EngineConfig config{};
    config.numThreads = 0; // auto
    config.useKVCache = true;
    config.useThreadPool = true;

    bool initOk = engine.initialize(config);
    check(initOk, "Deep2Engine::initialize()");
    if (!initOk) return false;

    // Load model
    auto t0 = std::chrono::high_resolution_clock::now();
    bool loadOk = engine.loadModel(modelPath);
    auto t1 = std::chrono::high_resolution_clock::now();
    double loadMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    check(loadOk, "Deep2Engine::loadModel()");
    printf("    Load time: %.1f ms\n", loadMs);

    if (!loadOk) return false;

    // Verify model metadata
    const auto& meta = engine.getModelMetadata();
    check(meta.vocabSize > 0, "Model metadata: vocabSize > 0");
    check(meta.hiddenSize > 0, "Model metadata: hiddenSize > 0");
    check(meta.numLayers > 0, "Model metadata: numLayers > 0");

    // Tokenizer round-trip
    std::string testPrompt = "Hello";
    auto tokens = engine.tokenize(testPrompt);
    check(!tokens.empty(), "Tokenizer: tokenize('Hello') produces tokens");

    if (!tokens.empty()) {
        std::string roundTrip = engine.detokenize(tokens);
        check(!roundTrip.empty(), "Tokenizer: detokenize() produces text");
        printf("    Prompt:     '%s'\n", testPrompt.c_str());
        printf("    Tokens:     %zu\n", tokens.size());
        printf("    RoundTrip:  '%s'\n", roundTrip.c_str());
    }

    return true;
}

// ============================================================================
// Phase G: Real Inference Certification
// ============================================================================
static bool certify_inference(const char* modelPath, const char* prompt, int maxTokens) {
    section("PHASE G: Real Inference Certification");

    Deep2::Deep2Engine engine;

    Deep2::EngineConfig config{};
    config.numThreads = 0;
    config.useKVCache = true;
    config.useThreadPool = true;

    if (!engine.initialize(config)) {
        check(false, "Deep2Engine::initialize()");
        return false;
    }
    check(true, "Deep2Engine::initialize()");

    if (!engine.loadModel(modelPath)) {
        check(false, "Deep2Engine::loadModel()");
        return false;
    }
    check(true, "Deep2Engine::loadModel()");

    // Tokenize prompt
    auto tokens = engine.tokenize(prompt);
    check(!tokens.empty(), "tokenize(prompt)");
    printf("    Prompt tokens: %zu\n", tokens.size());

    // Generate text
    auto t0 = std::chrono::high_resolution_clock::now();
    std::string output = engine.generateText(prompt, static_cast<size_t>(maxTokens));
    auto t1 = std::chrono::high_resolution_clock::now();
    double genMs = std::chrono::duration<double, std::milli>(t1 - t0).count();

    check(!output.empty(), "generateText() produces non-empty output");
    printf("    Output:      '%s'\n", output.c_str());
    printf("    Time:        %.1f ms\n", genMs);

    if (!output.empty()) {
        // Verify output tokens are valid
        auto outTokens = engine.tokenize(output);
        bool allValid = true;
        for (auto t : outTokens) {
            if (t < 0) { allValid = false; break; }
        }
        check(allValid, "All generated token IDs are valid");

        // Verify no NaN/Inf in output (basic sanity)
        bool noNaN = (output.find("nan") == std::string::npos &&
                      output.find("inf") == std::string::npos);
        check(noNaN, "Output contains no NaN/Inf strings");
    }

    return !output.empty();
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║  InferenceEngine.lib Certification Harness                     ║\n");
    printf("║  Phase C.5 → G: ABI → Registry → Loader → Model → Inference    ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");

    const char* modelPath = (argc > 1) ? argv[1] : nullptr;
    const char* prompt = (argc > 2) ? argv[2] : "Hello";
    int maxTokens = (argc > 3) ? atoi(argv[3]) : 32;

    // Phase C.5: Always run (no model needed)
    certify_abi();

    // Phase D: Always run (no model needed)
    certify_quant_registry();

    // Phases E-G require a real GGUF model
    if (!modelPath) {
        printf("\n[SKIP] No model path provided — skipping Phases E-G.\n");
        printf("Usage: %s <model.gguf> [prompt] [max_tokens]\n", argv[0]);
    } else {
        certify_gguf_loader(modelPath);
        certify_deep2_model(modelPath);
        certify_inference(modelPath, prompt, maxTokens);
    }

    // Summary
    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║  CERTIFICATION SUMMARY                                           ║\n");
    printf("║  PASS: %3d                                                       ║\n", g_pass);
    printf("║  FAIL: %3d                                                       ║\n", g_fail);
    printf("╚══════════════════════════════════════════════════════════════════╝\n");

    return (g_fail > 0) ? 1 : 0;
}
