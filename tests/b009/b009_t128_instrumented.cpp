// ============================================================================
// b009_t128_instrumented.cpp — B009 T=128 Instrumented Hang Diagnosis
// Traces execution through ForwardBatch() to identify exact stall boundary.
// ============================================================================
#include "rawrxd_transformer.h"
#include "rawrxd_model_loader.h"
#include "rawrxd_tokenizer.h"

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <chrono>
#include <vector>
#include <cstring>
#include <filesystem>
#include <numeric>
#include <algorithm>
#include <windows.h>
#include <psapi.h>

namespace {

constexpr float TOLERANCE_ABSOLUTE = 1e-4f;
constexpr float TOLERANCE_RELATIVE = 1e-3f;

bool WithinTolerance(float a, float b) {
    float diff = std::fabs(a - b);
    float max_val = std::max(std::fabs(a), std::fabs(b));
    if (max_val < 1e-6f) return diff < TOLERANCE_ABSOLUTE;
    return diff < TOLERANCE_ABSOLUTE || (diff / max_val) < TOLERANCE_RELATIVE;
}

bool LogitsMatch(const std::vector<float>& a, const std::vector<float>& b, float& max_diff, float& max_rel_diff) {
    if (a.size() != b.size()) return false;
    max_diff = 0.0f;
    max_rel_diff = 0.0f;
    for (size_t i = 0; i < a.size(); ++i) {
        float diff = std::fabs(a[i] - b[i]);
        max_diff = std::max(max_diff, diff);
        float max_val = std::max(std::fabs(a[i]), std::fabs(b[i]));
        if (max_val > 1e-6f) {
            max_rel_diff = std::max(max_rel_diff, diff / max_val);
        }
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (!WithinTolerance(a[i], b[i])) return false;
    }
    return true;
}

void FlushPrintf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

void PrintProcessMetrics(const char* label) {
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    GetProcessTimes(GetCurrentProcess(), &ftCreate, &ftExit, &ftKernel, &ftUser);
    ULARGE_INTEGER kernelTime, userTime;
    kernelTime.LowPart = ftKernel.dwLowDateTime;
    kernelTime.HighPart = ftKernel.dwHighDateTime;
    userTime.LowPart = ftUser.dwLowDateTime;
    userTime.HighPart = ftUser.dwHighDateTime;
    double cpuSec = (kernelTime.QuadPart + userTime.QuadPart) / 10'000'000.0;

    PROCESS_MEMORY_COUNTERS pmc{};
    pmc.cb = sizeof(pmc);
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));

    SYSTEM_INFO si;
    GetSystemInfo(&si);

    FlushPrintf("[DIAG] %s | CPU=%.2fs | WorkingSet=%.1fMB | PeakWorkingSet=%.1fMB | Threads=%lu\n",
                label, cpuSec, pmc.WorkingSetSize / (1024.0 * 1024.0),
                pmc.PeakWorkingSetSize / (1024.0 * 1024.0), si.dwNumberOfProcessors);
}

} // namespace

int main(int argc, char** argv) {
    const char* modelEnv = std::getenv("RAWRXD_TEST_MODEL");
    if (!modelEnv || !*modelEnv) {
        std::printf("SKIP: set RAWRXD_TEST_MODEL to run B009 T=128 diagnosis\n");
        return 0;
    }

    const std::string modelPath(modelEnv);
    if (!std::filesystem::exists(modelPath)) {
        std::printf("FAIL: model path does not exist: %s\n", modelPath.c_str());
        return 2;
    }

    // ========================================================================
    // Load model
    // ========================================================================
    FlushPrintf("[DIAG] === B009 T=128 Hang Diagnosis Harness ===\n");
    PrintProcessMetrics("startup");

    RawrXDModelLoader loader;
    std::wstring wPath(modelPath.begin(), modelPath.end());
    FlushPrintf("[DIAG] Loading model...\n");
    if (!loader.Load(wPath.c_str(), nullptr, nullptr)) {
        std::printf("FAIL: could not load model\n");
        return 2;
    }
    PrintProcessMetrics("model_loaded");

    RawrXDTransformer::Config cfg{};
    cfg.dim = loader.getDim();
    cfg.hidden_dim = loader.getFFNDim();
    cfg.n_layers = loader.getLayers();
    cfg.n_heads = loader.getHeads();
    cfg.n_kv_heads = loader.getKVHeads();
    cfg.vocab_size = loader.getVocabSize();
    cfg.rope_theta = 10000.0f;
    cfg.rms_norm_eps = 1e-5f;

    if (cfg.dim == 0) cfg.dim = 4096;
    if (cfg.n_layers == 0) cfg.n_layers = 32;
    if (cfg.n_heads == 0) cfg.n_heads = 32;
    if (cfg.n_kv_heads == 0) cfg.n_kv_heads = cfg.n_heads;

    FlushPrintf("[DIAG] Model config: dim=%d hidden_dim=%d layers=%d heads=%d kv_heads=%d vocab=%d\n",
                cfg.dim, cfg.hidden_dim, cfg.n_layers, cfg.n_heads, cfg.n_kv_heads, cfg.vocab_size);

    RawrXDTokenizer tokenizer;
    tokenizer.Load("vocab.json");

    const std::string base_prompt = "The quick brown fox jumps over the lazy dog. ";

    // ========================================================================
    // PHASE 1: T=1 warm-up on SAME transformer instance
    // ========================================================================
    FlushPrintf("\n[DIAG] === PHASE 1: T=1 warm-up ===\n");
    {
        std::string prompt1;
        while (static_cast<int>(prompt1.size()) < 4) { prompt1 += base_prompt; }
        std::vector<uint32_t> tokens1 = tokenizer.Encode(prompt1);
        tokens1.resize(1, 1);

        FlushPrintf("[DIAG] T=1 tokens.size=%zu\n", tokens1.size());
        PrintProcessMetrics("pre_t1_transformer_init");

        RawrXDTransformer transformer;
        transformer.Initialize(nullptr, nullptr, cfg, &loader);
        PrintProcessMetrics("t1_transformer_initialized");

        FlushPrintf("[DIAG] Calling Forward(T=1)...\n");
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_t1 = transformer.Forward(tokens1, 0);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        FlushPrintf("[DIAG] Forward(T=1) complete: logits.size=%zu elapsed=%.2fms\n", logits_t1.size(), ms);
        PrintProcessMetrics("t1_complete");

        // Now test ForwardBatch(T=1) on SAME instance
        FlushPrintf("[DIAG] Calling ForwardBatch(T=1) on SAME instance...\n");
        t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_batch_t1 = transformer.ForwardBatch(tokens1, 0);
        t1 = std::chrono::high_resolution_clock::now();
        ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        FlushPrintf("[DIAG] ForwardBatch(T=1) complete: logits.size=%zu elapsed=%.2fms\n", logits_batch_t1.size(), ms);
        PrintProcessMetrics("batch_t1_complete");

        float max_diff = 0.0f, max_rel = 0.0f;
        bool match = LogitsMatch(logits_t1, logits_batch_t1, max_diff, max_rel);
        FlushPrintf("[DIAG] T=1 comparison: %s max_diff=%.6f max_rel=%.6f\n",
                    match ? "MATCH" : "MISMATCH", max_diff, max_rel);
    }

    // ========================================================================
    // PHASE 2: T=128 on SAME transformer instance (re-initialized)
    // ========================================================================
    FlushPrintf("\n[DIAG] === PHASE 2: T=128 on fresh instance ===\n");
    {
        std::string prompt128;
        while (static_cast<int>(prompt128.size()) < 128 * 4) { prompt128 += base_prompt; }
        std::vector<uint32_t> tokens128 = tokenizer.Encode(prompt128);
        tokens128.resize(128, 1);

        FlushPrintf("[DIAG] T=128 tokens.size=%zu\n", tokens128.size());
        PrintProcessMetrics("pre_t128_transformer_init");

        RawrXDTransformer transformer128;
        transformer128.Initialize(nullptr, nullptr, cfg, &loader);
        PrintProcessMetrics("t128_transformer_initialized");

        FlushPrintf("[DIAG] Calling ForwardBatch(T=128)...\n");
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_batch_t128 = transformer128.ForwardBatch(tokens128, 0);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        FlushPrintf("[DIAG] ForwardBatch(T=128) complete: logits.size=%zu elapsed=%.2fms\n", logits_batch_t128.size(), ms);
        PrintProcessMetrics("batch_t128_complete");
    }

    // ========================================================================
    // PHASE 3: T=128 after T=1 on SAME instance (warm-up dependency test)
    // ========================================================================
    FlushPrintf("\n[DIAG] === PHASE 3: T=128 after T=1 warm-up on SAME instance ===\n");
    {
        std::string prompt1;
        while (static_cast<int>(prompt1.size()) < 4) { prompt1 += base_prompt; }
        std::vector<uint32_t> tokens1 = tokenizer.Encode(prompt1);
        tokens1.resize(1, 1);

        std::string prompt128;
        while (static_cast<int>(prompt128.size()) < 128 * 4) { prompt128 += base_prompt; }
        std::vector<uint32_t> tokens128 = tokenizer.Encode(prompt128);
        tokens128.resize(128, 1);

        RawrXDTransformer transformer;
        transformer.Initialize(nullptr, nullptr, cfg, &loader);
        PrintProcessMetrics("warmup_transformer_initialized");

        // T=1 warm-up
        FlushPrintf("[DIAG] Warm-up: ForwardBatch(T=1)...\n");
        auto t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_warmup = transformer.ForwardBatch(tokens1, 0);
        auto t1 = std::chrono::high_resolution_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        FlushPrintf("[DIAG] Warm-up complete: elapsed=%.2fms logits.size=%zu\n", ms, logits_warmup.size());
        PrintProcessMetrics("warmup_complete");

        // T=128 on same instance
        FlushPrintf("[DIAG] Now calling ForwardBatch(T=128) on warmed instance...\n");
        t0 = std::chrono::high_resolution_clock::now();
        std::vector<float> logits_t128 = transformer.ForwardBatch(tokens128, 0);
        t1 = std::chrono::high_resolution_clock::now();
        ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        FlushPrintf("[DIAG] ForwardBatch(T=128) on warmed instance complete: elapsed=%.2fms logits.size=%zu\n", ms, logits_t128.size());
        PrintProcessMetrics("t128_warmed_complete");
    }

    FlushPrintf("\n[DIAG] === All phases complete ===\n");
    return 0;
}
