// test_attention_core_phase31.cpp
// Phase 3.1 — Attention Core Micro-Harness
// Validates Q/K/V projections + attention math with hash checkpoints.
// No sampler, no tokenizer, no generation loop, no KV cache.
//
// Build: ninja test_attention_core_phase31
// Run:  .\test_attention_core_phase31.exe <model.gguf>

#include "SovereignInferenceEngine.hpp"
#include <cstdio>
#include <cstdint>
#include <windows.h>

using namespace RawrXD::AI;

static bool RunAttentionCore(const char* model_path,
                              const float* input,
                              uint32_t n_embd,
                              SovereignInferenceEngine::AttentionStageHashes& out_hashes) {
    SovereignEngineConfig cfg{};
    cfg.model_path = model_path;
    cfg.max_context_length = 128;

    SovereignInferenceEngine engine(cfg);
    if (!engine.Initialize()) {
        fprintf(stderr, "FATAL: engine.Initialize() failed\n");
        return false;
    }

    // Run attention core and capture stage hashes
    if (!engine.RunAttentionCore(input, n_embd, out_hashes)) {
        fprintf(stderr, "FATAL: RunAttentionCore() failed\n");
        return false;
    }
    return true;
}

static void PrintHashes(const SovereignInferenceEngine::AttentionStageHashes& h, const char* label) {
    printf("%s:\n", label);
    printf("  hash(input)    = %016llX\n", (unsigned long long)h.hash_input);
    printf("  hash(Q)        = %016llX\n", (unsigned long long)h.hash_q);
    printf("  hash(K)        = %016llX\n", (unsigned long long)h.hash_k);
    printf("  hash(V)        = %016llX\n", (unsigned long long)h.hash_v);
    printf("  hash(scores)   = %016llX\n", (unsigned long long)h.hash_scores);
    printf("  hash(softmax)  = %016llX\n", (unsigned long long)h.hash_softmax);
    printf("  hash(context)  = %016llX\n", (unsigned long long)h.hash_context);
    printf("  hash(attn_out) = %016llX\n", (unsigned long long)h.hash_attn_out);
}

int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    const uint32_t n_embd = 4096;

    printf("=== Attention Core Micro-Harness ===\n");
    printf("Model: %s\n", model_path);
    printf("n_embd: %u\n", n_embd);

    // Build deterministic input vector
    float* input = (float*)_aligned_malloc(n_embd * sizeof(float), 64);
    for (uint32_t i = 0; i < n_embd; ++i) {
        input[i] = static_cast<float>(i) * 0.001f;
    }

    // Run two independent instances
    SovereignInferenceEngine::AttentionStageHashes hashes_a{};
    SovereignInferenceEngine::AttentionStageHashes hashes_b{};

    printf("\n--- Instance A ---\n");
    if (!RunAttentionCore(model_path, input, n_embd, hashes_a)) {
        _aligned_free(input);
        return 1;
    }
    PrintHashes(hashes_a, "Instance A");

    printf("\n--- Instance B ---\n");
    if (!RunAttentionCore(model_path, input, n_embd, hashes_b)) {
        _aligned_free(input);
        return 1;
    }
    PrintHashes(hashes_b, "Instance B");

    // Validate bit-perfect identity across all stages
    bool pass = true;
    auto check = [&pass](const char* name, uint64_t a, uint64_t b) {
        if (a != b) {
            printf("MISMATCH %s: A=%016llX B=%016llX\n", name, (unsigned long long)a, (unsigned long long)b);
            pass = false;
        }
    };

    printf("\n--- Validation ---\n");
    check("input",    hashes_a.hash_input,    hashes_b.hash_input);
    check("Q",        hashes_a.hash_q,        hashes_b.hash_q);
    check("K",        hashes_a.hash_k,        hashes_b.hash_k);
    check("V",        hashes_a.hash_v,        hashes_b.hash_v);
    check("scores",   hashes_a.hash_scores,   hashes_b.hash_scores);
    check("softmax",  hashes_a.hash_softmax,  hashes_b.hash_softmax);
    check("context",  hashes_a.hash_context,  hashes_b.hash_context);
    check("attn_out", hashes_a.hash_attn_out, hashes_b.hash_attn_out);

    printf("\nOVERALL: %s\n", pass ? "PASS" : "FAIL");

    // -----------------------------------------------------------------------
    // Phase 3.1b — 1000-iteration stability test (single engine, catches buffer reuse / stale memory)
    // -----------------------------------------------------------------------
    if (pass) {
        printf("\n=== 1000-Iteration Stability Test ===\n");
        uint64_t first_hash = hashes_a.hash_context;
        bool stable = true;

        // Reuse a single engine for all iterations (avoid 1000x disk load)
        SovereignEngineConfig cfg{};
        cfg.model_path = model_path;
        cfg.max_context_length = 128;
        SovereignInferenceEngine engine(cfg);
        if (!engine.Initialize()) {
            printf("STABILITY: engine init failed\n");
            stable = false;
        } else {
            LARGE_INTEGER freq, t0, t1;
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&t0);
            for (int iter = 0; iter < 1000; ++iter) {
                SovereignInferenceEngine::AttentionStageHashes h{};
                if (!engine.RunAttentionCore(input, n_embd, h)) {
                    printf("STABILITY: RunAttentionCore failed at iter %d\n", iter);
                    stable = false;
                    break;
                }
                if (h.hash_context != first_hash) {
                    printf("STABILITY BREACH at iter %d: expected %016llX got %016llX\n",
                           iter, (unsigned long long)first_hash, (unsigned long long)h.hash_context);
                    stable = false;
                    break;
                }
            }
            QueryPerformanceCounter(&t1);
            double elapsed_ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
            printf("1000 iterations: %.2f ms (%.3f ms/iter) — %s\n",
                   elapsed_ms, elapsed_ms / 1000.0, stable ? "STABLE" : "UNSTABLE");
        }
        if (!stable) pass = false;
    }

    _aligned_free(input);
    return pass ? 0 : 1;
}
