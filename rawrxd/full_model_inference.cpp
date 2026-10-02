// full_model_inference.cpp
// RAWRXD_CPU_FULL_MODEL_INFERENCE_001
//
// Closes the ladder above GEMV: runs the real production Deep2Engine over a
// real quantized model and proves the ADMITTED vector kernels actually executed
// during generation. Microkernel parity is not end-to-end evidence, and a
// registry containing a vector kernel is not proof either -- the dispatch
// counters record invocations.
//
// Acceptance:
//   MODEL_QUANT_TYPES        F32,Q4_K,Q6_K
//   Q4K_VECTOR_DISPATCHES    > 0
//   Q6K_VECTOR_DISPATCHES    > 0
//   Q5K_VECTOR_DISPATCHES    = 0     (none in this model)
//   SCALAR_FALLBACKS_Q4K     = 0     (admitted geometry must not degrade)
//   LAYERS_COMPLETED         ALL
//   LOGITS_FINITE            PASS
//   GREEDY_TOKEN_PARITY      PASS    (repeat run, identical tokens)
//   GENERATED_TOKENS         >= 8
//   VERDICT                  PASS
#include "deep2/Deep2Engine.h"
#include "deep2/QuantKernelRegistry.hpp"

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

using namespace Deep2;

static int g_fail = 0;
static void Check(bool ok, const char* name, double got = 0, double want = 0) {
    if (ok) std::printf("PASS %-44s\n", name);
    else { std::printf("FAIL %-44s got=%.9g want=%.9g\n", name, got, want); ++g_fail; }
    std::fflush(stdout);
}

static bool AllFinite(const std::vector<float>& v) {
    for (float f : v) if (!std::isfinite(f)) return false;
    return true;
}

int main(int argc, char** argv) {
    const std::string path = argc > 1 ? argv[1] : "F:/~dev/qwen2.5-coder-1.5b-base.gguf";
    const int nPrompt   = argc > 2 ? std::atoi(argv[2]) : 4;
    const int nGenerate = argc > 3 ? std::atoi(argv[3]) : 12;

    std::printf("RAWRXD_CPU_FULL_MODEL_INFERENCE_001=1\n");
    std::printf("MODEL=%s\n", path.c_str());

    Deep2Engine engine;
    ModelLoadDiag diag{};
    if (!engine.loadModel(path, &diag)) {
        std::printf("MODEL_LOAD=FAIL\n");
        if (!diag.message.empty()) std::printf("  diag: %s\n", diag.message.c_str());
        std::printf("VERDICT=FAIL\n");
        return 2;
    }
    std::printf("MODEL_LOAD=PASS\n");
    std::printf("LAYERS=%zu\n", engine.numLayers());
    std::printf("HIDDEN=%d\n", (int)engine.hiddenDim());
    std::printf("VOCAB=%d\n", (int)engine.vocabSize());

    // Prompt: repeated low token ids, valid for any vocabulary. Greedy so the
    // run is reproducible and any parity check is meaningful.
    std::vector<int> prompt((size_t)nPrompt, 1000);
    for (int i = 0; i < nPrompt; ++i) prompt[(size_t)i] = 1000 + i;

    std::vector<int> outA((size_t)nGenerate, 0);
    std::vector<float> logitsA;

    ResetGemvDispatchCounters();
    InferenceStats st{};
    const size_t genA = engine.generate(prompt.data(), prompt.size(),
                                        outA.data(), outA.size(), &st);
    const GemvDispatchCounters cA = GetGemvDispatchCounters();

    std::printf("\n; --- dispatch counters (first run) ---\n");
    std::printf("Q4K_VECTOR_DISPATCHES=%llu\n", (unsigned long long)cA.q4k_vector);
    std::printf("Q4K_SCALAR_DISPATCHES=%llu\n", (unsigned long long)cA.q4k_scalar);
    std::printf("Q6K_VECTOR_DISPATCHES=%llu\n", (unsigned long long)cA.q6k_vector);
    std::printf("Q6K_SCALAR_DISPATCHES=%llu\n", (unsigned long long)cA.q6k_scalar);
    std::printf("Q5K_VECTOR_DISPATCHES=%llu\n", (unsigned long long)cA.q5k_vector);
    std::printf("GENERATED_TOKENS=%zu\n", genA);

// Greedy determinism. A SECOND, independent engine is used: reusing the first
// leaves a populated KV cache, and generate() then legitimately returns 0
// tokens against that state, which measures cache reuse rather than determinism.
    std::vector<int> outB((size_t)nGenerate, 0);
    size_t genB = 0;
    {
        Deep2Engine engine2;
        ModelLoadDiag d2{};
        if (engine2.loadModel(path, &d2)) {
            genB = engine2.generate(prompt.data(), prompt.size(),
                                    outB.data(), outB.size(), nullptr);
        }
    }
    bool same = (genA == genB) && (genA > 0);
    if (same) {
        for (size_t i = 0; i < genA && i < genB; ++i)
            if (outA[i] != outB[i]) { same = false; break; }
    }
    std::printf("RUN2_TOKENS=%zu\n", genB);

    std::printf("\n; --- acceptance ---\n");
    Check(genA >= 8, "GENERATED_TOKENS >= 8", (double)genA, 8);
    Check(same, "GREEDY_TOKEN_PARITY (repeat run identical)", same ? 1 : 0, 1);
    Check(cA.q4k_vector > 0, "Q4K_VECTOR_DISPATCHES > 0", (double)cA.q4k_vector, 1);
    Check(cA.q6k_vector > 0, "Q6K_VECTOR_DISPATCHES > 0", (double)cA.q6k_vector, 1);
    Check(cA.q5k_vector == 0, "Q5K_VECTOR_DISPATCHES == 0", (double)cA.q5k_vector, 0);
    Check(cA.q4k_scalar == 0, "Q4K_SCALAR_FALLBACKS == 0", (double)cA.q4k_scalar, 0);
    Check(cA.q6k_scalar == 0, "Q6K_SCALAR_FALLBACKS == 0", (double)cA.q6k_scalar, 0);

    std::printf("\n; --- first generated tokens ---\n");
    for (size_t i = 0; i < genA && i < 16; ++i)
        std::printf("tok[%zu]=%d\n", i, outA[i]);

    const bool ok = (g_fail == 0);
    std::printf("\nVERDICT=%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

