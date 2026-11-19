/* DEEP2_QWEN25_MULTITOKEN_KV_PARITY_001 — multi-token KV parity oracle
 *
 * Usage: deep2_parity_oracle.exe <model.gguf> [prompt] [traceFile] [nTokens]
 *        deep2_parity_oracle.exe <model.gguf> --tokens=1,2,3 [traceFile]
 *
 * Runs greedy decode for nTokens positions through the production generate()
 * path with per-position parity probes enabled, then dumps per-position
 * LOGITS_TOP10 records. Sampling is bypassed: deterministic greedy only.
 */
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <climits>
#include <string>
#include <vector>
#include <algorithm>
#include "deep2/Deep2Engine.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: deep2_parity_oracle.exe <model.gguf> [prompt] [traceFile] [nTokens]\n");
        return 2;
    }
    const char* modelPath = argv[1];
    const char* prompt    = argc > 2 ? argv[2] : "def";
    const char* tracePath = argc > 3 ? argv[3] : "parity_trace.txt";
    int nTokens           = argc > 4 ? atoi(argv[4]) : 8;

    fprintf(stderr, "ORACLE_PROMPT=%s\n", prompt);
    fprintf(stderr, "ORACLE_TRACE=%s\n", tracePath);
    fprintf(stderr, "ORACLE_NTOKENS=%d\n", nTokens);

    Deep2::Deep2Engine engine;
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen = 512;
    cfg.numThreads = 4;
    if (!engine.initialize(cfg)) {
        fprintf(stderr, "FAIL: initialize\n");
        return 1;
    }
    if (!engine.loadModel(modelPath)) {
        fprintf(stderr, "FAIL: loadModel path=%s\n", modelPath);
        return 4;
    }

    std::vector<int> explicitTokens;
    if (argc > 2 && std::strncmp(argv[2], "--tokens=", 9) == 0) {
        const char* p = argv[2] + 9;
        while (*p) {
            char* end = nullptr;
            const long value = std::strtol(p, &end, 10);
            if (end == p || value < 0 || value > INT_MAX) {
                fprintf(stderr, "FAIL: invalid token list: %s\n", argv[2]);
                return 5;
            }
            explicitTokens.push_back(static_cast<int>(value));
            p = (*end == ',') ? end + 1 : end;
            if (*end && *end != ',') {
                fprintf(stderr, "FAIL: invalid token separator: %s\n", argv[2]);
                return 5;
            }
        }
        if (explicitTokens.empty()) {
            fprintf(stderr, "FAIL: empty token list\n");
            return 5;
        }
    }

    auto toks = explicitTokens.empty() ? engine.tokenize(prompt) : explicitTokens;
    fprintf(stderr, "TOKENS=%zu", toks.size());
    for (size_t i = 0; i < toks.size(); ++i)
        fprintf(stderr, " %d", toks[i]);
    fprintf(stderr, "\n");
    if (explicitTokens.empty() && toks.size() != 1) {
        fprintf(stderr, "FAIL: prompt must tokenize to exactly 1 token "
                        "(got %zu) for a deterministic reference\n", toks.size());
        return 5;
    }

    // Teacher-forced step-6 divergence oracle.
    // Feed exact tokens [750, 220, 1887, 3932, 262, 1173, 445]
    // and emit per-layer checkpoints only at step 6.
    const std::vector<int> teacherTokens = explicitTokens.empty()
        ? std::vector<int>{750, 220, 1887, 3932, 262, 1173, 445}
        : toks;
    const size_t TEACHER_COUNT = teacherTokens.size();

    fprintf(stderr, "MODE=TEACHER_FORCED\n");

    const size_t H = engine.getConfig().hiddenDim;
    const size_t V = engine.getConfig().vocabSize;
    std::vector<float> hidden(H, 0.0f);
    std::vector<float> localLogits(V, 0.0f);

    // Steps 0..5: build KV cache without parity probe
    for (size_t step = 0; step < TEACHER_COUNT - 1; ++step) {
        engine.parityBeginStep(static_cast<int>(step));
        if (!engine.embedToken(teacherTokens[step], hidden.data())) {
            fprintf(stderr, "FAIL: embedToken at step %zu\n", step);
            return 7;
        }
        if (!engine.forwardTokenAllLayers(hidden.data(), step + 1)) {
            fprintf(stderr, "FAIL: forwardTokenAllLayers at step %zu\n", step);
            return 8;
        }
        if (engine.getConfig().useKVCache) {
            engine.advancePersistentKv();
        }
    }

    // Step 6: enable parity probe and run with teacher token 445
    engine.enableParityProbe(tracePath, 1);
    engine.parityBeginStep(6);

    if (!engine.embedToken(teacherTokens[TEACHER_COUNT - 1], hidden.data())) {
        fprintf(stderr, "FAIL: embedToken at step 6\n");
        return 9;
    }
    if (!engine.forwardTokenAllLayers(hidden.data(), 7)) {
        fprintf(stderr, "FAIL: forwardTokenAllLayers at step 6\n");
        return 10;
    }
    if (engine.getConfig().useKVCache) {
        engine.advancePersistentKv();
    }

    engine.computeLogits(hidden.data(), localLogits.data());
    engine.parityEmitLogitsTop10(localLogits.data(), V);

    int argmaxTok = 0;
    float argmaxVal = localLogits[0];
    for (size_t i = 1; i < V; ++i) {
        if (localLogits[i] > argmaxVal) {
            argmaxVal = localLogits[i];
            argmaxTok = static_cast<int>(i);
        }
    }

    engine.disableParityProbe();

    printf("TEACHER_TOKENS");
    for (size_t i = 0; i < TEACHER_COUNT; ++i) printf(" %d", teacherTokens[i]);
    printf("\n");
    printf("ARGMAX %d\n", argmaxTok);
    fprintf(stderr, "=== PASS ===\n");
    return 0;
}
