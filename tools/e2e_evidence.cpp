// RAW-XD autoregressive E2E evidence capture (RAWRXD_CORE_DLL_NATIVE_E2E_001).
//
// Runs the certified IR executor over a prompt with per-step evidence:
//   PROMPT_TOKEN_IDS, PREFILL_LAST_POSITION, GENERATION_STEP,
//   EXECUTED_POSITION, LOGITS_GENERATION_ID, LOGITS_FINITE, SAMPLED_TOKEN,
//   KV_CACHE_LENGTH
// and writes the per-position native logits snapshots for offline
// reference-differential comparison against llama.cpp.
//
// usage: e2e_evidence <model.gguf> <evidence_dir> --tokens t0 t1 ...
#include "ModelGenieExecutor.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

static uint64_t fnv1a(const float* p, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) {
        uint32_t b;
        std::memcpy(&b, p + i, 4);
        for (int k = 0; k < 4; ++k) {
            h ^= (b >> (8 * k)) & 0xFF;
            h *= 1099511628211ull;
        }
    }
    return h;
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: %s <model.gguf> <evidence_dir> --tokens t0 t1 ...\n",
            argv[0]);
        return 2;
    }
    const std::string model = argv[1];
    const std::string evdir = argv[2];
    std::vector<uint32_t> prompt;
    for (int i = 3; i < argc; ++i) {
        if (std::strcmp(argv[i], "--tokens") == 0) {
            for (int j = i + 1; j < argc; ++j) prompt.push_back(
                static_cast<uint32_t>(std::atoi(argv[j])));
            break;
        }
    }
    if (prompt.empty()) { prompt = {1u, 185u, 16u}; }

    const uint32_t max_tokens = 16;
    std::filesystem::create_directories(evdir);

    IRExecutor exec(model, prompt[0]);
    uint64_t logitsGenId = 0;
    std::vector<uint32_t> sequence;
    std::vector<uint32_t> generated;

    auto capture = [&](const char* tag) {
        const std::vector<float>* logits = exec.GetLogits();
        const size_t pos = exec.Position();
        ++logitsGenId;
        bool finite = logits && !logits->empty();
        uint32_t argmax = 0;
        float argmaxVal = 0.0f;
        uint64_t hash = 0;
        if (logits) {
            argmaxVal = (*logits)[0];
            for (size_t i = 0; i < logits->size(); ++i) {
                const float v = (*logits)[i];
                if (!std::isfinite(v)) finite = false;
                if (v > argmaxVal) { argmaxVal = v; argmax = (uint32_t) i; }
            }
            hash = fnv1a(logits->data(), logits->size());
            char path[1024];
            std::snprintf(path, sizeof(path),
                          "%s/native_tf_logits_pos%zu.bin", evdir.c_str(), pos);
            FILE* f = std::fopen(path, "wb");
            if (f) {
                std::fwrite(logits->data(), sizeof(float), logits->size(), f);
                std::fclose(f);
            }
        }
        std::printf("%s GENERATION_STEP=%zu EXECUTED_POSITION=%zu "
                    "LOGITS_GENERATION_ID=%llu LOGITS_FINITE=%s "
                    "NATIVE_ARGMAX=%u LOGITS_HASH=%016llx KV_CACHE_LENGTH=%zu\n",
                    tag, generated.size(), pos,
                    (unsigned long long) logitsGenId,
                    finite ? "true" : "false", argmax,
                    (unsigned long long) hash,
                    exec.GetKVCache() && exec.GetKVCache()->layers.size() ? exec.GetKVCache()->layers[0].Size() : 0);
        std::fflush(stdout);
    };

    std::printf("PROMPT_TOKEN_IDS");
    for (uint32_t t : prompt) std::printf(" %u", t);
    std::printf("\n");
    std::fflush(stdout);

    // ---- prefill ---------------------------------------------------------
    for (size_t i = 0; i < prompt.size(); ++i) {
        if (i > 0) { exec.SetTokenId(prompt[i]); exec.AdvancePosition(); }
        exec.ClearArena();
        if (!exec.Execute()) { std::fprintf(stderr, "prefill failed at %zu\n", i); return 5; }
        sequence.push_back(prompt[i]);
        capture("PREFILL");
    }
    std::printf("PREFILL_LAST_POSITION=%zu\n", exec.Position());
    std::fflush(stdout);

    // ---- autoregressive generation ---------------------------------------
    uint32_t next = exec.SampleToken();
    for (uint32_t step = 0; step < max_tokens; ++step) {
        generated.push_back(next);
        sequence.push_back(next);
        std::printf("GENERATION_STEP=%u SAMPLED_TOKEN=%u EXECUTED_POSITION=%zu\n",
                    step, next, exec.Position());
        if (step + 1 >= max_tokens) break;
        exec.SetTokenId(next);
        exec.AdvancePosition();
        exec.ClearArena();
        if (!exec.Execute()) { std::fprintf(stderr, "decode failed at step %u\n", step); return 6; }
        capture("GENERATE");
        next = exec.SampleToken();
    }

    std::printf("SEQUENCE_TOKEN_IDS");
    for (uint32_t t : sequence) std::printf(" %u", t);
    std::printf("\nGENERATED_COUNT=%zu\n", generated.size());
    std::printf("KV_CACHE_FINAL_LENGTH=%zu\n",
                exec.GetKVCache() && exec.GetKVCache()->layers.size() ? exec.GetKVCache()->layers[0].Size() : 0);
    std::fflush(stdout);
    return 0;
}
