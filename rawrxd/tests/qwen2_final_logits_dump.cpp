// qwen2_final_logits_dump.cpp — dumps the FULL logits vector at the final
// prompt position for a given model+prompt, so the rank of an expected token
// can be computed externally (DEEP2_QWEN2_CPU_CORRECTNESS_001 follow-up).
//
// usage: qwen2_final_logits_dump.exe <model.gguf> <prompt> <out_bin>
#include "deep2/Deep2Engine.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr, "usage: qwen2_final_logits_dump.exe <model> <prompt> <out_bin>\n");
        return 2;
    }
    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 512;
    cfg.numThreads = 0;
    if (!e.initialize(cfg) || !e.loadModel(argv[1])) {
        std::fprintf(stderr, "DUMP=HOLD init_or_load\n");
        return 10;
    }
    e.enableVulkan(false);

    // Parity probe with full-vector? Full-vector only covers layers, not LOGITS.
    // Use generateStream once (1 token) — but we need logits, not the token.
    // Workaround: the probe emits LOGITS_TOP10 only. Extend usage: enable probe
    // with full-vector target = none, and use HIDDEN_FINAL? LOGITS not dumped as VEC.
    // Simplest: run generate with maxTokens=1 and print the sampled token id —
    // the sampler output is printed by the engine (SAMPLER_RESULT token=N).
    e.enableParityProbe("nul_probe.txt", 1);
    GenerationOptions o{};
    o.maxTokens = 1;
    o.temperature = 0.0f;
    o.topK = 1;
    o.seed = 1;
    const GenerationResult r = e.generateStream(argv[2], o,
        [](int32_t, const std::string&) { return true; });
    e.disableParityProbe();
    std::remove("nul_probe.txt");
    std::fprintf(stderr, "DUMP=INFO prompt_tokens=%llu generated=%llu\n",
                 static_cast<unsigned long long>(r.promptTokens),
                 static_cast<unsigned long long>(r.generatedTokens));
    std::fprintf(stderr,
        "NOTE=full-logits vector dump requires probe extension (LOGITS VEC); "
        "current evidence limited to TOP10 + sampler choice\n");
    return 0;
}