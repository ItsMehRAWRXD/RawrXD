#include "deep2/Deep2Engine.h"
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s <model.gguf>\n", argv[0]); return 2; }
    Deep2::Deep2Engine e;
    Deep2::EngineConfig cfg{};
    cfg.maxSeqLen = 4096;
    if (!e.initialize(cfg)) return 10;
    if (!e.loadModel(argv[1])) return 11;
    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    if (!e.isVulkanInitialized()) return 12;

    Deep2::GenerationOptions o{};
    o.maxTokens = 8;
    o.temperature = 0.8f;
    o.topK = 40;
    o.seed = 0; // auto

    std::string tokens;
    auto r = e.generateStream("Hello world", o,
        [&](int32_t tok, const std::string& piece) {
            tokens += piece;
            std::fprintf(stderr, "TOK[%d]\n", tok);
            return true;
        });
    std::fprintf(stderr, "SEED_AUTO TOKENS=%s\n", tokens.c_str());
    return 0;
}
