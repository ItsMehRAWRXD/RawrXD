// tok_probe.cpp — DEEP2_QWEN2_CPU_CORRECTNESS_001 diagnostic:
// prints exactly what BPETokenizer::encode() returns for the oracle prompt.
// Purpose: PROMPT_TOKENS=1 was observed for 'The capital of France is'
// (5 words) — must be ~6 tokens under GPT2BPE. Fail-closed diagnostic.
#include "Tokenizer.hpp"
#include "GGUFLoader.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "usage: tok_probe.exe <model.gguf> <prompt>\n");
        return 2;
    }
    Deep2::GGUFLoader loader;
    if (!loader.load(argv[1])) {
        std::fprintf(stderr, "TOK_PROBE=HOLD stage=gguf_load\n");
        return 1;
    }
    Deep2::BPETokenizer tokenizer;
    if (!tokenizer.loadFromGGUF(loader)) {
        std::fprintf(stderr, "TOK_PROBE=HOLD stage=tokenizer_load\n");
        return 1;
    }
    std::fprintf(stderr, "TOK_KIND=%d\n", static_cast<int>(tokenizer.kind()));
    std::fprintf(stderr, "TOK_MODEL=%s\n", tokenizer.modelName().c_str());
    std::fprintf(stderr, "VOCAB=%zu\n", tokenizer.vocabSize());

    const std::string prompt = argv[2];
    std::vector<int> ids = tokenizer.encode(prompt);
    std::fprintf(stderr, "PROMPT_TOKENS=%zu\n", ids.size());
    for (int id : ids) {
        std::string piece = tokenizer.decode(id);
        std::fprintf(stderr, "ID=%d PIECE=%s\n", id, piece.c_str());
    }
    std::fprintf(stderr, "TOK_PROBE=%s\n", ids.size() >= 2 ? "PASS" : "FAIL");
    return ids.size() >= 2 ? 0 : 1;
}