// test_tokenizer.cpp — Tokenizer encode/decode verification for Qwen2
// Build: cmake --build . --config Release --target test_tokenizer
// Run: test_tokenizer.exe --model F:\~dev\qwen2.5-coder-1.5b-base.gguf

#include "Tokenizer.hpp"
#include "GGUFLoader.hpp"
#include <cstdio>
#include <string>
#include <vector>

static void printUsage(const char* prog) {
    std::fprintf(stderr,
        "Tokenizer Test\n"
        "Usage: %s --model <path>\n", prog);
}

int main(int argc, char** argv) {
    const char* prog = (argc > 0) ? argv[0] : "test_tokenizer";
    std::string modelPath;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            modelPath = argv[++i];
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            printUsage(prog);
            return 0;
        }
    }

    if (modelPath.empty()) {
        std::fprintf(stderr, "ERROR: --model is required\n");
        printUsage(prog);
        return 1;
    }

    Deep2::GGUFLoader loader;
    if (!loader.load(modelPath)) {
        std::fprintf(stderr, "Failed to load GGUF: %s\n", modelPath.c_str());
        return 1;
    }

    Deep2::BPETokenizer tokenizer;
    if (!tokenizer.loadFromGGUF(loader)) {
        std::fprintf(stderr, "Failed to load tokenizer from GGUF\n");
        return 1;
    }

    std::fprintf(stderr, "Tokenizer kind: %d (GPT2BPE=%d)\n", static_cast<int>(tokenizer.kind()), static_cast<int>(Deep2::BPETokenizer::Kind::GPT2BPE));
    std::fprintf(stderr, "Tokenizer model: %s\n", tokenizer.modelName().c_str());
    std::fprintf(stderr, "Vocab size: %zu\n", tokenizer.vocabSize());
    std::fprintf(stderr, "BOS: %d, EOS: %d, UNK: %d\n", tokenizer.bosTokenId(), tokenizer.eosTokenId(), tokenizer.unknownTokenId());
    std::fprintf(stderr, "Merge count: %zu\n", tokenizer.vocabSize()); // placeholder

    // Test encode/decode
    std::vector<std::string> tests = {"hi", "hello", " hello", "hello world", "12345", "\n", "hi there"};
    
    bool allPass = true;
    for (const auto& test : tests) {
        std::vector<int> encoded = tokenizer.encode(test);
        std::string decoded = tokenizer.decode(encoded);
        
        bool roundtrip = (decoded == test);
        allPass = allPass && roundtrip;
        
        std::fprintf(stderr, "\nInput: \"%s\"\n", test.c_str());
        std::fprintf(stderr, "Encoded (%zu tokens): ", encoded.size());
        for (int id : encoded) {
            std::fprintf(stderr, "%d ", id);
        }
        std::fprintf(stderr, "\nDecoded: \"%s\"\n", decoded.c_str());
        std::fprintf(stderr, "Roundtrip: %s\n", roundtrip ? "PASS" : "FAIL");
        
        // Check each token ID
        for (int id : encoded) {
            if (id >= 0 && static_cast<size_t>(id) < tokenizer.vocabSize()) {
                std::string piece = tokenizer.decode(id);
                std::fprintf(stderr, "  Token %d -> \"%s\"\n", id, piece.c_str());
            }
        }
    }

    // Special test: vocabulary lookup for token 6023
    if (6023 >= 0 && 6023 < static_cast<int>(tokenizer.vocabSize())) {
        std::string piece = tokenizer.decode(6023);
        std::fprintf(stderr, "\nVocab[6023] = \"%s\"\n", piece.c_str());
    }

    std::fprintf(stderr, "\n=== OVERALL: %s ===\n", allPass ? "PASS" : "FAIL");
    return allPass ? 0 : 1;
}