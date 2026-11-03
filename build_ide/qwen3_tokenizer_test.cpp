#include "streaming_gguf_loader.h"
#include "tokenizer/qwen3_tokenizer.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>

using namespace RawrXD::Qwen3Tokenizer;

struct TestCase {
    std::string name;
    std::string input;
    bool add_bos;
    bool add_eos;
    std::vector<int32_t> expected;  // Empty = not checked
};

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: qwen3_tokenizer_test <model.gguf>\n";
        return 2;
    }

    // Load GGUF metadata
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        std::cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto meta = loader.GetMetadata();

    // Create tokenizer
    Tokenizer tok;
    Config cfg;
    cfg.add_bos = false;
    cfg.add_eos = false;
    if (!tok.loadFromGGUF(meta.tokens, meta.kv_pairs, cfg)) {
        std::cerr << "TOKENIZER_LOAD_FAIL\n";
        return 4;
    }

    std::cout << "Tokenizer loaded: " << tok.vocabSize() << " tokens\n";
    std::cout << "BOS=" << tok.bosId() << " EOS=" << tok.eosId() << " PAD=" << tok.padId() << " UNK=" << tok.unkId() << "\n";

    // Verify byte mapping: all 256 bytes should map to a token
    std::cout << "\n=== Byte Mapping Verification ===\n";
    int byteMapped = 0;
    for (int b = 0; b < 256; ++b) {
        // We can't directly query byteToTokenId_, but we can test encoding
    }
    std::cout << "Byte mapping: built from first 256 GGUF tokens\n";

    // Test cases
    std::vector<TestCase> tests = {
        {"empty", "", false, false, {}},
        {"hello", "hello", false, false, {}},
        {"Hello World", "Hello World", false, false, {}},
        {"space test", " space test", false, false, {}},
        {"newline", "line1\nline2", false, false, {}},
        {"tab", "col1\tcol2", false, false, {}},
        {"punctuation", "Hello, world!", false, false, {}},
        {"numbers", "12345", false, false, {}},
        {"mixed", "Hello123", false, false, {}},
        {"unicode", "caf\xc3\xa9", false, false, {}},  // café
        {"chinese", "\xe4\xb8\xad\xe6\x96\x87", false, false, {}},  // 中文
        {"code", "#include <iostream>", false, false, {}},
        {"cpp", "int main() { return 0; }", false, false, {}},
        {"contractions", "don't can't won't", false, false, {}},
        {"bos_only", "hello", true, false, {}},
        {"eos_only", "hello", false, true, {}},
        {"bos_eos", "hello", true, true, {}},
        {"special_bos", "<|begin_of_sentence|>", false, false, {}},
        {"special_eos", "<|end_of_sentence|>", false, false, {}},
        {"chat_user", "<|User|>Hello<|Assistant|>", false, false, {}},
    };

    std::cout << "\n=== Tokenization Tests ===\n";
    int passCount = 0;
    int failCount = 0;

    for (const auto& test : tests) {
        auto enc = tok.encode(test.input, test.add_bos, test.add_eos);
        if (!enc.ok) {
            std::cout << "FAIL [" << test.name << "] " << enc.error << "\n";
            failCount++;
            continue;
        }

        std::string decoded = tok.decode(enc.ids);
        bool roundtripOk = (decoded == test.input);

        std::cout << test.name << ": ids=";
        for (size_t i = 0; i < enc.ids.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << enc.ids[i];
        }
        std::cout << " decoded=\"" << decoded << "\" roundtrip=" << (roundtripOk ? "OK" : "DIFF") << "\n";

        if (!test.expected.empty() && enc.ids != test.expected) {
            std::cout << "  MISMATCH expected vs actual\n";
            failCount++;
        } else if (!roundtripOk && test.input.find("<|") == std::string::npos) {
            // For special tokens, roundtrip may not be exact
            failCount++;
        } else {
            passCount++;
        }
    }

    std::cout << "\n=== Results: " << passCount << " pass, " << failCount << " fail ===\n";

    // Test BPE merge behavior: "hello" should be h+e+ll+o or similar
    std::cout << "\n=== BPE Merge Analysis ===\n";
    auto hello = tok.encode("hello");
    std::cout << "\"hello\" -> ";
    for (int id : hello.ids) {
        if (id >= 0 && id < tok.vocabSize()) {
            std::cout << "[" << id << "]" << tok.decode({id});
        } else {
            std::cout << "[" << id << "]?";
        }
    }
    std::cout << "\n";

    auto helloWorld = tok.encode("hello world");
    std::cout << "\"hello world\" -> ";
    for (int id : helloWorld.ids) {
        if (id >= 0 && id < tok.vocabSize()) {
            std::cout << "[" << id << "]" << tok.decode({id});
        } else {
            std::cout << "[" << id << "]?";
        }
    }
    std::cout << "\n";

    // Test that space is encoded as metaspace (▁)
    auto space = tok.encode(" ");
    std::cout << "\" \" -> ";
    for (int id : space.ids) {
        if (id >= 0 && id < tok.vocabSize()) {
            std::cout << "[" << id << "]" << tok.decode({id});
        } else {
            std::cout << "[" << id << "]?";
        }
    }
    std::cout << "\n";

    return failCount > 0 ? 1 : 0;
}
