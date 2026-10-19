// Standalone tokenizer check.
//
//   tokenizer_test <model.gguf> [--dump <text> | --dump-file <path>]
//
// Verifies that GgufTokenizer produces the same token ids as the reference
// HuggingFace tokenizer for the same GGUF, and that decode(encode(text))
// round-trips back to the original text.
//
// Token ids are written to stdout as "id piece" pairs so they can be diffed
// against a reference run:
//
//   tokenizer_test model.gguf --dump-file prompt.txt > ids.txt
//
// The --dump-file form reads UTF-8 from disk. Command-line arguments are
// decoded using the active code page on Windows, so non-ASCII prompts must be
// passed through a file to compare against a UTF-8 reference.
//
// Exit codes: 0 = pass, 1 = fail, 2 = usage error.

#include "core/GgufTokenizer.hpp"

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace Deep2Rom::Inference;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::cerr << "[PASS] " << what << "\n";
    } else {
        std::cerr << "[FAIL] " << what << "\n";
        ++g_failures;
    }
}

std::string escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\n') { out += "\\n"; }
        else if (c == '\r') { out += "\\r"; }
        else if (c == '\t') { out += "\\t"; }
        else if (static_cast<unsigned char>(c) < 0x20) { out += "?"; }
        else { out += c; }
    }
    return out;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: tokenizer_test <model.gguf> [--dump <text>]\n";
        return 2;
    }

    const std::string modelPath = argv[1];
    std::string dumpText;
    bool dump = false;
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--dump") == 0 && i + 1 < argc) {
            dump = true;
            dumpText = argv[i + 1];
            break;
        }
        if (std::strcmp(argv[i], "--dump-file") == 0 && i + 1 < argc) {
            dump = true;
            std::ifstream in(argv[i + 1], std::ios::binary);
            if (!in) {
                std::cerr << "[FAIL] cannot open " << argv[i + 1] << "\n";
                return 1;
            }
            std::ostringstream ss;
            ss << in.rdbuf();
            dumpText = ss.str();
            break;
        }
    }

    GgufTokenizer tok;
    if (!tok.loadFromGGUF(modelPath)) {
        std::cerr << "[FAIL] could not load tokenizer from " << modelPath << "\n";
        return 1;
    }
    check(tok.isReady(), "tokenizer loaded");

    const char* family = tok.type() == GgufTokenizerType::Spm ? "spm" : "bpe";
    std::cerr << "[INFO] family=" << family << " vocab=" << tok.vocabSize()
              << " bos=" << tok.bosTokenId() << " eos=" << tok.eosTokenId()
              << " unk=" << (tok.hasUnknownToken()
                                 ? std::to_string(tok.unkTokenId())
                                 : std::string("none"))
              << "\n";

    // Round-trip: encoding then decoding must reproduce the input. The SPM
    // path prepends a space, so a leading space in the decoded output is
    // expected and trimmed before comparison.
    const std::vector<std::string> roundTrips = {
        "Hello world",
        "The quick brown fox jumps over the lazy dog.",
        "int main() { return 0; }",
        "1 + 1 = 2",
        "Line one\nLine two\n",
        "Trailing space ",
        "  leading spaces",
        "punctuation!?,.;:()[]{}",
        "tabs\tand\treturns\r\n",
    };

    for (const std::string& text : roundTrips) {
        std::vector<uint32_t> ids = tok.encode(text);
        check(!ids.empty() || text.empty(), "encode produced tokens for \"" + escape(text) + "\"");

        std::string decoded = tok.decode(ids);
        if (tok.type() == GgufTokenizerType::Spm && !decoded.empty() && decoded[0] == ' ') {
            decoded = decoded.substr(1);  // the SPM space prefix
        }
        check(decoded == text,
              "round-trip \"" + escape(text) + "\" -> \"" + escape(decoded) + "\"");
    }

    // No token may be the unknown token: a working tokenizer resolves every
    // character of these prompts to a real vocabulary entry.
    for (const std::string& text : roundTrips) {
        std::vector<uint32_t> ids = tok.encode(text);
        size_t unk = 0;
        for (uint32_t id : ids) {
            if (id == tok.unkTokenId()) ++unk;
        }
        check(unk == 0, "no unknown tokens for \"" + escape(text) + "\" (" +
                           std::to_string(unk) + " unknown)");
    }

    if (dump) {
        std::vector<uint32_t> ids = tok.encode(dumpText);
        for (uint32_t id : ids) {
            std::cout << id << "\t" << escape(tok.piece(id)) << "\n";
        }
    }

    if (g_failures) {
        std::cerr << "[RESULT] " << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cerr << "[RESULT] all checks passed\n";
    return 0;
}
