#include "../src/GgufParityTokenizer.hpp"
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static bool loadIds(const std::string& path, std::vector<int32_t>& out) {
    std::ifstream f(path);
    if (!f) return false;
    long long x = 0;
    while (f >> x) out.push_back(static_cast<int32_t>(x));
    return !out.empty();
}

static std::string loadText(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(f), {});
}

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: tokenizer_parity_cert MODEL.gguf prompt.txt reference_ids.txt\n";
        return 64;
    }

    rawrxd::parity::GgufParityTokenizer tok;
    std::string err;
    if (!tok.load(argv[1], &err)) {
        std::cerr << "TOKENIZER_LOAD=FAIL reason=" << err << "\n";
        return 65;
    }

    const std::string prompt = loadText(argv[2]);
    std::vector<int32_t> ref;
    if (!loadIds(argv[3], ref)) {
        std::cerr << "REFERENCE_IDS=FAIL\n";
        return 66;
    }

    const auto got = tok.encode(prompt, true);
    std::cout << "TOKENIZER_VOCAB=" << tok.vocabSize() << "\n";
    std::cout << "GOT_COUNT=" << got.size() << "\n";
    std::cout << "REF_COUNT=" << ref.size() << "\n";

    const size_t n = got.size() < ref.size() ? got.size() : ref.size();
    for (size_t i = 0; i < n; ++i) {
        if (got[i] != ref[i]) {
            std::cout << "FIRST_DIFF=" << i
                      << " got=" << got[i]
                      << " ref=" << ref[i] << "\n";
            std::cout << "TOKENIZER_PARITY=FAIL\n";
            return 1;
        }
    }
    if (got.size() != ref.size()) {
        std::cout << "FIRST_DIFF=" << n << " length_mismatch=1\n";
        std::cout << "TOKENIZER_PARITY=FAIL\n";
        return 1;
    }

    std::cout << "TOKENIZER_PARITY=PASS\n";
    return 0;
}
