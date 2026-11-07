#include "streaming_gguf_loader.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: gguf_meta_dump <model.gguf>\n";
        return 2;
    }
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        std::cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto meta = loader.GetMetadata();
    std::cout << "=== METADATA KV PAIRS ===\n";
    for (const auto& [k, v] : meta.kv_pairs) {
        std::cout << std::left << std::setw(55) << k << " = " << v << "\n";
    }
    std::cout << "\n=== TOKENS ===\n";
    std::cout << "token count: " << meta.tokens.size() << "\n";
    for (size_t i = 0; i < std::min<size_t>(20, meta.tokens.size()); ++i) {
        std::cout << "  [" << i << "] \"" << meta.tokens[i] << "\"\n";
    }
    if (meta.tokens.size() > 20) {
        std::cout << "  ... (" << (meta.tokens.size() - 20) << " more)\n";
    }
    std::cout << "\n=== TOKEN SCORES ===\n";
    std::cout << "score count: " << meta.token_scores.size() << "\n";
    for (size_t i = 0; i < std::min<size_t>(10, meta.token_scores.size()); ++i) {
        std::cout << "  [" << i << "] " << meta.token_scores[i] << "\n";
    }
    std::cout << "\n=== TENSOR INDEX (first 20) ===\n";
    auto idx = loader.GetTensorIndex();
    size_t n = 0;
    for (const auto& ref : idx) {
        std::cout << "  " << ref.name << " type=" << static_cast<uint32_t>(ref.type)
                  << " offset=" << ref.offset << " size=" << ref.size
                  << " shape=[";
        for (size_t d = 0; d < ref.shape.size(); ++d) {
            if (d) std::cout << ",";
            std::cout << ref.shape[d];
        }
        std::cout << "]\n";
        if (++n >= 20) break;
    }
    std::cout << "total tensors: " << idx.size() << "\n";
    return 0;
}
