#include "streaming_gguf_loader.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: gguf_token_scan <model.gguf>\n";
        return 2;
    }
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        std::cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto meta = loader.GetMetadata();
    
    // Scan for byte tokens (<0xNN>)
    size_t byteTokens = 0;
    size_t firstByteToken = SIZE_MAX;
    size_t lastByteToken = SIZE_MAX;
    for (size_t i = 0; i < meta.tokens.size(); ++i) {
        const auto& t = meta.tokens[i];
        if (t.size() == 6 && t[0] == '<' && t[1] == '0' && t[2] == 'x' && t[5] == '>') {
            byteTokens++;
            if (firstByteToken == SIZE_MAX) firstByteToken = i;
            lastByteToken = i;
        }
    }
    std::cout << "Byte tokens: " << byteTokens << "\n";
    if (byteTokens > 0) {
        std::cout << "First byte token at index: " << firstByteToken << " = \"" << meta.tokens[firstByteToken] << "\"\n";
        std::cout << "Last byte token at index: " << lastByteToken << " = \"" << meta.tokens[lastByteToken] << "\"\n";
    }
    
    // Check for special tokens
    std::cout << "\nSpecial token IDs from metadata:\n";
    std::cout << "  BOS: " << meta.kv_pairs["tokenizer.ggml.bos_token_id"] << "\n";
    std::cout << "  EOS: " << meta.kv_pairs["tokenizer.ggml.eos_token_id"] << "\n";
    std::cout << "  PAD: " << meta.kv_pairs["tokenizer.ggml.padding_token_id"] << "\n";
    
    // Check merges key
    auto mergesIt = meta.kv_pairs.find("tokenizer.ggml.merges");
    std::cout << "\ntokenizer.ggml.merges present: " << (mergesIt != meta.kv_pairs.end() ? "YES" : "NO") << "\n";
    
    // Show some tokens around byte token area
    if (firstByteToken != SIZE_MAX) {
        std::cout << "\nTokens around first byte token:\n";
        size_t start = (firstByteToken > 5) ? firstByteToken - 5 : 0;
        for (size_t i = start; i <= firstByteToken + 5 && i < meta.tokens.size(); ++i) {
            std::cout << "  [" << i << "] \"" << meta.tokens[i] << "\"\n";
        }
    }
    
    // Check if merges are stored as array
    std::cout << "\nAll metadata keys containing 'merge':\n";
    for (const auto& [k, v] : meta.kv_pairs) {
        if (k.find("merge") != std::string::npos) {
            std::cout << "  " << k << " = " << v.substr(0, 80) << "\n";
        }
    }
    
    return 0;
}
