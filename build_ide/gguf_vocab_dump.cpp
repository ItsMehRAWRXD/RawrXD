#include "streaming_gguf_loader.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <map>
#include <algorithm>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: gguf_vocab_dump <model.gguf>\n";
        return 2;
    }
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        std::cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto meta = loader.GetMetadata();
    
    // Write full vocab to file
    std::ofstream out("F:\\rawrxd\\evidence\\qwen3_vocab_full.txt");
    out << "# Qwen3 vocab dump - " << meta.tokens.size() << " tokens\n";
    out << "# BOS=" << meta.kv_pairs["tokenizer.ggml.bos_token_id"] 
        << " EOS=" << meta.kv_pairs["tokenizer.ggml.eos_token_id"]
        << " PAD=" << meta.kv_pairs["tokenizer.ggml.padding_token_id"]
        << " model=" << meta.kv_pairs["tokenizer.ggml.model"]
        << " pre=" << meta.kv_pairs["tokenizer.ggml.pre"] << "\n\n";
    
    for (size_t i = 0; i < meta.tokens.size(); ++i) {
        out << i << "\t" << meta.tokens[i] << "\n";
    }
    out.close();
    
    std::cout << "Wrote " << meta.tokens.size() << " tokens to qwen3_vocab_full.txt\n";
    
    // Analyze patterns
    size_t byteLike = 0;
    size_t special = 0;
    size_t unicode = 0;
    size_t withSpace = 0;
    for (const auto& t : meta.tokens) {
        if (t.find("<") == 0 && t.find(">") == t.size()-1) {
            if (t.find("0x") != std::string::npos) byteLike++;
            else special++;
        }
        if (t.find('\xC4') != std::string::npos || t.find('\xE2') != std::string::npos) unicode++;
        if (t.find(' ') != std::string::npos) withSpace++;
    }
    std::cout << "Byte-like tokens (<0xXX>): " << byteLike << "\n";
    std::cout << "Special tokens (<*>): " << special << "\n";
    std::cout << "Unicode tokens: " << unicode << "\n";
    std::cout << "Tokens with space: " << withSpace << "\n";
    
    // Show tokens around common positions
    std::cout << "\nFirst 50:\n";
    for (size_t i = 0; i < 50 && i < meta.tokens.size(); ++i) {
        std::cout << "  [" << i << "] \"" << meta.tokens[i] << "\"\n";
    }
    
    // Check for byte tokens at different ranges
    std::cout << "\nSearching for byte patterns...\n";
    for (size_t i = 0; i < meta.tokens.size(); ++i) {
        if (meta.tokens[i].size() == 1 && (unsigned char)meta.tokens[i][0] < 32) {
            std::cout << "  Control char at [" << i << "]: 0x" << std::hex << (int)(unsigned char)meta.tokens[i][0] << std::dec << "\n";
        }
    }
    
    return 0;
}
