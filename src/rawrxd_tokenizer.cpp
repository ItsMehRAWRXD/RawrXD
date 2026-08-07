#include "rawrxd_tokenizer.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>

bool RawrXDTokenizer::Load(const std::string& vocabPath) {
    // 1. Initialize with bytes (always available as fallback)
    vocab.clear();
    reverse_vocab.clear();
    for (int i = 0; i < 256; i++) {
        std::string s(1, static_cast<char>(i));
        vocab[s] = i + 3; 
        reverse_vocab[i + 3] = s;
    }
    
    // 2. If no vocab file provided, byte-level fallback is sufficient
    if (vocabPath.empty()) {
        return true;
    }
    
    // 3. Attempt to load vocab file
    std::ifstream f(vocabPath, std::ios::binary);
    if (!f.is_open()) {
        // File not found — byte-level fallback is acceptable
        return true;
    }
    
    // Peek at first non-whitespace char to detect JSON
    char first = 0;
    while (f.get(first) && std::isspace(static_cast<unsigned char>(first))) {}
    if (!f) {
        return true; // Empty file
    }
    f.seekg(0, std::ios::beg);
    
    if (first == '{') {
        // tokenizer.json format — parse with nlohmann/json if available
        // For now, we don't have json.hpp included here; fall through to line-by-line
        // TODO: Add JSON parsing when nlohmann/json is available in this TU
    }
    
    // Line-by-line fallback (handles simple vocab files)
    std::string line;
    int idx = 259; // Start after bytes
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        // Strip trailing carriage return (Windows line endings)
        if (!line.empty() && line.back() == '\r') line.pop_back();
        vocab[line] = idx;
        reverse_vocab[idx] = line;
        idx++;
    }
    
    return true;
}

std::vector<uint32_t> RawrXDTokenizer::Encode(const std::string& text) {
    // Greedy Matcher (Longest Prefix) - Simplified BPE
    std::vector<uint32_t> tokens;
    
    // Add BOS
    tokens.push_back(BOS_ID);
    
    size_t pos = 0;
    size_t len = text.length();
    
    // Byte-level tokenization — greedy longest-prefix matching
    while (pos < len) {
        uint8_t c = (uint8_t)text[pos];
        std::string s(1, (char)c);

        if (vocab.count(s)) {
            tokens.push_back(vocab[s]);
        } else {
            tokens.push_back(c + 3);
        }
        pos++;
    }
    
    return tokens;
}

std::string RawrXDTokenizer::Decode(const std::vector<uint32_t>& tokens) {
    std::string res;
    for (uint32_t t : tokens) {
        if (t == BOS_ID || t == EOS_ID) continue;
        if (reverse_vocab.count(t)) {
            res += reverse_vocab[t];
        } else if (t < 256 + 3 && t >= 3) {
            res += (char)(t - 3);
        }
    }
    return res;
}
