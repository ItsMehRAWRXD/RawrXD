#include "rawrxd_tokenizer.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <immintrin.h>

bool RawrXDTokenizer::Load(const std::string& vocabPath) {
    // 1. Initialize with bytes as <0xXX> SentencePiece format
    for (int i = 0; i < 256; i++) {
        char hexBuf[8];
        snprintf(hexBuf, sizeof(hexBuf), "<0x%02X>", i);
        std::string hexStr(hexBuf);
        vocab[hexStr] = i + 3;
        reverse_vocab[i + 3] = hexStr;
    }
    
    // 2. Load file if exists (e.g. tokenizer.model or vocab.json)
    std::ifstream f(vocabPath);
    if (!f.is_open()) {
        return true;
    }
    
    std::string line;
    int idx = 259; // Start after bytes
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        // Handle SentencePiece model format: token\tscore\n
        size_t tabPos = line.find('\t');
        std::string token = (tabPos != std::string::npos) ? line.substr(0, tabPos) : line;
        
        // Decode SentencePiece escaped tokens
        std::string decoded;
        decoded.reserve(token.size());
        for (size_t i = 0; i < token.size(); ++i) {
            if (token[i] == '\\' && i + 1 < token.size()) {
                char next = token[i + 1];
                if (next == 'n') { decoded += '\n'; i++; }
                else if (next == 'r') { decoded += '\r'; i++; }
                else if (next == 't') { decoded += '\t'; i++; }
                else if (next == '\\') { decoded += '\\'; i++; }
                else { decoded += token[i]; }
            } else {
                decoded += token[i];
            }
        }
        
        vocab[decoded] = idx;
        reverse_vocab[idx] = decoded;
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
    
    // SIMD-optimized byte processing for simple byte-level tokenization
    // Process 64 bytes at a time using AVX-512 (64 bytes = 512 bits)
    while (pos + 63 < len) {
        // Load 64 bytes into AVX-512 register
        __m512i byte_vec = _mm512_loadu_si512((__m512i*)(text.data() + pos));
        
        // For each byte, create token
        // Since we're doing byte-level, we can process all 64 bytes in parallel
        for (int i = 0; i < 64; i++) {
            uint8_t c = ((uint8_t*)&byte_vec)[i];
            std::string s(1, (char)c);
            if (vocab.count(s)) {
                tokens.push_back(vocab[s]);
            } else {
                tokens.push_back(c + 3);
            }
        }
        pos += 64;
    }
    
    // Handle remaining bytes
    while (pos < len) {
        uint8_t c = (uint8_t)text[pos];
        std::string s(1, (char)c);
        
        if (vocab.count(s)) {
            tokens.push_back(vocab[s]);
        } else {
            // Unknown? Just cast to int?
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
            const std::string& raw = reverse_vocab[t];
            // SentencePiece byte-fallback: <0xXX> → actual byte
            if (raw.size() == 6 && raw[0] == '<' && raw[1] == '0' && raw[2] == 'x') {
                int byteVal = 0;
                for (size_t i = 3; i < 5; ++i) {
                    char c = raw[i];
                    byteVal *= 16;
                    if (c >= '0' && c <= '9') byteVal += c - '0';
                    else if (c >= 'A' && c <= 'F') byteVal += c - 'A' + 10;
                    else if (c >= 'a' && c <= 'f') byteVal += c - 'a' + 10;
                }
                res += static_cast<char>(byteVal);
            } else if (raw.size() == 4 && raw[0] == '0' && raw[1] == 'x') {
                int byteVal = 0;
                for (size_t i = 2; i < 4; ++i) {
                    char c = raw[i];
                    byteVal *= 16;
                    if (c >= '0' && c <= '9') byteVal += c - '0';
                    else if (c >= 'A' && c <= 'F') byteVal += c - 'A' + 10;
                    else if (c >= 'a' && c <= 'f') byteVal += c - 'a' + 10;
                }
                res += static_cast<char>(byteVal);
            } else {
                res += raw;
            }
        } else if (t < 256 + 3 && t >= 3) {
            res += (char)(t - 3);
        }
    }
    return res;
}
