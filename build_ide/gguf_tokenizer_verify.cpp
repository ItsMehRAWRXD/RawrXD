#include "streaming_gguf_loader.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <map>
#include <algorithm>
#include <unordered_map>
#include <set>

using namespace std;

// GPT-2 byte-to-Unicode mapping (same as sentencepiece_encode.hpp::normalizeGpt2)
static const array<uint32_t, 256> buildByteToCpt() {
    array<uint32_t, 256> m{};
    array<bool, 256> identity{};
    for (int ch = 0x21; ch <= 0x7E; ++ch) identity[ch] = true;
    for (int ch = 0xA1; ch <= 0xAC; ++ch) identity[ch] = true;
    for (int ch = 0xAE; ch <= 0xFF; ++ch) identity[ch] = true;
    uint32_t n = 0;
    for (int b = 0; b < 256; ++b)
        m[b] = identity[b] ? static_cast<uint32_t>(b) : (256u + n++);
    return m;
}

static string gpt2ByteEncode(unsigned char b) {
    static const auto kByteToCpt = buildByteToCpt();
    const uint32_t cp = kByteToCpt[b];
    string out;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        cerr << "usage: gguf_tokenizer_verify <model.gguf>\n";
        return 2;
    }
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto meta = loader.GetMetadata();
    const auto& tokens = meta.tokens;
    
    ofstream out("F:\\rawrxd\\evidence\\qwen3_tokenizer_analysis.txt");
    
    // Step 1: Verify GPT-2 byte mapping for all 256 bytes
    out << "=== STEP 1: GPT-2 Byte Mapping Verification ===\n";
    bool byteMappingOk = true;
    for (int b = 0; b < 256; ++b) {
        string expected = gpt2ByteEncode(static_cast<unsigned char>(b));
        if (b >= (int)tokens.size() || tokens[b] != expected) {
            out << "MISMATCH at byte " << b << ": expected=\"" << expected 
                << "\" actual=\"" << (b < (int)tokens.size() ? tokens[b] : "N/A") << "\"\n";
            byteMappingOk = false;
        }
    }
    out << "Byte mapping verified: " << (byteMappingOk ? "PASS" : "FAIL") << "\n\n";
    
    // Step 2: Identify all special tokens
    out << "=== STEP 2: Special Token Identification ===\n";
    vector<pair<int, string>> specialTokens;
    for (size_t i = 0; i < tokens.size(); ++i) {
        const auto& t = tokens[i];
        if (t.size() >= 2 && t[0] == '<' && (t[1] == '|' || t[1] == '\xEF')) {
            // Qwen special tokens: <|...|> or <｜...｜>
            specialTokens.push_back({(int)i, t});
        }
    }
    out << "Special tokens found: " << specialTokens.size() << "\n";
    for (const auto& [id, tok] : specialTokens) {
        out << "  [" << id << "] \"" << tok << "\"\n";
    }
    out << "\n";
    
    // Step 3: Analyze token ordering - find merge boundary
    out << "=== STEP 3: Token Ordering Analysis ===\n";
    int firstMultiChar = -1;
    for (int i = 0; i < (int)tokens.size(); ++i) {
        if (tokens[i].size() > 1) {
            firstMultiChar = i;
            break;
        }
    }
    out << "First multi-char token at index: " << firstMultiChar << "\n";
    
    // Check if tokens 0-255 are all single GPT-2 byte encodings
    bool allSingleBytes = true;
    for (int i = 0; i < 256 && i < (int)tokens.size(); ++i) {
        if (tokens[i].size() != 1 && tokens[i].size() != 2 && tokens[i].size() != 3) {
            // Could be 2 or 3 byte UTF-8 for non-ASCII bytes
            allSingleBytes = false;
            break;
        }
    }
    out << "Tokens 0-255 all byte-encoded: " << (allSingleBytes ? "YES" : "NO") << "\n";
    
    // Step 4: Test rank-derived merge decomposition
    out << "\n=== STEP 4: Merge Decomposition Test ===\n";
    // Build token->id map
    unordered_map<string, int> tokenToId;
    for (size_t i = 0; i < tokens.size(); ++i)
        tokenToId[tokens[i]] = (int)i;
    
    // Test decomposition of first 20 merge tokens (indices 256-275)
    out << "Testing merge decomposition for indices 256-280:\n";
    for (int i = 256; i <= 280 && i < (int)tokens.size(); ++i) {
        const auto& tok = tokens[i];
        bool decomposed = false;
        int bestLeft = -1, bestRight = -1;
        int bestScore = INT_MAX;
        
        // Try all possible splits
        for (size_t split = 1; split < tok.size(); ++split) {
            string left = tok.substr(0, split);
            string right = tok.substr(split);
            auto lit = tokenToId.find(left);
            auto rit = tokenToId.find(right);
            if (lit != tokenToId.end() && rit != tokenToId.end()) {
                int score = max(lit->second, rit->second);
                if (score < bestScore) {
                    bestScore = score;
                    bestLeft = lit->second;
                    bestRight = rit->second;
                    decomposed = true;
                }
            }
        }
        
        if (decomposed) {
            out << "  [" << i << "] \"" << tok << "\" = [" << bestLeft << "]\"" 
                << tokens[bestLeft] << "\" + [" << bestRight << "]\"" 
                << tokens[bestRight] << "\" (max_rank=" << bestScore << ")\n";
        } else {
            out << "  [" << i << "] \"" << tok << "\" = NO DECOMPOSITION FOUND\n";
        }
    }
    
    out.close();
    cout << "Analysis written to qwen3_tokenizer_analysis.txt\n";
    return 0;
}
