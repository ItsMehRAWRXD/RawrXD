#include "streaming_gguf_loader.h"
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <fstream>
#include <unordered_map>
#include <array>

using namespace std;

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
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        cerr << "usage: gguf_byte_check <model.gguf>\n";
        return 2;
    }
    StreamingGGUFLoader loader;
    if (!loader.Open(argv[1])) {
        cerr << "LOAD_FAIL\n";
        return 3;
    }
    auto meta = loader.GetMetadata();
    const auto& tokens = meta.tokens;
    
    cout << "=== GPT-2 Byte Mapping Check ===\n";
    cout << "Byte\tGPT-2 Enc\tGGUF Token\tMatch?\n";
    cout << "----\t---------\t----------\t------\n";
    
    int matches = 0;
    int mismatches = 0;
    for (int b = 0; b < 256; ++b) {
        string expected = gpt2ByteEncode(static_cast<unsigned char>(b));
        string actual = (b < (int)tokens.size()) ? tokens[b] : "N/A";
        bool match = (actual == expected);
        if (match) matches++; else mismatches++;
        
        cout << hex << setw(2) << setfill('0') << b << dec 
             << "\t\"" << expected << "\" (" << expected.size() << " bytes)"
             << "\t\"" << actual << "\" (" << actual.size() << " bytes)"
             << "\t" << (match ? "YES" : "NO") << "\n";
    }
    
    cout << "\n=== Summary ===\n";
    cout << "Matches: " << matches << "/256\n";
    cout << "Mismatches: " << mismatches << "/256\n";
    
    // Also check: are tokens 0-255 all unique?
    cout << "\n=== Token Uniqueness Check (0-255) ===\n";
    unordered_map<string, int> seen;
    int dups = 0;
    for (int i = 0; i < 256 && i < (int)tokens.size(); ++i) {
        if (seen.count(tokens[i])) dups++;
        seen[tokens[i]] = i;
    }
    cout << "Duplicates in tokens 0-255: " << dups << "\n";
    
    // Check token sizes for 0-255
    cout << "\n=== Token Size Distribution (0-255) ===\n";
    map<int, int> sizeDist;
    for (int i = 0; i < 256 && i < (int)tokens.size(); ++i)
        sizeDist[tokens[i].size()]++;
    for (const auto& [sz, cnt] : sizeDist)
        cout << "  Size " << sz << ": " << cnt << " tokens\n";
    
    return 0;
}
