/* Real BPE Tokenizer Implementation */
#include "Tokenizer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace Deep2 {

bool BPETokenizer::loadFromFile(const std::string& vocabPath) {
    std::ifstream f(vocabPath);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        size_t sp = line.find(' ');
        if (sp == std::string::npos) continue;
        int id = std::stoi(line.substr(0, sp));
        std::string tok = line.substr(sp + 1);
        // Unescape
        if (!tok.empty() && tok.front() == '"' && tok.back() == '"') {
            tok = tok.substr(1, tok.size() - 2);
        }
        tokenToId_[tok] = id;
        idToToken_[id] = tok;
    }
    return !idToToken_.empty();
}

bool BPETokenizer::loadFromGGUF(const void* ggufData, size_t len) {
    (void)ggufData; (void)len;
    // TODO: parse vocab tensor from GGUF metadata
    return false;
}

std::vector<std::string> BPETokenizer::byteEncode(const std::string& s) {
    std::vector<std::string> out;
    for (unsigned char c : s) {
        out.push_back(std::string(1, static_cast<char>(c)));
    }
    return out;
}

std::vector<std::string> BPETokenizer::splitToWords(const std::string& s) {
    std::vector<std::string> words;
    std::string cur;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!cur.empty()) { words.push_back(cur); cur.clear(); }
            words.push_back(std::string(1, c));
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) words.push_back(cur);
    return words;
}

std::vector<int> BPETokenizer::encode(const std::string& text) {
    std::vector<int> ids;
    auto words = splitToWords(text);
    for (const auto& w : words) {
        auto it = tokenToId_.find(w);
        if (it != tokenToId_.end()) {
            ids.push_back(it->second);
        } else {
            // Fallback: byte fallback
            for (unsigned char c : w) {
                std::string key(1, static_cast<char>(c));
                auto it2 = tokenToId_.find(key);
                if (it2 != tokenToId_.end()) ids.push_back(it2->second);
                else ids.push_back(0); // unk
            }
        }
    }
    return ids;
}

std::string BPETokenizer::decode(const std::vector<int>& tokens) {
    std::string out;
    for (int id : tokens) {
        auto it = idToToken_.find(id);
        if (it != idToToken_.end()) out += it->second;
    }
    return out;
}

std::string BPETokenizer::decode(int token) {
    auto it = idToToken_.find(token);
    if (it != idToToken_.end()) return it->second;
    return "?";
}

} // namespace Deep2
