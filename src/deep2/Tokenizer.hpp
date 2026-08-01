// ============================================================================
// Tokenizer.hpp - BPE Tokenizer for Deep2
// ============================================================================
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace Deep2 {

struct SpecialTokens {
    int bosId = 1;
    int eosId = 2;
    int unkId = 0;
    int padId = -1;
    int maskId = -1;
};

class ITokenizer {
public:
    virtual ~ITokenizer() = default;
    virtual std::vector<int> Encode(const std::string& text) const = 0;
    virtual std::string Decode(const std::vector<int>& tokens) const = 0;
    virtual std::string Decode(int token) const = 0;
    virtual size_t VocabSize() const = 0;
    virtual bool IsSpecial(int token) const = 0;
    virtual const SpecialTokens& GetSpecialTokens() const = 0;
};

// Simple character-level tokenizer (fallback when no BPE vocab loaded)
class CharTokenizer : public ITokenizer {
public:
    std::vector<int> Encode(const std::string& text) const override {
        std::vector<int> tokens;
        tokens.reserve(text.size());
        for (unsigned char c : text) {
            tokens.push_back((int)c);
        }
        return tokens;
    }

    std::string Decode(const std::vector<int>& tokens) const override {
        std::string result;
        for (int t : tokens) {
            if (t >= 0 && t < 256) result += (char)t;
        }
        return result;
    }

    std::string Decode(int token) const override {
        if (token >= 0 && token < 256) return std::string(1, (char)token);
        return "";
    }

    size_t VocabSize() const override { return 256; }
    bool IsSpecial(int token) const override { return false; }
    const SpecialTokens& GetSpecialTokens() const override { return special_; }

private:
    SpecialTokens special_;
};

// BPE Tokenizer (loads vocab from GGUF)
class BPETokenizer : public ITokenizer {
public:
    bool LoadVocab(const std::vector<std::string>& vocab) {
        vocab_.clear();
        reverseVocab_.clear();
        for (size_t i = 0; i < vocab.size(); ++i) {
            vocab_[vocab[i]] = (int)i;
            reverseVocab_[(int)i] = vocab[i];
        }
        return true;
    }

    std::vector<int> Encode(const std::string& text) const override {
        // Simple: map each character to its token if in vocab
        std::vector<int> tokens;
        for (unsigned char c : text) {
            std::string s(1, (char)c);
            auto it = vocab_.find(s);
            if (it != vocab_.end()) {
                tokens.push_back(it->second);
            } else {
                tokens.push_back(special_.unkId);
            }
        }
        return tokens;
    }

    std::string Decode(const std::vector<int>& tokens) const override {
        std::string result;
        for (int t : tokens) {
            result += Decode(t);
        }
        return result;
    }

    std::string Decode(int token) const override {
        auto it = reverseVocab_.find(token);
        if (it != reverseVocab_.end()) return it->second;
        return "";
    }

    size_t VocabSize() const override { return reverseVocab_.size(); }
    bool IsSpecial(int token) const override {
        return token == special_.bosId || token == special_.eosId ||
               token == special_.unkId || token == special_.padId;
    }
    const SpecialTokens& GetSpecialTokens() const override { return special_; }

private:
    std::unordered_map<std::string, int> vocab_;
    std::unordered_map<int, std::string> reverseVocab_;
    SpecialTokens special_;
};

} // namespace Deep2
