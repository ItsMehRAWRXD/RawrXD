// ============================================================================
// Tokenizer.hpp - BPE Tokenizer for Deep2
// Canonical SentencePiece encode via RawrXD::Spm (TOKENIZER-PARITY-002c)
// ============================================================================
#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <algorithm>
#include <array>

#include "../tokenizer/sentencepiece_encode.hpp"

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

// BPE/SPM Tokenizer — agentic encode authority (same Spm::encode as parity API)
class BPETokenizer : public ITokenizer {
public:
    bool LoadVocab(const std::vector<std::string>& vocab) {
        vocab_.clear();
        reverseVocab_.clear();
        byteFallback_.fill(-1);
        scores_.assign(vocab.size(), 0.0f);
        for (size_t i = 0; i < vocab.size(); ++i) {
            const std::string& piece = vocab[i];
            vocab_[piece] = (int)i;
            reverseVocab_[(int)i] = piece;
            if (piece.size() == 6 && piece[0] == '<' && piece[1] == '0' &&
                piece[2] == 'x' && piece[5] == '>') {
                int byteVal = 0;
                bool ok = true;
                for (size_t k = 3; k < 5; ++k) {
                    char c = piece[k];
                    byteVal *= 16;
                    if (c >= '0' && c <= '9') byteVal += c - '0';
                    else if (c >= 'A' && c <= 'F') byteVal += c - 'A' + 10;
                    else if (c >= 'a' && c <= 'f') byteVal += c - 'a' + 10;
                    else { ok = false; break; }
                }
                if (ok && byteVal >= 0 && byteVal < 256 &&
                    byteFallback_[static_cast<size_t>(byteVal)] < 0) {
                    byteFallback_[static_cast<size_t>(byteVal)] = (int)i;
                }
            }
        }
        return true;
    }

    // Optional: load GGUF tokenizer.ggml.scores (TinyLlama is all-zero).
    bool LoadScores(const std::vector<float>& scores) {
        if (scores.size() != reverseVocab_.size()) return false;
        scores_ = scores;
        return true;
    }

    // gpt2 (Llama-3) vs llama (SentencePiece ▁). Auto-detect if unset.
    void SetTokenizerModel(const std::string& model) {
        model_ = model;
        gpt2_ = false;
        for (char& c : model_) c = (char)tolower((unsigned char)c);
        if (model_ == "gpt2" || model_ == "gpt-2") gpt2_ = true;
    }
    void InferTokenizerFamily() {
        if (!model_.empty()) return;
        // Vocab probe: Ġ (U+0120) vs ▁ (U+2581)
        int g = 0, u = 0;
        for (const auto& kv : reverseVocab_) {
            const std::string& p = kv.second;
            for (size_t i = 0; i + 1 < p.size(); ++i) {
                if ((unsigned char)p[i] == 0xC4 &&
                    (unsigned char)p[i + 1] == 0xA0)
                    ++g;
                if (i + 2 < p.size() && (unsigned char)p[i] == 0xE2 &&
                    (unsigned char)p[i + 1] == 0x96 &&
                    (unsigned char)p[i + 2] == 0x81)
                    ++u;
            }
            if (g > 32 || u > 32) break;
        }
        gpt2_ = (g > u);
        model_ = gpt2_ ? "gpt2" : "llama";
    }
    const std::string& TokenizerModel() const { return model_; }
    bool IsGpt2() const { return gpt2_; }

    // Apply merge ranks as scores (higher priority = larger score).
    bool LoadMergesAsScores(const std::vector<std::string>& merges) {
        if (reverseVocab_.empty()) return false;
        scores_.assign(reverseVocab_.size(), 0.0f);
        int rank = 0;
        for (const auto& line : merges) {
            if (line.empty() || line[0] == '#') continue;
            size_t sp = line.find(' ');
            if (sp == std::string::npos) continue;
            const std::string a = line.substr(0, sp);
            const std::string b = line.substr(sp + 1);
            if (a.empty() || b.empty()) continue;
            auto it = vocab_.find(a + b);
            if (it != vocab_.end() && it->second >= 0 &&
                (size_t)it->second < scores_.size()) {
                // Earlier merges win (llama.cpp rank order).
                scores_[(size_t)it->second] = (float)(1000000 - rank);
            }
            ++rank;
        }
        return rank > 0;
    }

    std::vector<int> Encode(const std::string& text) const override {
        std::vector<int> tokens;
        if (text.empty()) return tokens;

        // Same pipeline as GGUFEmbeddedTokenizer::EncodeLongestMatch:
        // special/control atoms → Spm::encode on ordinary spans.
        std::vector<std::pair<std::string, int>> specials;
        auto addSpecial = [&](int id) {
            if (id < 0) return;
            auto it = reverseVocab_.find(id);
            if (it == reverseVocab_.end() || it->second.empty()) return;
            for (const auto& e : specials) {
                if (e.second == id) return;
            }
            specials.emplace_back(it->second, id);
        };
        addSpecial(special_.bosId);
        addSpecial(special_.eosId);
        std::sort(specials.begin(), specials.end(),
                  [](const auto& a, const auto& b) {
                      if (a.first.size() != b.first.size())
                          return a.first.size() > b.first.size();
                      return a.first < b.first;
                  });

        const float* scorePtr =
            scores_.empty() ? nullptr : scores_.data();

        auto encodeSpan = [&](std::string_view span) {
            if (span.empty()) return;
            std::vector<int> part;
            if (gpt2_) {
                RawrXD::Spm::encodeGpt2(
                    span, vocab_, byteFallback_, scorePtr, special_.unkId,
                    part);
            } else {
                RawrXD::Spm::encode(
                    span, vocab_, byteFallback_, scorePtr, special_.unkId,
                    part);
            }
            tokens.insert(tokens.end(), part.begin(), part.end());
        };

        size_t pos = 0;
        size_t ordinaryStart = 0;
        while (pos < text.size()) {
            bool matched = false;
            const std::string_view rest(text.data() + pos, text.size() - pos);
            for (const auto& sp : specials) {
                if (rest.size() >= sp.first.size() &&
                    rest.compare(0, sp.first.size(), sp.first) == 0) {
                    encodeSpan(std::string_view(
                        text.data() + ordinaryStart, pos - ordinaryStart));
                    tokens.push_back(sp.second);
                    pos += sp.first.size();
                    ordinaryStart = pos;
                    matched = true;
                    break;
                }
            }
            if (!matched) ++pos;
        }
        encodeSpan(std::string_view(
            text.data() + ordinaryStart, text.size() - ordinaryStart));

        const char* dump = std::getenv("RAWRXD_BPE_ENCODE_DUMP");
        if (dump && dump[0] == '1') {
            std::fprintf(stderr, "[BPE_ENCODE] input_bytes=%zu tokens=%zu\n",
                         text.size(), tokens.size());
            for (size_t i = 0; i < tokens.size(); ++i) {
                std::fprintf(stderr, "[BPE_ENCODE] %zu id=%d\n", i, tokens[i]);
            }
            std::fflush(stderr);
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
        if (it == reverseVocab_.end()) return "";

        const std::string& raw = it->second;
        if (raw.size() == 6 && raw[0] == '<' && raw[1] == '0' && raw[2] == 'x') {
            int byteVal = 0;
            for (size_t i = 3; i < 5; ++i) {
                char c = raw[i];
                byteVal *= 16;
                if (c >= '0' && c <= '9') byteVal += c - '0';
                else if (c >= 'A' && c <= 'F') byteVal += c - 'A' + 10;
                else if (c >= 'a' && c <= 'f') byteVal += c - 'a' + 10;
            }
            return std::string(1, static_cast<char>(byteVal));
        }
        if (raw.size() == 4 && raw[0] == '0' && raw[1] == 'x') {
            int byteVal = 0;
            for (size_t i = 2; i < 4; ++i) {
                char c = raw[i];
                byteVal *= 16;
                if (c >= '0' && c <= '9') byteVal += c - '0';
                else if (c >= 'A' && c <= 'F') byteVal += c - 'A' + 10;
                else if (c >= 'a' && c <= 'f') byteVal += c - 'a' + 10;
            }
            return std::string(1, static_cast<char>(byteVal));
        }
        std::string out;
        out.reserve(raw.size());
        for (size_t i = 0; i < raw.size();) {
            // SentencePiece metaspace U+2581 ▁
            if (i + 2 < raw.size() &&
                static_cast<unsigned char>(raw[i]) == 0xE2 &&
                static_cast<unsigned char>(raw[i + 1]) == 0x96 &&
                static_cast<unsigned char>(raw[i + 2]) == 0x81) {
                out.push_back(' ');
                i += 3;
            // GPT-2 / Llama-3 space marker U+0120 Ġ
            } else if (i + 1 < raw.size() &&
                       static_cast<unsigned char>(raw[i]) == 0xC4 &&
                       static_cast<unsigned char>(raw[i + 1]) == 0xA0) {
                out.push_back(' ');
                i += 2;
            } else {
                out.push_back(raw[i]);
                ++i;
            }
        }
        return out;
    }

    size_t VocabSize() const override { return reverseVocab_.size(); }
    bool IsSpecial(int token) const override {
        return token == special_.bosId || token == special_.eosId ||
               token == special_.unkId || token == special_.padId;
    }
    const SpecialTokens& GetSpecialTokens() const override { return special_; }
    void SetSpecialTokens(const SpecialTokens& s) { special_ = s; }

private:
    std::unordered_map<std::string, int> vocab_;
    std::unordered_map<int, std::string> reverseVocab_;
    std::array<int, 256> byteFallback_{};
    std::vector<float> scores_;
    SpecialTokens special_;
    std::string model_;
    bool gpt2_ = false;
};

} // namespace Deep2
