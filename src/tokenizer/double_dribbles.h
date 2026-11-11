#pragma once
// ============================================================================
// double_dribbles.h — Sovereign Tokenizer
// Reverse-engineered byte-level BPE + SentencePiece. Zero external deps.
// Dual-mode: EXACT (GGUF vocab + merge table) or APPROX (statistical).
// ============================================================================

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <memory>
#include <functional>
#include <algorithm>
#include <cctype>
#include <regex>

namespace rawrxd {
namespace tokenizer {

// ============================================================================
// Tokenizer Types
// ============================================================================
enum class TokenizerMode {
    APPROX = 0,  // Statistical fast-path, no model needed
    EXACT = 1    // Real BPE via GGUF vocab + merge table
};

// ============================================================================
// Merge Pair (for BPE)
// ============================================================================
struct MergePair {
    uint32_t id_a;
    uint32_t id_b;
    uint32_t merged_id;
    uint32_t rank;
};

// ============================================================================
// DoubleDribbles — Sovereign Tokenizer
// ============================================================================
class DoubleDribbles {
public:
    DoubleDribbles(const std::string& family = "llama");
    ~DoubleDribbles() = default;

    // Mount a GGUF-derived vocabulary for exact tokenization
    void LoadVocab(const std::vector<std::string>& tokens,
                   const std::vector<uint32_t>& ids);
    void LoadMerges(const std::vector<MergePair>& merges);

    // Token counting (primary interface for Chatter Boxes)
    size_t Count(const std::string& text) const;

    // Full encode/decode
    std::vector<uint32_t> Encode(const std::string& text) const;
    std::string Decode(const std::vector<uint32_t>& tokens) const;

    // Stream interface — dribbles tokens one at a time
    class Dribbler {
    public:
        Dribbler(const DoubleDribbles* tokenizer, const std::string& text);
        bool Next(uint32_t& token);
    private:
        std::vector<uint32_t> m_tokens;
        size_t m_index = 0;
    };

    Dribbler Dribble(const std::string& text) const {
        return Dribbler(this, text);
    }

    // Properties
    TokenizerMode Mode() const { return m_mode; }
    size_t VocabSize() const { return m_id2token.size(); }
    bool IsExact() const { return m_mode == TokenizerMode::EXACT; }

    // Special tokens
    int32_t UnkId() const { return m_unkId; }
    int32_t BosId() const { return m_bosId; }
    int32_t EosId() const { return m_eosId; }

private:
    // Approximate counting
    size_t CountApprox(const std::string& text) const;

    // Exact BPE encoding
    std::vector<uint32_t> EncodeExact(const std::string& text) const;
    std::vector<uint32_t> BpeWord(const std::vector<uint8_t>& word_bytes) const;

    // State
    TokenizerMode m_mode = TokenizerMode::APPROX;
    std::string m_family;

    // Vocab
    std::unordered_map<uint32_t, std::vector<uint8_t>> m_id2token;
    std::unordered_map<std::vector<uint8_t>, uint32_t> m_token2id;

    // Merge table
    std::vector<MergePair> m_merges;
    // Fast lookup: pair_hash -> (merged_id, rank)
    struct PairKey {
        uint64_t key; // (id_a << 32) | id_b
        bool operator==(const PairKey& o) const { return key == o.key; }
    };
    struct PairHash {
        size_t operator()(const PairKey& k) const {
            return std::hash<uint64_t>{}(k.key);
        }
    };
    std::unordered_map<PairKey, std::pair<uint32_t, uint32_t>, PairHash> m_mergeLookup;

    // Special token IDs
    int32_t m_unkId = 0;
    int32_t m_bosId = -1;
    int32_t m_eosId = -1;

    // Approximate calibration constants per family
    struct Calibration {
        double chars_per_token = 3.2;
        double code_mult = 1.25;
        double num_mult = 0.8;
        double sym_mult = 1.0;
        double ws_mult = 0.3;
    };
    Calibration m_cal;
    static Calibration GetCalibration(const std::string& family);
};

} // namespace tokenizer
} // namespace rawrxd
