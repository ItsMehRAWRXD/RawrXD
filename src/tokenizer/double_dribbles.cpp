// ============================================================================
// double_dribbles.cpp — Sovereign Tokenizer Implementation
// Reverse-engineered byte-level BPE + SentencePiece. Zero external deps.
// ============================================================================

#include "double_dribbles.h"
#include <cstring>
#include <sstream>
#include <iostream>

namespace rawrxd {
namespace tokenizer {

// ============================================================================
// Calibration tables
// ============================================================================
DoubleDribbles::Calibration DoubleDribbles::GetCalibration(const std::string& family) {
    Calibration cal;
    if (family == "llama") {
        cal = {3.2, 1.25, 0.8, 1.0, 0.3};
    } else if (family == "qwen") {
        cal = {3.5, 1.15, 0.9, 1.0, 0.25};
    } else if (family == "phi") {
        cal = {3.0, 1.35, 0.75, 1.0, 0.35};
    } else if (family == "deepseek") {
        cal = {3.1, 1.20, 0.85, 1.0, 0.28};
    }
    return cal;
}

// ============================================================================
// Constructor
// ============================================================================
DoubleDribbles::DoubleDribbles(const std::string& family)
    : m_family(family)
    , m_cal(GetCalibration(family))
{
}

// ============================================================================
// Load vocabulary from GGUF-derived arrays
// ============================================================================
void DoubleDribbles::LoadVocab(const std::vector<std::string>& tokens,
                                const std::vector<uint32_t>& ids) {
    m_id2token.clear();
    m_token2id.clear();

    for (size_t i = 0; i < tokens.size() && i < ids.size(); ++i) {
        const auto& tok = tokens[i];
        uint32_t id = ids[i];
        std::vector<uint8_t> bytes(tok.begin(), tok.end());
        m_id2token[id] = bytes;
        m_token2id[bytes] = id;
    }

    // Detect special tokens
    auto findSpecial = [&](const std::vector<std::string>& candidates) -> int32_t {
        for (const auto& c : candidates) {
            std::vector<uint8_t> cb(c.begin(), c.end());
            auto it = m_token2id.find(cb);
            if (it != m_token2id.end()) return (int32_t)it->second;
        }
        return -1;
    };

    m_unkId = findSpecial({"<|unk|>", "<unk>", "[UNK]"});
    m_bosId = findSpecial({"<|begin_of_text|>", "<s>", "[CLS]"});
    m_eosId = findSpecial({"<|end_of_text|>", "</s>", "[SEP]"});

    if (m_unkId < 0 && !m_id2token.empty()) m_unkId = 0;
    m_mode = TokenizerMode::EXACT;
}

// ============================================================================
// Load merge rules
// ============================================================================
void DoubleDribbles::LoadMerges(const std::vector<MergePair>& merges) {
    m_merges = merges;
    m_mergeLookup.clear();

    for (const auto& m : merges) {
        PairKey key;
        key.key = ((uint64_t)m.id_a << 32) | m.id_b;
        m_mergeLookup[key] = {m.merged_id, m.rank};
    }
}

// ============================================================================
// Approximate token counting (statistical fast-path)
// ============================================================================
size_t DoubleDribbles::CountApprox(const std::string& text) const {
    if (text.empty()) return 0;

    // Detect if text is code-heavy
    int nonAlnum = 0;
    for (char c : text) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && !std::isspace(static_cast<unsigned char>(c)))
            nonAlnum++;
    }
    double mult = m_cal.code_mult;
    if ((double)nonAlnum / std::max((int)text.length(), 1) <= 0.15) {
        mult = 1.0; // prose
    }

    size_t total = 0;
    size_t i = 0;
    while (i < text.length()) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        if (std::isalpha(c)) {
            // Word
            size_t start = i;
            while (i < text.length() && std::isalpha(static_cast<unsigned char>(text[i]))) i++;
            size_t len = i - start;
            total += std::max((size_t)1, (size_t)(len / (m_cal.chars_per_token * mult)));
        } else if (std::isdigit(c)) {
            size_t start = i;
            while (i < text.length() && std::isdigit(static_cast<unsigned char>(text[i]))) i++;
            size_t len = i - start;
            total += std::max((size_t)1, (size_t)(len / (m_cal.chars_per_token * m_cal.num_mult * mult)));
        } else if (std::isspace(c)) {
            size_t start = i;
            while (i < text.length() && std::isspace(static_cast<unsigned char>(text[i]))) i++;
            size_t len = i - start;
            total += std::max((size_t)1, (size_t)(len / (m_cal.chars_per_token * m_cal.ws_mult * mult)));
        } else {
            // Symbol
            total += (size_t)(m_cal.sym_mult);
            i++;
        }
    }
    return total;
}

// ============================================================================
// BPE word encoding
// ============================================================================
std::vector<uint32_t> DoubleDribbles::BpeWord(const std::vector<uint8_t>& word_bytes) const {
    if (word_bytes.empty()) return {};

    // Initialize with byte-level tokens
    std::vector<uint32_t> tokens;
    for (uint8_t b : word_bytes) {
        std::vector<uint8_t> byte_tok = {b};
        auto it = m_token2id.find(byte_tok);
        if (it != m_token2id.end()) {
            tokens.push_back(it->second);
        } else {
            tokens.push_back(m_unkId);
        }
    }

    if (m_merges.empty()) return tokens;

    // Greedy BPE merge loop
    while (tokens.size() > 1) {
        uint32_t best_rank = UINT32_MAX;
        int best_idx = -1;
        uint32_t best_merged = 0;

        for (size_t i = 0; i < tokens.size() - 1; ++i) {
            PairKey key;
            key.key = ((uint64_t)tokens[i] << 32) | tokens[i + 1];
            auto it = m_mergeLookup.find(key);
            if (it != m_mergeLookup.end()) {
                if (it->second.second < best_rank) {
                    best_rank = it->second.second;
                    best_idx = (int)i;
                    best_merged = it->second.first;
                }
            }
        }

        if (best_idx < 0) break; // No more merges possible

        // Apply merge: replace pair at best_idx with merged token
        tokens[best_idx] = best_merged;
        tokens.erase(tokens.begin() + best_idx + 1);
    }

    return tokens;
}

// ============================================================================
// Exact BPE encoding
// ============================================================================
std::vector<uint32_t> DoubleDribbles::EncodeExact(const std::string& text) const {
    if (text.empty()) return {};

    // Split into words (GPT-2 style regex)
    std::vector<std::vector<uint8_t>> words;
    size_t i = 0;
    while (i < text.length()) {
        // Skip whitespace
        if (std::isspace(static_cast<unsigned char>(text[i]))) {
            size_t start = i;
            while (i < text.length() && std::isspace(static_cast<unsigned char>(text[i]))) i++;
            std::vector<uint8_t> ws(text.begin() + start, text.begin() + i);
            words.push_back(ws);
            continue;
        }

        // Collect word (including punctuation contractions like 's, 't, etc.)
        size_t start = i;
        while (i < text.length() && !std::isspace(static_cast<unsigned char>(text[i]))) i++;
        std::vector<uint8_t> word(text.begin() + start, text.begin() + i);
        words.push_back(word);
    }

    // Encode each word with BPE
    std::vector<uint32_t> result;
    for (const auto& w : words) {
        auto encoded = BpeWord(w);
        result.insert(result.end(), encoded.begin(), encoded.end());
    }
    return result;
}

// ============================================================================
// Public encode
// ============================================================================
std::vector<uint32_t> DoubleDribbles::Encode(const std::string& text) const {
    if (m_mode == TokenizerMode::EXACT) {
        return EncodeExact(text);
    }
    // Approximate mode returns sequential IDs
    size_t count = CountApprox(text);
    std::vector<uint32_t> result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        result.push_back((uint32_t)i);
    }
    return result;
}

// ============================================================================
// Token count (primary interface)
// ============================================================================
size_t DoubleDribbles::Count(const std::string& text) const {
    if (text.empty()) return 0;
    if (m_mode == TokenizerMode::EXACT) {
        return EncodeExact(text).size();
    }
    return CountApprox(text);
}

// ============================================================================
// Decode
// ============================================================================
std::string DoubleDribbles::Decode(const std::vector<uint32_t>& tokens) const {
    if (m_mode != TokenizerMode::EXACT) {
        return "[approximate decode unavailable]";
    }

    std::vector<uint8_t> result;
    for (uint32_t id : tokens) {
        auto it = m_id2token.find(id);
        if (it != m_id2token.end()) {
            result.insert(result.end(), it->second.begin(), it->second.end());
        }
    }
    return std::string(result.begin(), result.end());
}

// ============================================================================
// Dribbler implementation
// ============================================================================
DoubleDribbles::Dribbler::Dribbler(const DoubleDribbles* tokenizer, const std::string& text)
    : m_tokens(tokenizer->Encode(text))
{
}

bool DoubleDribbles::Dribbler::Next(uint32_t& token) {
    if (m_index >= m_tokens.size()) return false;
    token = m_tokens[m_index++];
    return true;
}

} // namespace tokenizer
} // namespace rawrxd
