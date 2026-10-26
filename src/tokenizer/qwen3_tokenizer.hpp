#pragma once
// ============================================================================
// qwen3_tokenizer.hpp -- Native Qwen3 BPE tokenizer for RawrXD
// ============================================================================
// Implements Qwen3/GPT-2-style byte-level BPE tokenizer using GGUF vocabulary.
// No external dependencies. Uses only C++20 standard library and Windows APIs.
//
// Tokenizer structure derived from GGUF:
//   tokens[0-255]   = Byte vocabulary (one per byte value)
//   tokens[256+]    = Merge results (position = merge rank, lower = higher priority)
//   tokens[151643+] = Special tokens (BOS=151643, EOS=151645, etc.)
//
// Pre-tokenization: Qwen2-style regex-based segmentation.
// Byte encoding: GPT-2-style reversible byte-to-Unicode mapping.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <map>
#include <array>
#include <cstdio>

namespace RawrXD {
namespace Qwen3Tokenizer {

// Encoded output
struct Encoded {
    std::vector<int32_t> ids;
    bool ok = false;
    std::string error;
};

// Tokenizer configuration
struct Config {
    int32_t bos_id = 151643;
    int32_t eos_id = 151645;
    int32_t pad_id = 151645;
    int32_t unk_id = 0;  // Will be set from vocab
    bool add_bos = false;
    bool add_eos = false;
};

// ---------------------------------------------------------------------------
// GPT-2 byte-to-Unicode mapping (reversible, all 256 bytes)
// ---------------------------------------------------------------------------
inline std::array<uint32_t, 256> buildByteToUnicode() {
    std::array<uint32_t, 256> m{};
    std::array<bool, 256> identity{};
    for (int ch = 0x21; ch <= 0x7E; ++ch) identity[ch] = true;
    for (int ch = 0xA1; ch <= 0xAC; ++ch) identity[ch] = true;
    for (int ch = 0xAE; ch <= 0xFF; ++ch) identity[ch] = true;
    uint32_t n = 0;
    for (int b = 0; b < 256; ++b)
        m[b] = identity[b] ? static_cast<uint32_t>(b) : (256u + n++);
    return m;
}

// Encode a single byte to its GPT-2 Unicode representation (UTF-8 string)
inline std::string byteToUtf8(unsigned char b) {
    static const auto kMap = buildByteToUnicode();
    uint32_t cp = kMap[b];
    std::string out;
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
    return out;
}

// Decode a GPT-2 Unicode string back to a byte (reverse lookup)
inline int utf8ToByte(std::string_view s) {
    static const auto kMap = buildByteToUnicode();
    // Build reverse map on first use
    static std::unordered_map<std::string, int> reverse;
    static bool built = false;
    if (!built) {
        for (int b = 0; b < 256; ++b)
            reverse[byteToUtf8(static_cast<unsigned char>(b))] = b;
        built = true;
    }
    auto it = reverse.find(std::string(s));
    return it != reverse.end() ? it->second : -1;
}

// ---------------------------------------------------------------------------
// Qwen2 pre-tokenizer: regex-based text segmentation
// Splits text into pre-tokens using Qwen's contraction-aware pattern.
// ---------------------------------------------------------------------------
struct PreToken {
    std::string text;
    size_t byte_offset;
    size_t byte_length;
};

// Qwen2 pre-tokenization pattern (adapted from Qwen2 tokenizer)
// Matches: contractions, words, numbers, punctuation, whitespace, other
inline std::vector<PreToken> preTokenize(std::string_view text) {
    std::vector<PreToken> result;
    size_t i = 0;
    const size_t n = text.size();

    auto isAlpha = [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    };
    auto isDigit = [](unsigned char c) { return c >= '0' && c <= '9'; };
    auto isSpace = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
               c == '\v' || c == '\f';
    };
    auto isUtf8Lead = [](unsigned char c) { return c >= 0x80; };

    while (i < n) {
        unsigned char c0 = static_cast<unsigned char>(text[i]);

        // Contractions: 's, 't, 'm, 'd, 're, 've, 'll
        if (c0 == '\'') {
            size_t end = i + 2;
            if (i + 2 <= n) {
                std::string_view sv(text.data() + i, 2);
                if (sv == "'s" || sv == "'t" || sv == "'m" || sv == "'d") {
                    result.push_back({std::string(sv), i, 2});
                    i += 2;
                    continue;
                }
            }
            if (i + 3 <= n) {
                std::string_view sv3(text.data() + i, 3);
                if (sv3 == "'re" || sv3 == "'ve" || sv3 == "'ll") {
                    result.push_back({std::string(sv3), i, 3});
                    i += 3;
                    continue;
                }
            }
            // Fall through to single char
        }

        // Words: [^\r\n\p{L}\p{N}]?\p{L}+\p{N}*
        // Simplified: optional non-alphanumeric + alphanumeric run
        if (isAlpha(c0) || isUtf8Lead(c0)) {
            size_t start = i;
            // Optional leading punctuation before a letter
            if (!isAlpha(c0)) {
                // It's a UTF-8 lead byte, consume the full codepoint
                size_t len = 1;
                if ((c0 & 0xF0) == 0xF0) len = 4;
                else if ((c0 & 0xE0) == 0xE0) len = 3;
                else if ((c0 & 0xC0) == 0xC0) len = 2;
                if (i + len <= n) i += len;
                if (i < n && isAlpha(static_cast<unsigned char>(text[i]))) {
                    // Continue with word
                } else {
                    result.push_back({std::string(text.substr(start, len)), start, len});
                    continue;
                }
            }
            // Consume alphanumeric run
            while (i < n) {
                unsigned char cc = static_cast<unsigned char>(text[i]);
                if (isAlpha(cc) || isDigit(cc) || isUtf8Lead(cc)) {
                    size_t len = 1;
                    if (isUtf8Lead(cc)) {
                        if ((cc & 0xF0) == 0xF0) len = 4;
                        else if ((cc & 0xE0) == 0xE0) len = 3;
                        else if ((cc & 0xC0) == 0xC0) len = 2;
                    }
                    if (i + len > n) break;
                    i += len;
                } else {
                    break;
                }
            }
            result.push_back({std::string(text.substr(start, i - start)), start, i - start});
            continue;
        }

        // Numbers: \p{N}+
        if (isDigit(c0)) {
            size_t start = i;
            while (i < n && isDigit(static_cast<unsigned char>(text[i]))) i++;
            result.push_back({std::string(text.substr(start, i - start)), start, i - start});
            continue;
        }

        // Whitespace: \s+
        if (isSpace(c0)) {
            size_t start = i;
            while (i < n && isSpace(static_cast<unsigned char>(text[i]))) i++;
            result.push_back({std::string(text.substr(start, i - start)), start, i - start});
            continue;
        }

        // Other: single non-space, non-alphanumeric character
        result.push_back({std::string(1, text[i]), i, 1});
        i++;
    }

    return result;
}

// ---------------------------------------------------------------------------
// Tokenizer class
// ---------------------------------------------------------------------------
class Tokenizer {
public:
    Tokenizer() = default;

    // Load from GGUF metadata (token list, special token IDs)
    bool loadFromGGUF(
        const std::vector<std::string>& tokens,
        const std::map<std::string, std::string>& metadata,
        const Config& cfg = Config()
    ) {
        tokens_ = tokens;
        config_ = cfg;

        // Build token -> id map
        idOf_.clear();
        idOf_.reserve(tokens.size());
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (!idOf_.count(tokens[i]))
                idOf_[tokens[i]] = static_cast<int32_t>(i);
        }

        // Build byte -> token id map from first 256 tokens
        byteToTokenId_.fill(-1);
        for (int b = 0; b < 256; ++b) {
            if (b < (int)tokens.size()) {
                std::string encoded = byteToUtf8(static_cast<unsigned char>(b));
                auto it = idOf_.find(encoded);
                if (it != idOf_.end())
                    byteToTokenId_[b] = it->second;
                else
                    byteToTokenId_[b] = b;  // Fallback: use index directly
            }
        }

        // Parse special token IDs from metadata
        auto getInt = [&](const std::string& key, int32_t def) -> int32_t {
            auto it = metadata.find(key);
            if (it != metadata.end()) {
                try { return std::stoi(it->second); } catch (...) { return def; }
            }
            return def;
        };
        config_.bos_id = getInt("tokenizer.ggml.bos_token_id", config_.bos_id);
        config_.eos_id = getInt("tokenizer.ggml.eos_token_id", config_.eos_id);
        config_.pad_id = getInt("tokenizer.ggml.padding_token_id", config_.pad_id);

        // Qwen3 GGUF has no explicit unk token; token 0 is "!".
        // Use -1 as unk_id sentinel so real token 0 is not skipped during decode.
        config_.unk_id = -1;

        return !tokens.empty();
    }

    bool isReady() const { return !tokens_.empty(); }
    int32_t vocabSize() const { return static_cast<int32_t>(tokens_.size()); }
    int32_t bosId() const { return config_.bos_id; }
    int32_t eosId() const { return config_.eos_id; }
    int32_t padId() const { return config_.pad_id; }
    int32_t unkId() const { return config_.unk_id; }

    // Encode text to token IDs
    Encoded encode(std::string_view text, bool add_bos = false, bool add_eos = false) {
        Encoded result;
        result.ok = false;

        if (!isReady()) {
            result.error = "Tokenizer not ready";
            return result;
        }

        // Step 1: Pre-tokenize
        auto preTokens = preTokenize(text);

        // Step 2: For each pre-token, convert to bytes, then apply BPE
        for (const auto& pt : preTokens) {
            auto ids = encodePreToken(pt.text);
            result.ids.insert(result.ids.end(), ids.begin(), ids.end());
        }

        // Step 3: Add special tokens
        if (add_bos && config_.bos_id >= 0)
            result.ids.insert(result.ids.begin(), config_.bos_id);
        if (add_eos && config_.eos_id >= 0)
            result.ids.push_back(config_.eos_id);

        result.ok = true;
        return result;
    }

    // Decode token IDs back to text
    // Reverses GPT-2 byte mapping: GPT-2 Unicode chars → raw bytes,
    // metaspace (▁ U+2581) → space, other GPT-2 symbols → raw bytes.
    std::string decode(const std::vector<int32_t>& ids, bool skip_special = true) const {
        // Step 1: Concatenate token strings
        std::string raw;
        raw.reserve(ids.size() * 2);
        for (int32_t id : ids) {
            if (skip_special && isSpecialToken(id)) continue;
            if (id < 0 || id >= (int32_t)tokens_.size()) continue;
            raw += tokens_[static_cast<size_t>(id)];
        }

        // Step 2: Reverse GPT-2 byte mapping
        // Each GPT-2 Unicode symbol represents either:
        //   - A printable ASCII byte (0x21-0x7E) as itself
        //   - A Latin-1 byte (0xA1-0xFF) as itself
        //   - A non-printable byte as U+0100-U+0143 (2-byte UTF-8)
        //   - Metaspace ▁ (U+2581) as space (0x20)
        std::string out;
        out.reserve(raw.size());
        for (size_t i = 0; i < raw.size();) {
            // Check for metaspace ▁ (U+2581 = UTF-8 E2 96 81)
            if (i + 3 <= raw.size() &&
                (unsigned char)raw[i] == 0xE2 &&
                (unsigned char)raw[i + 1] == 0x96 &&
                (unsigned char)raw[i + 2] == 0x81) {
                out += ' ';
                i += 3;
                continue;
            }
            // Try to decode a GPT-2 byte symbol (1 or 2 byte UTF-8)
            int b = -1;
            // 1-byte: printable ASCII or Latin-1
            if (i + 1 <= raw.size()) {
                b = utf8ToByte(raw.substr(i, 1));
            }
            if (b < 0 && i + 2 <= raw.size()) {
                b = utf8ToByte(raw.substr(i, 2));
            }
            if (b < 0 && i + 3 <= raw.size()) {
                b = utf8ToByte(raw.substr(i, 3));
            }
            if (b >= 0) {
                out += static_cast<char>(b);
                // Advance by the UTF-8 length of the GPT-2 symbol
                uint8_t c0 = (unsigned char)raw[i];
                size_t symLen = 1;
                if ((c0 & 0xF0) == 0xF0) symLen = 4;
                else if ((c0 & 0xE0) == 0xE0) symLen = 3;
                else if ((c0 & 0xC0) == 0xC0) symLen = 2;
                i += symLen;
                continue;
            }
            // Not a GPT-2 symbol: copy as-is (for special tokens, etc.)
            out += raw[i];
            i++;
        }
        return out;
    }

private:
    bool isSpecialToken(int32_t id) const {
        return id == config_.bos_id || id == config_.eos_id ||
               id == config_.pad_id || id == config_.unk_id;
    }

    // Encode a single pre-token using BPE
    std::vector<int32_t> encodePreToken(std::string_view text) {
        std::vector<int32_t> ids;

        // Convert text to bytes, then each byte to its GPT-2 Unicode representation
        // Then split into individual Unicode characters (symbols)
        std::vector<std::string> symbols;
        for (unsigned char c : text) {
            symbols.push_back(byteToUtf8(c));
        }

        if (symbols.empty()) return ids;

        // BPE: repeatedly merge the pair with the lowest rank
        // Merge rank = token position in vocab (lower = higher priority)
        bool merged = true;
        while (merged && symbols.size() > 1) {
            merged = false;
            int bestRank = INT32_MAX;
            size_t bestPos = 0;
            std::string bestMerged;

            for (size_t i = 0; i + 1 < symbols.size(); ++i) {
                std::string pair = symbols[i] + symbols[i + 1];
                auto it = idOf_.find(pair);
                if (it != idOf_.end()) {
                    int rank = it->second;
                    if (rank < bestRank) {
                        bestRank = rank;
                        bestPos = i;
                        bestMerged = pair;
                        merged = true;
                    }
                }
            }

            if (merged) {
                symbols[bestPos] = bestMerged;
                symbols.erase(symbols.begin() + static_cast<long>(bestPos) + 1);
            }
        }

        // Convert symbols to token IDs
        for (const auto& sym : symbols) {
            auto it = idOf_.find(sym);
            if (it != idOf_.end()) {
                ids.push_back(it->second);
            } else {
                // Fallback: encode byte-by-byte
                for (unsigned char c : sym) {
                    int tid = byteToTokenId_[static_cast<size_t>(c)];
                    if (tid >= 0) ids.push_back(tid);
                    else ids.push_back(config_.unk_id);
                }
            }
        }

        return ids;
    }

    std::vector<std::string> tokens_;
    std::unordered_map<std::string, int32_t> idOf_;
    std::array<int32_t, 256> byteToTokenId_;
    Config config_;
};

} // namespace Qwen3Tokenizer
} // namespace RawrXD
