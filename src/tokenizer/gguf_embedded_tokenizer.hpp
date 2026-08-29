#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <array>

namespace RawrXD {

class GGUFEmbeddedTokenizer {
public:
    GGUFEmbeddedTokenizer() = default;
    ~GGUFEmbeddedTokenizer() = default;

    GGUFEmbeddedTokenizer(const GGUFEmbeddedTokenizer&) = delete;
    GGUFEmbeddedTokenizer& operator=(const GGUFEmbeddedTokenizer&) = delete;

    bool LoadFromGGUF(const std::string& ggufPath);

    bool IsLoaded() const noexcept {
        return !tokens_.empty();
    }

    size_t VocabSize() const noexcept {
        return tokens_.size();
    }

    const std::string& Token(uint32_t id) const {
        static const std::string empty;
        return id < tokens_.size() ? tokens_[id] : empty;
    }

    int32_t BosToken() const noexcept { return bosToken_; }
    int32_t EosToken() const noexcept { return eosToken_; }

    // Exact token lookup.
    int32_t FindToken(std::string_view text) const;

    // Dependency-free encoder approximating llama.cpp / SentencePiece:
    //   1) Match GGUF control/user-defined tokens atomically
    //   2) Encode ordinary spans with ▁ prefix (SPM space marker)
    //   3) Byte-fallback via <0xHH> vocab entries
    bool EncodeLongestMatch(
        std::string_view text,
        std::vector<uint32_t>& output) const;

    // Public for fuzz/bounds testing
    bool ParseGGUF(const uint8_t* data, size_t size);

private:
    static constexpr int32_t TOKEN_CONTROL = 3;
    static constexpr int32_t TOKEN_USER_DEFINED = 4;

    std::vector<std::string> tokens_;
    std::vector<int32_t> tokenTypes_;
    std::unordered_map<std::string, uint32_t> lookup_;
    // Special/control/user-defined strings, longest-first for atomic matching
    std::vector<std::pair<std::string, uint32_t>> specialsSorted_;
    // Byte fallback: raw byte -> vocab id of "<0xHH>" (or -1)
    std::array<int32_t, 256> byteFallback_{};

    int32_t bosToken_ = -1;
    int32_t eosToken_ = -1;

    void RebuildIndexes();
    bool EncodeOrdinarySpan(
        std::string_view span,
        std::vector<uint32_t>& output) const;
    bool MatchSpecialAt(
        std::string_view text,
        size_t pos,
        size_t& matchedLen,
        uint32_t& matchedId) const;

    static bool ReadU32(
        const uint8_t*& p,
        const uint8_t* end,
        uint32_t& out);

    static bool ReadU64(
        const uint8_t*& p,
        const uint8_t* end,
        uint64_t& out);

    static bool ReadI32(
        const uint8_t*& p,
        const uint8_t* end,
        int32_t& out);

    static bool ReadString(
        const uint8_t*& p,
        const uint8_t* end,
        std::string& out);

    static bool SkipValue(
        const uint8_t*& p,
        const uint8_t* end,
        uint32_t type);

    static bool IsValidRange(
        const uint8_t* p,
        const uint8_t* end,
        size_t n);
};

} // namespace RawrXD
