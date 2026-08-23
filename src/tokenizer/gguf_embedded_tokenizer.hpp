#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>

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

    // Dependency-free fallback encoder.
    //
    // This intentionally does not pretend to implement SentencePiece/BPE.
    // It performs longest embedded-vocabulary matching, which is sufficient
    // for the VAL-051 real-token proof path and guarantees that token IDs
    // originate from the GGUF vocabulary.
    bool EncodeLongestMatch(
        std::string_view text,
        std::vector<uint32_t>& output) const;

    // Public for fuzz/bounds testing
    bool ParseGGUF(const uint8_t* data, size_t size);

private:
    std::vector<std::string> tokens_;
    std::unordered_map<std::string, uint32_t> lookup_;

    int32_t bosToken_ = -1;
    int32_t eosToken_ = -1;

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
