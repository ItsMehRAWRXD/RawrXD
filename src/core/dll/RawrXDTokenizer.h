// RawrXDTokenizer.h — GGUF Tokenizer Integration
// Reads tokenizer data from GGUF metadata and provides encoding/decoding

#pragma once

#include "RawrXDCore_exports.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

// Token type enum (matches GGUF tokenizer token types)
typedef enum RawrXDTokenType {
    RAWXD_TOKEN_NORMAL = 1,
    RAWXD_TOKEN_UNKNOWN = 2,
    RAWXD_TOKEN_CONTROL = 3,
    RAWXD_TOKEN_USER_DEFINED = 4,
    RAWXD_TOKEN_UNUSED = 5,
    RAWXD_TOKEN_BYTE = 6
} RawrXDTokenType;

// Opaque tokenizer handle
typedef struct RawrXDTokenizer RawrXDTokenizer;

// Tokenizer creation from loaded model
RAWXDCORE_EXPORT RawrXDTokenizer* RawrXDCore_CreateTokenizer(RawrXDModel* model);
RAWXDCORE_EXPORT void RawrXDCore_DestroyTokenizer(RawrXDTokenizer* tokenizer);

// Encoding/decoding
RAWXDCORE_EXPORT size_t RawrXDCore_Tokenize(
    RawrXDTokenizer* tokenizer,
    const char* text,
    uint32_t* outTokens,
    size_t maxTokens
);

RAWXDCORE_EXPORT const char* RawrXDCore_Detokenize(
    RawrXDTokenizer* tokenizer,
    const uint32_t* tokens,
    size_t tokenCount,
    char* outBuffer,
    size_t bufferSize
);

// Special token IDs
RAWXDCORE_EXPORT uint32_t RawrXDCore_GetBosTokenId(RawrXDTokenizer* tokenizer);
RAWXDCORE_EXPORT uint32_t RawrXDCore_GetEosTokenId(RawrXDTokenizer* tokenizer);
RAWXDCORE_EXPORT uint32_t RawrXDCore_GetUnkTokenId(RawrXDTokenizer* tokenizer);
RAWXDCORE_EXPORT uint32_t RawrXDCore_GetVocabSize(RawrXDTokenizer* tokenizer);

// Token info
RAWXDCORE_EXPORT const char* RawrXDCore_GetTokenText(RawrXDTokenizer* tokenizer, uint32_t tokenId);
RAWXDCORE_EXPORT RawrXDTokenType RawrXDCore_GetTokenType(RawrXDTokenizer* tokenizer, uint32_t tokenId);

// BPE merge info (for debugging/analysis)
RAWXDCORE_EXPORT size_t RawrXDCore_GetMergeCount(RawrXDTokenizer* tokenizer);

#ifdef __cplusplus
}
#endif

// C++ API
#ifdef __cplusplus

namespace rawrxd {

class RAWXDCORE_EXPORT Tokenizer {
public:
    Tokenizer() : handle_(nullptr) {}
    explicit Tokenizer(RawrXDModel* model) { create(model); }
    ~Tokenizer() { if (handle_) RawrXDCore_DestroyTokenizer(handle_); }
    
    Tokenizer(Tokenizer&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }
    Tokenizer& operator=(Tokenizer&& other) noexcept {
        if (handle_) RawrXDCore_DestroyTokenizer(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
        return *this;
    }
    
    Tokenizer(const Tokenizer&) = delete;
    Tokenizer& operator=(const Tokenizer&) = delete;
    
    bool create(RawrXDModel* model) {
        if (handle_) RawrXDCore_DestroyTokenizer(handle_);
        handle_ = RawrXDCore_CreateTokenizer(model);
        return handle_ != nullptr;
    }
    
    std::vector<uint32_t> encode(const std::string& text) const {
        if (!handle_) return {};
        std::vector<uint32_t> tokens(RawrXDCore_GetVocabSize(handle_));
        size_t count = RawrXDCore_Tokenize(handle_, text.c_str(), tokens.data(), tokens.size());
        tokens.resize(count);
        return tokens;
    }
    
    std::string decode(const std::vector<uint32_t>& tokens) const {
        if (!handle_) return "";
        size_t bufferSize = tokens.size() * 4 + 1; // rough estimate
        std::string result;
        result.resize(bufferSize);
        size_t written = RawrXDCore_Detokenize(handle_, tokens.data(), tokens.size(), result.data(), bufferSize);
        result.resize(written);
        return result;
    }
    
    uint32_t bosTokenId() const { return handle_ ? RawrXDCore_GetBosTokenId(handle_) : 0; }
    uint32_t eosTokenId() const { return handle_ ? RawrXDCore_GetEosTokenId(handle_) : 0; }
    uint32_t unkTokenId() const { return handle_ ? RawrXDCore_GetUnkTokenId(handle_) : 0; }
    uint32_t vocabSize() const { return handle_ ? RawrXDCore_GetVocabSize(handle_) : 0; }
    
    const char* getTokenText(uint32_t id) const { return handle_ ? RawrXDCore_GetTokenText(handle_, id) : nullptr; }
    RawrXDTokenType getTokenType(uint32_t id) const { return handle_ ? RawrXDCore_GetTokenType(handle_, id) : RAWXD_TOKEN_UNKNOWN; }
    
    operator bool() const { return handle_ != nullptr; }
    RawrXDTokenizer* get() const { return handle_; }
    
private:
    RawrXDTokenizer* handle_;
};

} // namespace rawrxd

#endif // __cplusplus