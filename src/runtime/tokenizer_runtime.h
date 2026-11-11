/**
 * @file tokenizer_runtime.h
 * @brief RawrXD Runtime Tokenizer - Step C2
 *
 * Runtime-owned tokenizer that consumes ModelContext.
 * Gateway remains unaware of SentencePiece/BPE internals.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include "../model/model_context.h"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

namespace rawrxd {
namespace runtime {

using TokenId = int32_t;
constexpr TokenId INVALID_TOKEN = -1;

// ============================================================================
// Tokenizer Telemetry
// ============================================================================

struct TokenizerTelemetry {
    size_t input_bytes = 0;
    size_t token_count = 0;
    double tokens_per_byte = 0.0;
    double encode_ms = 0.0;
    double decode_ms = 0.0;
    TokenId bos_id = INVALID_TOKEN;
    TokenId eos_id = INVALID_TOKEN;
    TokenId unk_id = INVALID_TOKEN;
    
    std::string ToJson() const;
};

// ============================================================================
// Tokenizer Interface (Runtime-Owned)
// ============================================================================

class Tokenizer {
public:
    Tokenizer();
    ~Tokenizer();
    
    // Disable copy, enable move
    Tokenizer(const Tokenizer&) = delete;
    Tokenizer& operator=(const Tokenizer&) = delete;
    Tokenizer(Tokenizer&&) noexcept;
    Tokenizer& operator=(Tokenizer&&) noexcept;
    
    /**
     * Load tokenizer from ModelContext.
     * Extracts vocabulary from GGUF metadata.
     */
    bool Load(const model::ModelContext& model);
    
    /**
     * Encode text to token IDs.
     * Returns empty vector on failure.
     */
    std::vector<TokenId> Encode(const std::string& text) const;
    
    /**
     * Decode token IDs to text.
     */
    std::string Decode(const std::vector<TokenId>& tokens) const;
    
    /**
     * Decode single token to string.
     */
    std::string Decode(TokenId token) const;
    
    /**
     * Convert token ID to token string.
     */
    std::string IdToToken(TokenId id) const;
    
    /**
     * Vocabulary size.
     */
    size_t VocabularySize() const;
    
    /**
     * Check if tokenizer is loaded and ready.
     */
    bool IsLoaded() const;
    
    /**
     * Get special token IDs.
     */
    TokenId BosToken() const { return bos_id_; }
    TokenId EosToken() const { return eos_id_; }
    TokenId UnkToken() const { return unk_id_; }
    TokenId PadToken() const { return pad_id_; }
    
    /**
     * Get tokenizer model type.
     */
    std::string ModelType() const { return model_type_; }
    
    /**
     * Get telemetry from last operation.
     */
    TokenizerTelemetry GetTelemetry() const { return telemetry_; }
    
    /**
     * Reset telemetry.
     */
    void ResetTelemetry();
    
    /**
     * Human-readable summary.
     */
    std::string ToString() const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    // Metadata
    std::string model_type_;
    TokenId bos_id_ = INVALID_TOKEN;
    TokenId eos_id_ = INVALID_TOKEN;
    TokenId unk_id_ = INVALID_TOKEN;
    TokenId pad_id_ = INVALID_TOKEN;
    
    // Telemetry
    mutable TokenizerTelemetry telemetry_;
    
    // Implementation helpers
    bool LoadFromGGUFMetadata(const model::ModelContext& model);
};

// ============================================================================
// Tokenizer Factory
// ============================================================================

class TokenizerFactory {
public:
    static std::unique_ptr<Tokenizer> FromModel(const model::ModelContext& model);
    static std::unique_ptr<Tokenizer> Empty();
};

// ============================================================================
// Validation Helpers (for testing)
// ============================================================================

struct TokenizerValidation {
    static bool TestRoundTrip(const Tokenizer& tokenizer, const std::string& text);
    static bool TestVocabularyLoaded(const Tokenizer& tokenizer);
    static bool TestSpecialTokens(const Tokenizer& tokenizer);
};

} // namespace runtime
} // namespace rawrxd
