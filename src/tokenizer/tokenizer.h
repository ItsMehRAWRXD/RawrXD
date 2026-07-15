/**
 * @file tokenizer.h
 * @brief RawrXD Tokenizer - Runtime-Owned Interface
 *
 * Step C2: Tokenizer Bridge. Consumes ModelContext, not GGUF files directly.
 * The gateway remains unaware of SentencePiece, BPE, or vocabulary internals.
 *
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// Forward declaration - only dependency
namespace rawrxd { namespace model { class ModelContext; } }

namespace rawrxd {
namespace tokenizer {

using TokenId = uint32_t;

// ============================================================================
// Tokenizer Telemetry (for inference integration)
// ============================================================================

struct TokenizerTelemetry {
    size_t input_bytes = 0;
    size_t token_count = 0;
    double tokens_per_byte = 0.0;
    uint32_t bos_id = 0;
    uint32_t eos_id = 0;
    double encode_ms = 0.0;
    double decode_ms = 0.0;
    
    std::string ToJson() const;
};

// ============================================================================
// Tokenizer Interface
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
     * This is the ONLY integration point with model data.
     * Does NOT read GGUF files directly.
     */
    bool Load(const model::ModelContext& model);
    
    // Check if loaded
    bool IsLoaded() const { return loaded_; }
    
    // Encode text to token IDs
    std::vector<TokenId> Encode(const std::string& text) const;
    
    // Decode token IDs to text
    std::string Decode(const std::vector<TokenId>& tokens) const;
    
    // Decode single token
    std::string DecodeToken(TokenId token) const;
    
    // Vocabulary info
    size_t VocabularySize() const { return vocab_size_; }
    TokenId GetBosToken() const { return bos_id_; }
    TokenId GetEosToken() const { return eos_id_; }
    TokenId GetPadToken() const { return pad_id_; }
    
    // Check if token is special
    bool IsSpecialToken(TokenId token) const;
    
    // Get telemetry from last operation
    const TokenizerTelemetry& GetLastTelemetry() const { return last_telemetry_; }
    
    // Get tokenizer type
    const std::string& GetType() const { return type_; }
    
    // Validation: round-trip test
    bool ValidateRoundTrip(const std::string& text, std::string* reconstructed = nullptr) const;
    
private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
    
    bool loaded_ = false;
    std::string type_;           // "llama", "gpt2", "sentencepiece", etc.
    size_t vocab_size_ = 0;
    TokenId bos_id_ = 1;
    TokenId eos_id_ = 2;
    TokenId pad_id_ = 0;
    mutable TokenizerTelemetry last_telemetry_;
};

// ============================================================================
// Tokenizer Factory
// ============================================================================

class TokenizerFactory {
public:
    // Create tokenizer from ModelContext
    static std::unique_ptr<Tokenizer> FromModel(const model::ModelContext& model);
    
    // Create empty tokenizer
    static std::unique_ptr<Tokenizer> Empty();
};

// ============================================================================
// Validation Utilities
// ============================================================================

struct TokenizerValidationResult {
    bool success = false;
    std::string test_name;
    std::string input_text;
    std::vector<TokenId> encoded_tokens;
    std::string decoded_text;
    bool round_trip_match = false;
    std::string error_message;
    TokenizerTelemetry telemetry;
    
    std::string ToJson() const;
    std::string ToHumanReadable() const;
};

// Run full validation suite
TokenizerValidationResult ValidateTokenizer(const Tokenizer& tokenizer, 
                                              const std::string& test_text = "hello world");

} // namespace tokenizer
} // namespace rawrxd
