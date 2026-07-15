// ============================================================================
// C7: Decode Output - Token-to-Text Conversion
// Final step in the sovereign inference pipeline
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <memory>

namespace seg {

// ============================================================================
// Decode Configuration
// ============================================================================

struct DecodeConfig {
    // Special token handling
    bool strip_special_tokens = true;      // Remove <|...|> tokens
    bool preserve_eos = false;            // Keep EOS token in output
    
    // Whitespace handling
    bool trim_leading_whitespace = true;  // Remove leading space from first token
    bool normalize_whitespace = false;    // Collapse multiple spaces
    
    // Error handling
    char unknown_token_char = 0xFFFD;      // Replacement char for unknown tokens
    bool skip_unknown_tokens = false;     // Skip instead of replacing
    
    // BPE-specific
    bool handle_byte_fallback = true;    // Handle byte fallback tokens
    bool merge_continuation_spaces = true; // Merge "Ġ" space markers
};

// ============================================================================
// Token Decoder
// ============================================================================

class TokenDecoder {
public:
    TokenDecoder();
    ~TokenDecoder();
    
    // Initialize with vocabulary
    bool Initialize(const std::unordered_map<uint32_t, std::string>& vocab);
    bool Initialize(const std::vector<std::string>& vocab_list);
    
    // Decode tokens to text
    std::string Decode(const std::vector<uint32_t>& tokens, 
                       const DecodeConfig& config = {});
    
    // Decode single token
    std::string DecodeToken(uint32_t token_id) const;
    
    // Check if token is special
    bool IsSpecialToken(uint32_t token_id) const;
    bool IsByteFallbackToken(uint32_t token_id) const;
    
    // Get vocabulary info
    size_t GetVocabSize() const { return vocab_.size(); }
    bool HasToken(uint32_t token_id) const;
    
private:
    std::unordered_map<uint32_t, std::string> vocab_;
    std::unordered_map<std::string, uint32_t> reverse_vocab_;
    
    // Special token detection
    bool IsSpecialTokenString(const std::string& text) const;
    std::string ProcessBPE(const std::string& text, const DecodeConfig& config);
    std::string HandleByteFallback(uint32_t token_id) const;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick decode with default settings
std::string DecodeTokens(const std::vector<uint32_t>& tokens,
                         const std::unordered_map<uint32_t, std::string>& vocab);

// Decode with custom config
std::string DecodeTokens(const std::vector<uint32_t>& tokens,
                         const std::unordered_map<uint32_t, std::string>& vocab,
                         const DecodeConfig& config);

// Strip special tokens from text
std::string StripSpecialTokens(const std::string& text);

// Normalize whitespace
std::string NormalizeWhitespace(const std::string& text);

// ============================================================================
// Common Vocabulary Helpers
// ============================================================================

// Create Llama-3 vocabulary (simplified)
std::unordered_map<uint32_t, std::string> CreateLlama3Vocab();

// Create Qwen2 vocabulary (simplified)
std::unordered_map<uint32_t, std::string> CreateQwen2Vocab();

// Load vocabulary from file
std::unordered_map<uint32_t, std::string> LoadVocabFromFile(const std::string& path);

} // namespace seg
