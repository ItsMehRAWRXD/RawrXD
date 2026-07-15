// ============================================================================
// RawrXD Tokenizer - BPE Implementation with GGUF Vocab Support
// ============================================================================
// Zero-dependency tokenizer for LLM inference
// Supports byte-pair encoding with deterministic normalization
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <functional>

namespace rawrxd {
namespace tokenizer {

// ============================================================================
// Types and Constants
// ============================================================================

using TokenId = int32_t;
using Token = std::string;

enum class NormalizationMode {
    NONE,           // No normalization
    NFKC,           // Unicode NFKC normalization (default)
    NFKC_STRICT     // NFKC + additional whitespace rules
};

// Special token IDs
constexpr TokenId TOKEN_UNK = 0;
constexpr TokenId TOKEN_BOS = 1;
constexpr TokenId TOKEN_EOS = 2;
constexpr TokenId TOKEN_PAD = 3;
constexpr TokenId TOKEN_MASK = 4;

// ============================================================================
// Vocabulary Structure
// ============================================================================

struct Vocabulary {
    // Token ID -> Token string
    std::unordered_map<TokenId, Token> id_to_token;
    
    // Token string -> Token ID
    std::unordered_map<Token, TokenId> token_to_id;
    
    // Byte-pair merges (priority order)
    std::vector<std::pair<Token, Token>> merges;
    
    // Special tokens
    TokenId unk_id = TOKEN_UNK;
    TokenId bos_id = TOKEN_BOS;
    TokenId eos_id = TOKEN_EOS;
    TokenId pad_id = TOKEN_PAD;
    
    // Vocab hash for proof metadata
    uint64_t vocab_hash = 0;
    
    // Version info
    std::string version = "1.0.0";
    
    // Check if token exists
    bool HasToken(const Token& token) const {
        return token_to_id.find(token) != token_to_id.end();
    }
    
    // Get token ID (returns unk_id if not found)
    TokenId GetTokenId(const Token& token) const {
        auto it = token_to_id.find(token);
        return (it != token_to_id.end()) ? it->second : unk_id;
    }
    
    // Get token string (returns "<unk>" if not found)
    Token GetTokenString(TokenId id) const {
        auto it = id_to_token.find(id);
        return (it != id_to_token.end()) ? it->second : "<unk>";
    }
    
    // Vocab size
    size_t Size() const { return id_to_token.size(); }
};

// ============================================================================
// Tokenizer Class
// ============================================================================

class Tokenizer {
public:
    Tokenizer();
    ~Tokenizer();
    
    // Load vocabulary from GGUF file
    bool LoadFromGGUF(const std::string& gguf_path);
    
    // Load vocabulary from separate vocab file
    bool LoadFromFile(const std::string& vocab_path);
    
    // Encode text to token IDs
    std::vector<TokenId> Encode(const std::string& text);
    
    // Decode token IDs to text
    std::string Decode(const std::vector<TokenId>& tokens);
    
    // Encode with special tokens (BOS/EOS)
    std::vector<TokenId> EncodeWithSpecial(const std::string& text, 
                                            bool add_bos = true, 
                                            bool add_eos = true);
    
    // Set normalization mode
    void SetNormalization(NormalizationMode mode) { norm_mode_ = mode; }
    
    // Get current normalization mode
    NormalizationMode GetNormalization() const { return norm_mode_; }
    
    // Get vocabulary info
    const Vocabulary& GetVocabulary() const { return vocab_; }
    
    // Get vocab hash for proof metadata
    uint64_t GetVocabHash() const { return vocab_.vocab_hash; }
    
    // Check if loaded
    bool IsLoaded() const { return loaded_; }
    
    // Get last error
    const std::string& GetLastError() const { return last_error_; }
    
    // Pre-tokenization cache
    void EnableCache(size_t max_size = 10000);
    void DisableCache();
    void ClearCache();
    
private:
    Vocabulary vocab_;
    NormalizationMode norm_mode_ = NormalizationMode::NFKC;
    bool loaded_ = false;
    std::string last_error_;
    
    // Cache
    struct CacheEntry {
        std::vector<TokenId> tokens;
        uint64_t access_count = 0;
    };
    std::unordered_map<std::string, CacheEntry> cache_;
    size_t cache_max_size_ = 0;
    bool cache_enabled_ = false;
    
    // Internal methods
    std::string Normalize(const std::string& text);
    std::vector<Token> PreTokenize(const std::string& text);
    std::vector<TokenId> BPEEncode(const std::vector<Token>& pieces);
    TokenId GetCachedOrEncode(const std::string& text);
    void AddToCache(const std::string& text, const std::vector<TokenId>& tokens);
    
    // Byte-level fallback for unknown characters
    std::vector<TokenId> ByteEncode(uint8_t byte);
};

// ============================================================================
// Utility Functions
// ============================================================================

// Compute vocab hash (SHA256-like)
uint64_t ComputeVocabHash(const Vocabulary& vocab);

// Validate token sequence
bool ValidateTokens(const std::vector<TokenId>& tokens, const Vocabulary& vocab);

// Get special token IDs
struct SpecialTokens {
    TokenId unk;
    TokenId bos;
    TokenId eos;
    TokenId pad;
};

SpecialTokens GetSpecialTokens(const Tokenizer& tokenizer);

// ============================================================================
// Global Tokenizer Access
// ============================================================================

// Get global tokenizer instance (singleton pattern)
Tokenizer* GetGlobalTokenizer();

// Set global tokenizer instance
void SetGlobalTokenizer(Tokenizer* tokenizer);

// Initialize global tokenizer from GGUF file
bool InitGlobalTokenizer(const std::string& gguf_path);

// Cleanup global tokenizer
void CleanupGlobalTokenizer();

// ============================================================================
// Checkpoint Integration
// ============================================================================

// Checkpoint hook for tokenizer state
#define RAWRXD_CHECKPOINT_GGUF_VOCAB(vocab_hash) \
    do { /* Implementation in checkpoint system */ } while(0)

// Checkpoint hook for tokenized input
#define RAWRXD_CHECKPOINT_TOKENS(tokens, count) \
    do { /* Implementation in checkpoint system */ } while(0)

} // namespace tokenizer
} // namespace rawrxd
