// =============================================================================
// sovereign_tokenizer.h
// BPE Tokenizer for Llama 3.2
// Reads vocab from GGUF and handles encode/decode
// =============================================================================

#ifndef SOVEREIGN_TOKENIZER_H
#define SOVEREIGN_TOKENIZER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace Sovereign {

// =============================================================================
// Tokenizer Configuration
// =============================================================================

struct TokenizerConfig {
    uint32_t vocab_size = 32000;
    uint32_t bos_token_id = 1;  // Beginning of sequence
    uint32_t eos_token_id = 2;  // End of sequence
    uint32_t pad_token_id = 0;  // Padding
    uint32_t unk_token_id = 0;  // Unknown token
    bool add_bos = true;        // Prepend BOS token
    bool add_eos = false;       // Append EOS token
};

// =============================================================================
// BPE Merge Rule
// =============================================================================

struct BPEMerge {
    std::string left;
    std::string right;
    std::string merged;
    uint32_t rank;
    
    bool operator<(const BPEMerge& other) const {
        return rank < other.rank;
    }
};

// =============================================================================
// Sovereign Tokenizer
// =============================================================================

class SovereignTokenizer {
public:
    SovereignTokenizer();
    ~SovereignTokenizer();
    
    // Load tokenizer from GGUF file
    // Returns true on success
    bool LoadFromGGUF(const std::string& gguf_path);
    
    // Load from pre-extracted vocab data
    bool LoadVocabulary(
        const std::vector<std::string>& tokens,
        const std::vector<float>& scores,
        const TokenizerConfig& config = TokenizerConfig{}
    );
    
    // Encode text to token IDs
    // text: input string
    // Returns: vector of token IDs
    std::vector<uint32_t> Encode(const std::string& text) const;
    
    // Decode token IDs to text
    // ids: token IDs
    // Returns: reconstructed string
    std::string Decode(const std::vector<uint32_t>& ids) const;
    
    // Decode single token ID
    std::string DecodeToken(uint32_t token_id) const;
    
    // Get token ID for string (returns unk_token_id if not found)
    uint32_t GetTokenId(const std::string& token) const;
    
    // Check if tokenizer is loaded
    bool IsLoaded() const { return !id_to_token_.empty(); }
    
    // Get vocabulary size
    size_t GetVocabSize() const { return id_to_token_.size(); }
    
    // Get config
    const TokenizerConfig& GetConfig() const { return config_; }
    
    // Print vocab info (for debugging)
    void PrintVocabInfo() const;
    
private:
    TokenizerConfig config_;
    
    // Vocabulary mappings
    std::unordered_map<std::string, uint32_t> token_to_id_;
    std::vector<std::string> id_to_token_;
    std::vector<float> token_scores_;
    
    // BPE merge rules
    std::vector<BPEMerge> bpe_merges_;
    
    // Special token detection
    bool IsSpecialToken(const std::string& token) const;
    
    // BPE encoding steps
    std::vector<std::string> PreTokenize(const std::string& text) const;
    std::string ApplyBPE(const std::string& word) const;
    std::vector<std::pair<std::string, std::string>> GetBytePairs(
        const std::vector<std::string>& tokens
    ) const;
    
    // Byte-level fallback for unknown characters
    std::vector<uint32_t> ByteFallbackEncode(const std::string& text) const;
};

// =============================================================================
// Utility Functions
// =============================================================================

// Convert UTF-8 string to byte sequence
std::vector<uint8_t> UTF8ToBytes(const std::string& text);

// Convert byte to string representation
std::string ByteToString(uint8_t byte);

// Normalize text (lowercase, strip accents, etc.)
std::string NormalizeText(const std::string& text);

} // namespace Sovereign

#endif // SOVEREIGN_TOKENIZER_H
