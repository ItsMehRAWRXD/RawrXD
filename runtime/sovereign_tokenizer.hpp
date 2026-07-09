// ============================================================================
// sovereign_tokenizer.hpp - Pure C++ BPE Tokenizer
// ============================================================================
// Zero-dependency tokenizer supporting GPT-2, LLaMA, Mistral, Phi-3, Qwen.
// Loads tokenizer.json (HuggingFace format) and performs greedy BPE.
//
// Features:
// - UTF-8 aware
// - Byte-level BPE (GPT-2 style)
// - Reversible encoding/decoding
// - Zero allocations in hot paths
// - Embeddable vocab option
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Tokenizer Configuration
// ============================================================================
struct TokenizerConfig {
    std::string vocab_path;           // Path to tokenizer.json
    bool add_bos = false;             // Add beginning-of-sequence token
    bool add_eos = false;             // Add end-of-sequence token
    uint32_t bos_token_id = 1;        // BOS token ID
    uint32_t eos_token_id = 2;        // EOS token ID
    uint32_t pad_token_id = 0;        // Padding token ID
    uint32_t unk_token_id = 0;        // Unknown token ID
    
    // Special tokens
    std::string bos_token = "<s>";
    std::string eos_token = "</s>";
    std::string unk_token = "<unk>";
    std::string pad_token = "<pad>";
};

// ============================================================================
// BPE Merge Rank
// ============================================================================
// Used for priority ordering of BPE merges
using BPEMerge = std::pair<std::string, std::string>;

struct BPEMergeHash {
    size_t operator()(const BPEMerge& merge) const {
        return std::hash<std::string>{}(merge.first) ^ 
               (std::hash<std::string>{}(merge.second) << 1);
    }
};

// ============================================================================
// SovereignTokenizer - Pure C++ BPE Implementation
// ============================================================================
class SovereignTokenizer {
public:
    SovereignTokenizer();
    ~SovereignTokenizer();

    // Load tokenizer from tokenizer.json
    bool Load(const std::string& path);
    bool LoadFromJson(const std::string& json_content);
    
    // Configure behavior
    void SetConfig(const TokenizerConfig& config) { m_config = config; }
    const TokenizerConfig& GetConfig() const { return m_config; }

    // Encode text to token IDs
    std::vector<uint32_t> Encode(const std::string& text) const;
    std::vector<uint32_t> Encode(const std::string& text, bool add_bos, bool add_eos) const;
    
    // Decode token IDs to text
    std::string Decode(const std::vector<uint32_t>& tokens) const;
    std::string Decode(const uint32_t* tokens, size_t count) const;
    
    // Single token operations
    uint32_t TokenToId(const std::string& token) const;
    std::string IdToToken(uint32_t id) const;
    
    // Vocab info
    size_t GetVocabSize() const { return m_id_to_token.size(); }
    bool IsInVocab(const std::string& token) const;
    
    // Special tokens
    uint32_t GetBosTokenId() const { return m_config.bos_token_id; }
    uint32_t GetEosTokenId() const { return m_config.eos_token_id; }
    uint32_t GetPadTokenId() const { return m_config.pad_token_id; }
    uint32_t GetUnkTokenId() const { return m_config.unk_token_id; }
    
    // Statistics
    size_t GetNumMerges() const { return m_merges.size(); }
    
    // Validation
    bool IsValid() const { return !m_id_to_token.empty(); }

private:
    TokenizerConfig m_config;
    
    // Vocabulary
    std::unordered_map<std::string, uint32_t> m_token_to_id;
    std::vector<std::string> m_id_to_token;
    
    // BPE merges (pair -> rank/priority)
    std::unordered_map<BPEMerge, int, BPEMergeHash> m_merges;
    
    // Byte encoder/decoder (GPT-2 style)
    // Maps bytes 0-255 to their string representation (may be multi-byte UTF-8)
    std::unordered_map<uint8_t, std::string> m_byte_to_char;
    std::unordered_map<std::string, uint8_t> m_char_to_byte;
    
    // Pre-tokenization regex (simplified)
    std::vector<std::string> PreTokenize(const std::string& text) const;
    
    // BPE core algorithm
    std::vector<std::string> BPE(const std::string& token) const;
    
    // Byte encoding/decoding
    std::string ByteEncode(const std::string& text) const;
    std::string ByteDecode(const std::string& text) const;
    
    // JSON parsing helpers
    bool ParseTokenizerJson(const std::string& json);
    bool ParseVocab(const std::string& json, size_t& pos);
    bool ParseMerges(const std::string& json, size_t& pos);
    bool ParseSpecialTokens(const std::string& json, size_t& pos);
    
    // JSON utilities
    std::string ParseString(const std::string& json, size_t& pos) const;
    std::vector<std::string> ParseStringArray(const std::string& json, size_t& pos) const;
    void SkipWhitespace(const std::string& json, size_t& pos) const;
};

// ============================================================================
// Convenience Functions
// ============================================================================
// Quick encode/decode without managing tokenizer instance
std::vector<uint32_t> QuickEncode(const std::string& text, const std::string& tokenizer_path);
std::string QuickDecode(const std::vector<uint32_t>& tokens, const std::string& tokenizer_path);

} // namespace Runtime
} // namespace RawrXD
