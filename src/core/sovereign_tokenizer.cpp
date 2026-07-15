// =============================================================================
// sovereign_tokenizer.cpp
// BPE Tokenizer Implementation for Llama 3.2
// =============================================================================

#include "sovereign_tokenizer.h"
#include "../streaming_gguf_loader.h"
#include <cstdio>
#include <cctype>
#include <algorithm>
#include <sstream>
#include <regex>

namespace Sovereign {

// =============================================================================
// Constructor / Destructor
// =============================================================================

SovereignTokenizer::SovereignTokenizer() = default;
SovereignTokenizer::~SovereignTokenizer() = default;

// =============================================================================
// Load from GGUF File
// =============================================================================

bool SovereignTokenizer::LoadFromGGUF(const std::string& gguf_path) {
    printf("[Tokenizer] Loading from GGUF: %s\n", gguf_path.c_str());
    
    RawrXD::StreamingGGUFLoader loader;
    if (!loader.Open(gguf_path)) {
        fprintf(stderr, "[Tokenizer] Failed to open GGUF file\n");
        return false;
    }
    
    if (!loader.ParseHeader()) {
        fprintf(stderr, "[Tokenizer] Failed to parse GGUF header\n");
        return false;
    }
    
    // Get vocabulary from loader
    const auto& vocab = loader.GetVocabulary();
    if (vocab.empty()) {
        fprintf(stderr, "[Tokenizer] No vocabulary found in GGUF\n");
        return false;
    }
    
    printf("[Tokenizer] Found %zu tokens in vocabulary\n", vocab.size());
    
    // Build mappings
    id_to_token_.clear();
    token_to_id_.clear();
    token_scores_.clear();
    
    id_to_token_.reserve(vocab.size());
    token_scores_.reserve(vocab.size());
    
    for (size_t i = 0; i < vocab.size(); i++) {
        const std::string& token = vocab[i];
        id_to_token_.push_back(token);
        token_to_id_[token] = static_cast<uint32_t>(i);
        token_scores_.push_back(0.0f); // Scores not always available
    }
    
    // Set config based on vocab size
    config_.vocab_size = static_cast<uint32_t>(vocab.size());
    
    // Try to detect special tokens
    // Common patterns: "<s>", "</s>", "<|endoftext|>", etc.
    for (size_t i = 0; i < id_to_token_.size() && i < 10; i++) {
        const std::string& token = id_to_token_[i];
        if (token.find("<s>") != std::string::npos || token == "<bos>") {
            config_.bos_token_id = static_cast<uint32_t>(i);
            printf("[Tokenizer] Detected BOS token: %zu = '%s'\n", i, token.c_str());
        }
        if (token.find("</s>") != std::string::npos || token == "<eos>") {
            config_.eos_token_id = static_cast<uint32_t>(i);
            printf("[Tokenizer] Detected EOS token: %zu = '%s'\n", i, token.c_str());
        }
        if (token.find("pad") != std::string::npos || token == "<pad>") {
            config_.pad_token_id = static_cast<uint32_t>(i);
        }
    }
    
    printf("[Tokenizer] Loaded %zu tokens\n", id_to_token_.size());
    return true;
}

// =============================================================================
// Load from Pre-extracted Data
// =============================================================================

bool SovereignTokenizer::LoadVocabulary(
    const std::vector<std::string>& tokens,
    const std::vector<float>& scores,
    const TokenizerConfig& config
) {
    if (tokens.empty()) {
        return false;
    }
    
    config_ = config;
    id_to_token_ = tokens;
    token_scores_ = scores;
    
    token_to_id_.clear();
    for (size_t i = 0; i < tokens.size(); i++) {
        token_to_id_[tokens[i]] = static_cast<uint32_t>(i);
    }
    
    printf("[Tokenizer] Loaded %zu tokens from pre-extracted data\n", tokens.size());
    return true;
}

// =============================================================================
// Encode: Text -> Token IDs
// =============================================================================

std::vector<uint32_t> SovereignTokenizer::Encode(const std::string& text) const {
    std::vector<uint32_t> result;
    
    if (!IsLoaded()) {
        fprintf(stderr, "[Tokenizer] Error: Not loaded\n");
        return result;
    }
    
    // Add BOS token if configured
    if (config_.add_bos) {
        result.push_back(config_.bos_token_id);
    }
    
    // Pre-tokenize: split into words/subwords
    auto words = PreTokenize(text);
    
    // Apply BPE to each word
    for (const auto& word : words) {
        // Try direct lookup first
        auto it = token_to_id_.find(word);
        if (it != token_to_id_.end()) {
            result.push_back(it->second);
            continue;
        }
        
        // Apply BPE
        std::string bpe_result = ApplyBPE(word);
        
        // Split BPE result and convert to IDs
        std::istringstream iss(bpe_result);
        std::string token;
        while (iss >> token) {
            auto token_it = token_to_id_.find(token);
            if (token_it != token_to_id_.end()) {
                result.push_back(token_it->second);
            } else {
                // Try byte fallback
                auto byte_ids = ByteFallbackEncode(token);
                result.insert(result.end(), byte_ids.begin(), byte_ids.end());
            }
        }
    }
    
    // Add EOS token if configured
    if (config_.add_eos) {
        result.push_back(config_.eos_token_id);
    }
    
    return result;
}

// =============================================================================
// Pre-tokenization
// =============================================================================

std::vector<std::string> SovereignTokenizer::PreTokenize(const std::string& text) const {
    std::vector<std::string> result;
    
    // Simple pre-tokenization: split on whitespace and punctuation
    // In production, this would be more sophisticated
    std::regex word_regex(R"([\s\p{P}]+)");
    std::sregex_token_iterator iter(text.begin(), text.end(), word_regex, -1);
    std::sregex_token_iterator end;
    
    for (; iter != end; ++iter) {
        std::string word = *iter;
        if (!word.empty()) {
            result.push_back(word);
        }
    }
    
    // If regex didn't find anything, treat whole text as one token
    if (result.empty() && !text.empty()) {
        result.push_back(text);
    }
    
    return result;
}

// =============================================================================
// Apply BPE
// =============================================================================

std::string SovereignTokenizer::ApplyBPE(const std::string& word) const {
    // Simple BPE implementation
    // Start with character-level tokens
    std::vector<std::string> tokens;
    for (char c : word) {
        tokens.push_back(std::string(1, c));
    }
    
    if (tokens.empty()) {
        return word;
    }
    
    // Iteratively merge most frequent pairs
    while (tokens.size() > 1) {
        auto pairs = GetBytePairs(tokens);
        if (pairs.empty()) break;
        
        // Find the best merge (lowest rank / highest priority)
        bool merged = false;
        for (const auto& pair : pairs) {
            std::string merged_token = pair.first + pair.second;
            auto it = token_to_id_.find(merged_token);
            if (it != token_to_id_.end()) {
                // Found a valid merge
                std::vector<std::string> new_tokens;
                for (size_t i = 0; i < tokens.size(); i++) {
                    if (i < tokens.size() - 1 && 
                        tokens[i] == pair.first && 
                        tokens[i + 1] == pair.second) {
                        new_tokens.push_back(merged_token);
                        i++; // Skip next token
                    } else {
                        new_tokens.push_back(tokens[i]);
                    }
                }
                tokens = std::move(new_tokens);
                merged = true;
                break;
            }
        }
        
        if (!merged) break; // No more merges possible
    }
    
    // Join tokens with space
    std::string result;
    for (size_t i = 0; i < tokens.size(); i++) {
        if (i > 0) result += " ";
        result += tokens[i];
    }
    return result;
}

// =============================================================================
// Get Byte Pairs
// =============================================================================

std::vector<std::pair<std::string, std::string>> SovereignTokenizer::GetBytePairs(
    const std::vector<std::string>& tokens
) const {
    std::vector<std::pair<std::string, std::string>> pairs;
    for (size_t i = 0; i + 1 < tokens.size(); i++) {
        pairs.emplace_back(tokens[i], tokens[i + 1]);
    }
    return pairs;
}

// =============================================================================
// Byte Fallback Encode
// =============================================================================

std::vector<uint32_t> SovereignTokenizer::ByteFallbackEncode(const std::string& text) const {
    std::vector<uint32_t> result;
    
    // Convert each byte to a token
    for (uint8_t byte : text) {
        std::string byte_token = "<0x" + ByteToString(byte) + ">";
        auto it = token_to_id_.find(byte_token);
        if (it != token_to_id_.end()) {
            result.push_back(it->second);
        } else {
            result.push_back(config_.unk_token_id);
        }
    }
    
    return result;
}

// =============================================================================
// Decode: Token IDs -> Text
// =============================================================================

std::string SovereignTokenizer::Decode(const std::vector<uint32_t>& ids) const {
    std::string result;
    
    if (!IsLoaded()) {
        return result;
    }
    
    for (uint32_t id : ids) {
        if (id >= id_to_token_.size()) {
            continue; // Skip invalid IDs
        }
        
        // Skip special tokens
        if (id == config_.bos_token_id || id == config_.eos_token_id || 
            id == config_.pad_token_id) {
            continue;
        }
        
        const std::string& token = id_to_token_[id];
        
        // Handle byte tokens like "<0x20>"
        if (token.size() >= 5 && token[0] == '<' && token[1] == '0' && token[2] == 'x') {
            // Extract hex value
            std::string hex_str = token.substr(3, token.size() - 4);
            try {
                int byte_val = std::stoi(hex_str, nullptr, 16);
                result += static_cast<char>(byte_val);
            } catch (...) {
                result += token;
            }
        } else {
            result += token;
        }
    }
    
    return result;
}

// =============================================================================
// Decode Single Token
// =============================================================================

std::string SovereignTokenizer::DecodeToken(uint32_t token_id) const {
    if (token_id >= id_to_token_.size()) {
        return "<INVALID>";
    }
    return id_to_token_[token_id];
}

// =============================================================================
// Get Token ID
// =============================================================================

uint32_t SovereignTokenizer::GetTokenId(const std::string& token) const {
    auto it = token_to_id_.find(token);
    if (it != token_to_id_.end()) {
        return it->second;
    }
    return config_.unk_token_id;
}

// =============================================================================
// Is Special Token
// =============================================================================

bool SovereignTokenizer::IsSpecialToken(const std::string& token) const {
    return token.find('<') != std::string::npos && token.find('>') != std::string::npos;
}

// =============================================================================
// Print Vocab Info
// =============================================================================

void SovereignTokenizer::PrintVocabInfo() const {
    printf("\n=== Tokenizer Vocabulary ===\n");
    printf("Vocab size: %zu\n", id_to_token_.size());
    printf("BOS token: %u = '%s'\n", config_.bos_token_id, 
           DecodeToken(config_.bos_token_id).c_str());
    printf("EOS token: %u = '%s'\n", config_.eos_token_id,
           DecodeToken(config_.eos_token_id).c_str());
    printf("PAD token: %u = '%s'\n", config_.pad_token_id,
           DecodeToken(config_.pad_token_id).c_str());
    printf("UNK token: %u = '%s'\n", config_.unk_token_id,
           DecodeToken(config_.unk_token_id).c_str());
    printf("\nFirst 10 tokens:\n");
    for (size_t i = 0; i < std::min(size_t(10), id_to_token_.size()); i++) {
        printf("  %zu: '%s'\n", i, id_to_token_[i].c_str());
    }
    printf("===========================\n\n");
}

// =============================================================================
// Utility Functions
// =============================================================================

std::vector<uint8_t> UTF8ToBytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::string ByteToString(uint8_t byte) {
    const char* hex = "0123456789ABCDEF";
    std::string result;
    result += hex[byte >> 4];
    result += hex[byte & 0x0F];
    return result;
}

std::string NormalizeText(const std::string& text) {
    std::string result = text;
    // Simple normalization: lowercase
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

} // namespace Sovereign
