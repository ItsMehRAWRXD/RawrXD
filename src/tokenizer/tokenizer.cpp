// ============================================================================
// RawrXD Tokenizer Implementation
// ============================================================================

#include "tokenizer.hpp"
#include "../model/ModelLoader.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace rawrxd {
namespace tokenizer {

// ============================================================================
// Byte Pair Encoding Implementation
// ============================================================================

class BPEEncoder {
public:
    explicit BPEEncoder(const Vocabulary& vocab) : vocab_(vocab) {}
    
    std::vector<TokenId> Encode(const std::vector<Token>& pieces) {
        std::vector<TokenId> result;
        
        for (const auto& piece : pieces) {
            auto tokens = EncodePiece(piece);
            result.insert(result.end(), tokens.begin(), tokens.end());
        }
        
        return result;
    }
    
private:
    const Vocabulary& vocab_;
    
    std::vector<TokenId> EncodePiece(const Token& piece) {
        // Check if piece is already in vocab
        auto it = vocab_.token_to_id.find(piece);
        if (it != vocab_.token_to_id.end()) {
            return {it->second};
        }
        
        // Start with character-level tokens
        std::vector<Token> word;
        for (size_t i = 0; i < piece.size(); ++i) {
            word.push_back(piece.substr(i, 1));
        }
        
        // Apply BPE merges
        while (word.size() >= 2) {
            // Find the best merge (lowest rank in merges list)
            int best_rank = -1;
            size_t best_idx = 0;
            
            for (size_t i = 0; i < word.size() - 1; ++i) {
                Token pair = word[i] + word[i + 1];
                int rank = GetMergeRank(word[i], word[i + 1]);
                if (rank != -1 && (best_rank == -1 || rank < best_rank)) {
                    best_rank = rank;
                    best_idx = i;
                }
            }
            
            if (best_rank == -1) break; // No more merges possible
            
            // Apply the merge
            word[best_idx] = word[best_idx] + word[best_idx + 1];
            word.erase(word.begin() + best_idx + 1);
        }
        
        // Convert to token IDs
        std::vector<TokenId> result;
        for (const auto& token : word) {
            auto it = vocab_.token_to_id.find(token);
            if (it != vocab_.token_to_id.end()) {
                result.push_back(it->second);
            } else {
                // Byte fallback
                for (uint8_t b : token) {
                    result.push_back(ByteToToken(b));
                }
            }
        }
        
        return result;
    }
    
    int GetMergeRank(const Token& left, const Token& right) {
        for (size_t i = 0; i < vocab_.merges.size(); ++i) {
            if (vocab_.merges[i].first == left && vocab_.merges[i].second == right) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }
    
    TokenId ByteToToken(uint8_t byte) {
        // Map bytes to special tokens (typically 3-258 in LLaMA vocab)
        // This is a simplified version - real implementation would use vocab
        return static_cast<TokenId>(3 + byte);
    }
};

// ============================================================================
// Tokenizer Implementation
// ============================================================================

Tokenizer::Tokenizer() = default;
Tokenizer::~Tokenizer() = default;

bool Tokenizer::LoadFromGGUF(const std::string& gguf_path) {
    // Extract vocabulary and merges from GGUF using ModelLoader
    std::vector<std::string> vocab_tokens;
    std::vector<std::pair<std::string, std::string>> merges;
    
    if (!model::ExtractVocabAndMerges(gguf_path, vocab_tokens, merges)) {
        last_error_ = "Failed to extract vocabulary from GGUF";
        return false;
    }
    
    // Build vocabulary structure
    vocab_.unk_id = 0;
    vocab_.bos_id = 1;
    vocab_.eos_id = 2;
    vocab_.pad_id = 3;
    
    // Add tokens to vocab (limit to prevent memory issues)
    size_t max_tokens = std::min(vocab_tokens.size(), size_t(32000));
    for (size_t i = 0; i < max_tokens; ++i) {
        TokenId id = static_cast<TokenId>(i);
        vocab_.id_to_token[id] = vocab_tokens[i];
        vocab_.token_to_id[vocab_tokens[i]] = id;
    }
    
    // Add merge rules
    vocab_.merges = std::move(merges);
    
    // Compute vocab hash
    vocab_.vocab_hash = model::ComputeVocabHash(vocab_tokens);
    
    loaded_ = true;
    return true;
}

bool Tokenizer::LoadFromFile(const std::string& vocab_path) {
    std::ifstream file(vocab_path);
    if (!file.is_open()) {
        last_error_ = "Failed to open vocab file: " + vocab_path;
        return false;
    }
    
    // Parse vocab file format (JSON or TSV)
    // Simplified implementation
    std::string line;
    TokenId id = 0;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        vocab_.id_to_token[id] = line;
        vocab_.token_to_id[line] = id;
        ++id;
    }
    
    vocab_.vocab_hash = ComputeVocabHash(vocab_);
    loaded_ = true;
    return true;
}

std::vector<TokenId> Tokenizer::Encode(const std::string& text) {
    if (!loaded_) {
        return {};
    }
    
    // Check cache first
    if (cache_enabled_) {
        auto it = cache_.find(text);
        if (it != cache_.end()) {
            it->second.access_count++;
            return it->second.tokens;
        }
    }
    
    // Normalize text
    std::string normalized = Normalize(text);
    
    // Pre-tokenize
    std::vector<Token> pieces = PreTokenize(normalized);
    
    // BPE encode
    BPEEncoder encoder(vocab_);
    std::vector<TokenId> tokens = encoder.Encode(pieces);
    
    // Add to cache
    if (cache_enabled_) {
        AddToCache(text, tokens);
    }
    
    return tokens;
}

std::string Tokenizer::Decode(const std::vector<TokenId>& tokens) {
    if (!loaded_) {
        return "";
    }
    
    std::string result;
    for (TokenId id : tokens) {
        auto it = vocab_.id_to_token.find(id);
        if (it != vocab_.id_to_token.end()) {
            result += it->second;
        } else {
            result += "<unk>";
        }
    }
    
    return result;
}

std::vector<TokenId> Tokenizer::EncodeWithSpecial(const std::string& text, 
                                                    bool add_bos, 
                                                    bool add_eos) {
    std::vector<TokenId> tokens = Encode(text);
    
    if (add_bos) {
        tokens.insert(tokens.begin(), vocab_.bos_id);
    }
    if (add_eos) {
        tokens.push_back(vocab_.eos_id);
    }
    
    return tokens;
}

std::string Tokenizer::Normalize(const std::string& text) {
    if (norm_mode_ == NormalizationMode::NONE) {
        return text;
    }
    
    // Simplified NFKC normalization
    // Real implementation would use ICU or similar
    std::string result = text;
    
    // Basic whitespace normalization
    if (norm_mode_ == NormalizationMode::NFKC || 
        norm_mode_ == NormalizationMode::NFKC_STRICT) {
        // Replace multiple spaces with single space
        bool prev_space = false;
        std::string cleaned;
        for (char c : result) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                if (!prev_space) {
                    cleaned += ' ';
                    prev_space = true;
                }
            } else {
                cleaned += c;
                prev_space = false;
            }
        }
        result = cleaned;
        
        // Trim leading/trailing whitespace
        size_t start = result.find_first_not_of(' ');
        size_t end = result.find_last_not_of(' ');
        if (start != std::string::npos) {
            result = result.substr(start, end - start + 1);
        }
    }
    
    return result;
}

std::vector<Token> Tokenizer::PreTokenize(const std::string& text) {
    std::vector<Token> pieces;
    
    // Simple word-level pretokenization
    // Real implementation would use regex patterns
    size_t start = 0;
    size_t end = 0;
    
    while (end < text.size()) {
        // Find word boundary (space or punctuation)
        while (end < text.size() && 
               text[end] != ' ' && 
               !ispunct(static_cast<unsigned char>(text[end]))) {
            ++end;
        }
        
        if (end > start) {
            pieces.push_back(text.substr(start, end - start));
        }
        
        // Handle punctuation
        if (end < text.size() && ispunct(static_cast<unsigned char>(text[end]))) {
            pieces.push_back(text.substr(end, 1));
            ++end;
        }
        
        // Skip whitespace
        while (end < text.size() && text[end] == ' ') {
            ++end;
        }
        
        start = end;
    }
    
    return pieces;
}

void Tokenizer::EnableCache(size_t max_size) {
    cache_enabled_ = true;
    cache_max_size_ = max_size;
}

void Tokenizer::DisableCache() {
    cache_enabled_ = false;
    ClearCache();
}

void Tokenizer::ClearCache() {
    cache_.clear();
}

void Tokenizer::AddToCache(const std::string& text, const std::vector<TokenId>& tokens) {
    if (cache_.size() >= cache_max_size_) {
        // Simple LRU eviction - remove least accessed
        auto min_it = cache_.begin();
        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (it->second.access_count < min_it->second.access_count) {
                min_it = it;
            }
        }
        cache_.erase(min_it);
    }
    
    cache_[text] = {tokens, 1};
}

// ============================================================================
// Utility Functions
// ============================================================================

uint64_t ComputeVocabHash(const Vocabulary& vocab) {
    // Simple hash computation
    // Real implementation would use SHA256
    uint64_t hash = 0x9e3779b97f4a7c15ULL; // Golden ratio
    
    for (const auto& [id, token] : vocab.id_to_token) {
        hash ^= std::hash<std::string>{}(token) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
        hash ^= id + 0x9e3779b9 + (hash << 6) + (hash >> 2);
    }
    
    return hash;
}

bool ValidateTokens(const std::vector<TokenId>& tokens, const Vocabulary& vocab) {
    for (TokenId id : tokens) {
        if (vocab.id_to_token.find(id) == vocab.id_to_token.end()) {
            return false;
        }
    }
    return true;
}

SpecialTokens GetSpecialTokens(const Tokenizer& tokenizer) {
    const auto& vocab = tokenizer.GetVocabulary();
    return {
        vocab.unk_id,
        vocab.bos_id,
        vocab.eos_id,
        vocab.pad_id
    };
}

// ============================================================================
// Global Tokenizer Instance
// ============================================================================

static Tokenizer* g_global_tokenizer = nullptr;

Tokenizer* GetGlobalTokenizer() {
    return g_global_tokenizer;
}

void SetGlobalTokenizer(Tokenizer* tokenizer) {
    g_global_tokenizer = tokenizer;
}

bool InitGlobalTokenizer(const std::string& gguf_path) {
    if (g_global_tokenizer) {
        delete g_global_tokenizer;
    }
    g_global_tokenizer = new Tokenizer();
    return g_global_tokenizer->LoadFromGGUF(gguf_path);
}

void CleanupGlobalTokenizer() {
    if (g_global_tokenizer) {
        delete g_global_tokenizer;
        g_global_tokenizer = nullptr;
    }
}

} // namespace tokenizer
} // namespace rawrxd
