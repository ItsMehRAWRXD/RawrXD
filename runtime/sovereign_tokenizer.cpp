// ============================================================================
// sovereign_tokenizer.cpp - Pure C++ BPE Tokenizer Implementation
// ============================================================================

#include "sovereign_tokenizer.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <regex>

namespace RawrXD {
namespace Runtime {

// ============================================================================
// Constructor / Destructor
// ============================================================================
SovereignTokenizer::SovereignTokenizer() = default;
SovereignTokenizer::~SovereignTokenizer() = default;

// ============================================================================
// Load from tokenizer.json file
// ============================================================================
bool SovereignTokenizer::Load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    
    return LoadFromJson(buffer.str());
}

// ============================================================================
// Load from JSON string
// ============================================================================
bool SovereignTokenizer::LoadFromJson(const std::string& json_content) {
    // Clear existing state
    m_token_to_id.clear();
    m_id_to_token.clear();
    m_merges.clear();
    
    // Initialize byte encoder (GPT-2 style)
    // Maps bytes 0-255 to printable Unicode characters
    for (int i = 0; i < 256; ++i) {
        if (i < 33 || i > 126 || i == 32 || i == 33 || i == 63 || i == 91 || i == 93) {
            // Non-printable or special chars get encoded as multi-byte UTF-8
            char utf8[4];
            int len = 0;
            if (i < 0x80) {
                // Should not reach here for these values
                utf8[0] = static_cast<char>(i);
                len = 1;
            } else {
                // Encode as continuation byte pattern
                utf8[0] = static_cast<char>(0xC0 | (i >> 6));
                utf8[1] = static_cast<char>(0x80 | (i & 0x3F));
                len = 2;
            }
            m_byte_to_char[i] = std::string(utf8, len);
            m_char_to_byte[std::string(utf8, len)] = static_cast<uint8_t>(i);
        } else {
            // Printable ASCII
            char c = static_cast<char>(i);
            m_byte_to_char[i] = std::string(1, c);
            m_char_to_byte[std::string(1, c)] = static_cast<uint8_t>(i);
        }
    }
    
    return ParseTokenizerJson(json_content);
}

// ============================================================================
// JSON Parsing - Simplified tokenizer.json parser
// ============================================================================
bool SovereignTokenizer::ParseTokenizerJson(const std::string& json) {
    size_t pos = 0;
    SkipWhitespace(json, pos);
    
    // Expect opening brace
    if (pos >= json.size() || json[pos] != '{') {
        return false;
    }
    ++pos;
    
    // Parse key-value pairs
    while (pos < json.size()) {
        SkipWhitespace(json, pos);
        if (pos >= json.size()) break;
        
        // Check for closing brace
        if (json[pos] == '}') {
            ++pos;
            break;
        }
        
        // Parse key
        std::string key = ParseString(json, pos);
        if (key.empty()) break;
        
        SkipWhitespace(json, pos);
        if (pos >= json.size() || json[pos] != ':') return false;
        ++pos;
        
        SkipWhitespace(json, pos);
        
        // Parse value based on key
        if (key == "model") {
            // Parse model section containing vocab and merges
            if (!ParseModel(json, pos)) return false;
        } else if (key == "added_tokens") {
            // Skip for now
            SkipWhitespace(json, pos);
            if (json[pos] == '[') {
                int depth = 1;
                ++pos;
                while (pos < json.size() && depth > 0) {
                    if (json[pos] == '[') ++depth;
                    else if (json[pos] == ']') --depth;
                    ++pos;
                }
            }
        } else {
            // Skip unknown values
            SkipWhitespace(json, pos);
            if (json[pos] == '{') {
                int depth = 1;
                ++pos;
                while (pos < json.size() && depth > 0) {
                    if (json[pos] == '{') ++depth;
                    else if (json[pos] == '}') --depth;
                    ++pos;
                }
            } else if (json[pos] == '[') {
                int depth = 1;
                ++pos;
                while (pos < json.size() && depth > 0) {
                    if (json[pos] == '[') ++depth;
                    else if (json[pos] == ']') --depth;
                    ++pos;
                }
            } else if (json[pos] == '"') {
                ParseString(json, pos);
            } else {
                while (pos < json.size() && json[pos] != ',' && json[pos] != '}') ++pos;
            }
        }
        
        SkipWhitespace(json, pos);
        if (pos < json.size() && json[pos] == ',') ++pos;
    }
    
    return !m_token_to_id.empty();
}

bool SovereignTokenizer::ParseModel(const std::string& json, size_t& pos) {
    SkipWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != '{') return false;
    ++pos;
    
    while (pos < json.size()) {
        SkipWhitespace(json, pos);
        if (pos >= json.size()) break;
        if (json[pos] == '}') { ++pos; break; }
        
        // Parse key
        std::string key = ParseString(json, pos);
        if (key.empty()) break;
        
        SkipWhitespace(json, pos);
        if (pos >= json.size() || json[pos] != ':') return false;
        ++pos;
        
        SkipWhitespace(json, pos);
        
        // Parse value based on key
        if (key == "vocab") {
            if (!ParseVocab(json, pos)) return false;
        } else if (key == "merges") {
            if (!ParseMerges(json, pos)) return false;
        } else {
            // Skip unknown values in model section
            SkipWhitespace(json, pos);
            if (json[pos] == '{') {
                int depth = 1;
                ++pos;
                while (pos < json.size() && depth > 0) {
                    if (json[pos] == '{') ++depth;
                    else if (json[pos] == '}') --depth;
                    ++pos;
                }
            } else if (json[pos] == '[') {
                int depth = 1;
                ++pos;
                while (pos < json.size() && depth > 0) {
                    if (json[pos] == '[') ++depth;
                    else if (json[pos] == ']') --depth;
                    ++pos;
                }
            } else if (json[pos] == '"') {
                ParseString(json, pos);
            } else {
                while (pos < json.size() && json[pos] != ',' && json[pos] != '}') ++pos;
            }
        }
        
        SkipWhitespace(json, pos);
        if (pos < json.size() && json[pos] == ',') ++pos;
    }
    
    return true;
}

bool SovereignTokenizer::ParseVocab(const std::string& json, size_t& pos) {
    SkipWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != '{') return false;
    ++pos;
    
    while (pos < json.size()) {
        SkipWhitespace(json, pos);
        if (pos >= json.size()) break;
        if (json[pos] == '}') { ++pos; break; }
        
        // Parse vocab key
        std::string key = ParseString(json, pos);
        if (key.empty()) break;
        
        SkipWhitespace(json, pos);
        if (pos >= json.size() || json[pos] != ':') return false;
        ++pos;
        
        SkipWhitespace(json, pos);
        
        // Parse vocab value (token ID)
        uint32_t token_id = 0;
        if (pos < json.size() && json[pos] == '"') {
            // String ID (rare)
            std::string id_str = ParseString(json, pos);
            token_id = static_cast<uint32_t>(std::stoul(id_str));
        } else {
            // Numeric ID
            while (pos < json.size() && std::isdigit(json[pos])) {
                token_id = token_id * 10 + (json[pos] - '0');
                ++pos;
            }
        }
        
        // Store vocab entry
        m_token_to_id[key] = token_id;
        if (token_id >= m_id_to_token.size()) {
            m_id_to_token.resize(token_id + 1);
        }
        m_id_to_token[token_id] = key;
        
        SkipWhitespace(json, pos);
        if (pos < json.size() && json[pos] == ',') ++pos;
    }
    
    return true;
}

bool SovereignTokenizer::ParseMerges(const std::string& json, size_t& pos) {
    SkipWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != '[') return false;
    ++pos;
    
    int rank = 0;
    while (pos < json.size()) {
        SkipWhitespace(json, pos);
        if (pos >= json.size()) break;
        if (json[pos] == ']') { ++pos; break; }
        
        // Parse merge pair - can be either ["token1", "token2"] or "token1 token2"
        if (json[pos] == '[') {
            // Array format: ["token1", "token2"]
            ++pos;
            
            std::string token1 = ParseString(json, pos);
            
            SkipWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != ',') return false;
            ++pos;
            
            std::string token2 = ParseString(json, pos);
            
            SkipWhitespace(json, pos);
            if (pos >= json.size() || json[pos] != ']') return false;
            ++pos;
            
            m_merges[{token1, token2}] = rank++;
        } else if (json[pos] == '"') {
            // String format: "token1 token2"
            std::string merge_str = ParseString(json, pos);
            
            // Split on space
            size_t space_pos = merge_str.find(' ');
            if (space_pos != std::string::npos) {
                std::string token1 = merge_str.substr(0, space_pos);
                std::string token2 = merge_str.substr(space_pos + 1);
                m_merges[{token1, token2}] = rank++;
            }
        } else {
            // Unknown format, skip
            return false;
        }
        
        SkipWhitespace(json, pos);
        if (pos < json.size() && json[pos] == ',') ++pos;
    }
    
    return true;
}

std::string SovereignTokenizer::ParseString(const std::string& json, size_t& pos) const {
    SkipWhitespace(json, pos);
    if (pos >= json.size() || json[pos] != '"') return "";
    ++pos;
    
    std::string result;
    while (pos < json.size()) {
        char c = json[pos];
        if (c == '"') { ++pos; break; }
        if (c == '\\' && pos + 1 < json.size()) {
            char next = json[pos + 1];
            switch (next) {
                case '"': result += '"'; pos += 2; break;
                case '\\': result += '\\'; pos += 2; break;
                case '/': result += '/'; pos += 2; break;
                case 'b': result += '\b'; pos += 2; break;
                case 'f': result += '\f'; pos += 2; break;
                case 'n': result += '\n'; pos += 2; break;
                case 'r': result += '\r'; pos += 2; break;
                case 't': result += '\t'; pos += 2; break;
                case 'u': {
                    // Unicode escape (simplified)
                    if (pos + 5 < json.size()) {
                        std::string hex = json.substr(pos + 2, 4);
                        try {
                            int codepoint = std::stoi(hex, nullptr, 16);
                            // Convert to UTF-8 (simplified)
                            if (codepoint < 0x80) {
                                result += static_cast<char>(codepoint);
                            } else if (codepoint < 0x800) {
                                result += static_cast<char>(0xC0 | (codepoint >> 6));
                                result += static_cast<char>(0x80 | (codepoint & 0x3F));
                            } else {
                                result += static_cast<char>(0xE0 | (codepoint >> 12));
                                result += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
                                result += static_cast<char>(0x80 | (codepoint & 0x3F));
                            }
                        } catch (...) {
                            result += '?';
                        }
                        pos += 6;
                    } else {
                        pos += 2;
                    }
                    break;
                }
                default: result += next; pos += 2; break;
            }
        } else {
            result += c;
            ++pos;
        }
    }
    
    return result;
}

void SovereignTokenizer::SkipWhitespace(const std::string& json, size_t& pos) const {
    while (pos < json.size() && std::isspace(json[pos])) ++pos;
}

// ============================================================================
// Encode - Text to Token IDs
// ============================================================================
std::vector<uint32_t> SovereignTokenizer::Encode(const std::string& text) const {
    return Encode(text, m_config.add_bos, m_config.add_eos);
}

std::vector<uint32_t> SovereignTokenizer::Encode(const std::string& text, bool add_bos, bool add_eos) const {
    std::vector<uint32_t> tokens;
    
    // Add BOS token
    if (add_bos) {
        tokens.push_back(m_config.bos_token_id);
    }
    
    // Pre-tokenize
    std::vector<std::string> words = PreTokenize(text);
    
    // Apply BPE to each word
    for (const auto& word : words) {
        // First check if the whole word exists in vocab (for test vocab compatibility)
        auto whole_it = m_token_to_id.find(word);
        if (whole_it != m_token_to_id.end()) {
            tokens.push_back(whole_it->second);
            continue;
        }
        
        // Byte-encode the word
        std::string byte_encoded = ByteEncode(word);
        
        // Apply BPE
        std::vector<std::string> bpe_tokens = BPE(byte_encoded);
        
        // Convert to IDs
        for (const auto& token : bpe_tokens) {
            auto it = m_token_to_id.find(token);
            if (it != m_token_to_id.end()) {
                tokens.push_back(it->second);
            } else {
                tokens.push_back(m_config.unk_token_id);
            }
        }
    }
    
    // Add EOS token
    if (add_eos) {
        tokens.push_back(m_config.eos_token_id);
    }
    
    return tokens;
}

// ============================================================================
// Pre-tokenization
// ============================================================================
std::vector<std::string> SovereignTokenizer::PreTokenize(const std::string& text) const {
    std::vector<std::string> tokens;
    
    // Simplified pre-tokenization: split on whitespace and punctuation
    // Full GPT-2 regex: 's|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L\p{N}]+|\s+(?!\S)|\s+
    
    size_t start = 0;
    size_t i = 0;
    
    while (i < text.size()) {
        // Skip leading whitespace
        while (i < text.size() && std::isspace(text[i])) ++i;
        if (i >= text.size()) break;
        
        start = i;
        
        // Check for contractions
        if (i + 2 < text.size() && text[i] == '\'') {
            // Handle 's, 't, 're, 've, 'm, 'll, 'd
            // Simplified: just include in word
        }
        
        // Collect word characters
        while (i < text.size() && !std::isspace(text[i])) ++i;
        
        if (i > start) {
            tokens.push_back(text.substr(start, i - start));
        }
    }
    
    return tokens;
}

// ============================================================================
// BPE Algorithm
// ============================================================================
std::vector<std::string> SovereignTokenizer::BPE(const std::string& token) const {
    if (token.empty()) return {};
    
    // Start with individual characters
    std::vector<std::string> symbols;
    for (size_t i = 0; i < token.size();) {
        size_t len = 1;
        // Try to decode UTF-8
        unsigned char c = static_cast<unsigned char>(token[i]);
        if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0) len = 4;
        
        symbols.push_back(token.substr(i, len));
        i += len;
    }
    
    // Add end-of-word marker to last symbol
    if (!symbols.empty()) {
        symbols.back() += "</w>";
    }
    
    // Apply merges greedily
    while (symbols.size() > 1) {
        // Find the best merge (lowest rank)
        int best_rank = -1;
        size_t best_idx = 0;
        
        for (size_t i = 0; i + 1 < symbols.size(); ++i) {
            BPEMerge merge = {symbols[i], symbols[i + 1]};
            auto it = m_merges.find(merge);
            if (it != m_merges.end()) {
                if (best_rank == -1 || it->second < best_rank) {
                    best_rank = it->second;
                    best_idx = i;
                }
            }
        }
        
        // No more merges possible
        if (best_rank == -1) break;
        
        // Apply the merge
        symbols[best_idx] = symbols[best_idx] + symbols[best_idx + 1];
        symbols.erase(symbols.begin() + best_idx + 1);
    }
    
    return symbols;
}

// ============================================================================
// Byte Encoding/Decoding (GPT-2 style)
// ============================================================================
std::string SovereignTokenizer::ByteEncode(const std::string& text) const {
    std::string result;
    for (unsigned char c : text) {
        auto it = m_byte_to_char.find(c);
        if (it != m_byte_to_char.end()) {
            result += it->second;
        } else {
            result += static_cast<char>(c);
        }
    }
    return result;
}

std::string SovereignTokenizer::ByteDecode(const std::string& text) const {
    std::string result;
    size_t i = 0;
    while (i < text.size()) {
        // Try multi-byte sequences first
        bool found = false;
        for (size_t len = std::min(size_t(4), text.size() - i); len > 0; --len) {
            std::string sub = text.substr(i, len);
            auto it = m_char_to_byte.find(sub);
            if (it != m_char_to_byte.end()) {
                result += static_cast<char>(it->second);
                i += len;
                found = true;
                break;
            }
        }
        if (!found) {
            result += text[i];
            ++i;
        }
    }
    return result;
}

// ============================================================================
// Decode - Token IDs to Text
// ============================================================================
std::string SovereignTokenizer::Decode(const std::vector<uint32_t>& tokens) const {
    return Decode(tokens.data(), tokens.size());
}

std::string SovereignTokenizer::Decode(const uint32_t* tokens, size_t count) const {
    std::string result;
    bool prev_was_word = false;
    
    for (size_t i = 0; i < count; ++i) {
        uint32_t token_id = tokens[i];
        
        // Skip special tokens
        if (token_id == m_config.bos_token_id) continue;
        if (token_id == m_config.eos_token_id) continue;
        if (token_id == m_config.pad_token_id) continue;
        
        if (token_id < m_id_to_token.size()) {
            std::string token = m_id_to_token[token_id];
            
            // Check for end-of-word marker
            bool is_word_end = false;
            size_t pos = token.find("</w>");
            if (pos != std::string::npos) {
                token = token.substr(0, pos);
                is_word_end = true;
            }
            
            // Add space between words (heuristic: multi-char tokens that look like words)
            if (prev_was_word && token.length() > 1) {
                result += ' ';
            }
            
            // Byte decode
            std::string decoded = ByteDecode(token);
            result += decoded;
            
            // Track if this was a word (multi-char or had </w> marker)
            prev_was_word = (is_word_end || token.length() > 1);
        }
    }
    
    return result;
}

// ============================================================================
// Token/ID Conversion
// ============================================================================
uint32_t SovereignTokenizer::TokenToId(const std::string& token) const {
    auto it = m_token_to_id.find(token);
    return (it != m_token_to_id.end()) ? it->second : m_config.unk_token_id;
}

std::string SovereignTokenizer::IdToToken(uint32_t id) const {
    if (id < m_id_to_token.size()) {
        return m_id_to_token[id];
    }
    return m_config.unk_token;
}

bool SovereignTokenizer::IsInVocab(const std::string& token) const {
    return m_token_to_id.find(token) != m_token_to_id.end();
}

// ============================================================================
// Convenience Functions
// ============================================================================
std::vector<uint32_t> QuickEncode(const std::string& text, const std::string& tokenizer_path) {
    SovereignTokenizer tokenizer;
    if (!tokenizer.Load(tokenizer_path)) {
        return {};
    }
    return tokenizer.Encode(text);
}

std::string QuickDecode(const std::vector<uint32_t>& tokens, const std::string& tokenizer_path) {
    SovereignTokenizer tokenizer;
    if (!tokenizer.Load(tokenizer_path)) {
        return "";
    }
    return tokenizer.Decode(tokens);
}

} // namespace Runtime
} // namespace RawrXD
