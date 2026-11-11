// ============================================================================
// C7: Decode Output Implementation
// ============================================================================

#include "decode_output.hpp"
#include <sstream>
#include <cctype>
#include <algorithm>

namespace seg {

// ============================================================================
// TokenDecoder Implementation
// ============================================================================

TokenDecoder::TokenDecoder() = default;
TokenDecoder::~TokenDecoder() = default;

bool TokenDecoder::Initialize(const std::unordered_map<uint32_t, std::string>& vocab) {
    vocab_ = vocab;
    reverse_vocab_.clear();
    
    for (const auto& [id, text] : vocab_) {
        reverse_vocab_[text] = id;
    }
    
    return !vocab_.empty();
}

bool TokenDecoder::Initialize(const std::vector<std::string>& vocab_list) {
    vocab_.clear();
    for (size_t i = 0; i < vocab_list.size(); ++i) {
        vocab_[static_cast<uint32_t>(i)] = vocab_list[i];
    }
    
    reverse_vocab_.clear();
    for (const auto& [id, text] : vocab_) {
        reverse_vocab_[text] = id;
    }
    
    return !vocab_.empty();
}

std::string TokenDecoder::Decode(const std::vector<uint32_t>& tokens,
                                  const DecodeConfig& config) {
    std::string result;
    bool first_token = true;
    
    for (uint32_t token : tokens) {
        // Skip special tokens if configured
        if (config.strip_special_tokens && IsSpecialToken(token)) {
            if (token == 2 && config.preserve_eos) {
                // EOS token - stop decoding
                break;
            }
            continue;
        }
        
        // Get token text
        std::string token_text = DecodeToken(token);
        
        // Handle unknown tokens
        if (token_text.empty()) {
            if (config.skip_unknown_tokens) {
                continue;
            }
            token_text = std::string(1, config.unknown_token_char);
        }
        
        // Handle byte fallback
        if (config.handle_byte_fallback && IsByteFallbackToken(token)) {
            token_text = HandleByteFallback(token);
        }
        
        // Process BPE markers
        if (config.merge_continuation_spaces) {
            token_text = ProcessBPE(token_text, config);
        }
        
        // Trim leading whitespace on first token
        if (first_token && config.trim_leading_whitespace) {
            size_t start = token_text.find_first_not_of(" \t\n\r");
            if (start != std::string::npos) {
                token_text = token_text.substr(start);
            } else {
                token_text.clear();
            }
        }
        
        result += token_text;
        first_token = false;
    }
    
    // Normalize whitespace if configured
    if (config.normalize_whitespace) {
        result = NormalizeWhitespace(result);
    }
    
    return result;
}

std::string TokenDecoder::DecodeToken(uint32_t token_id) const {
    auto it = vocab_.find(token_id);
    if (it != vocab_.end()) {
        return it->second;
    }
    return "";
}

bool TokenDecoder::IsSpecialToken(uint32_t token_id) const {
    auto it = vocab_.find(token_id);
    if (it == vocab_.end()) return false;
    return IsSpecialTokenString(it->second);
}

bool TokenDecoder::IsByteFallbackToken(uint32_t token_id) const {
    // Byte fallback tokens are typically in range 3-258 for Llama models
    // Token 0 = pad, 1 = bos, 2 = eos
    // Tokens 3-258 = byte fallback (256 bytes + 2 special)
    return (token_id >= 3 && token_id <= 258);
}

bool TokenDecoder::HasToken(uint32_t token_id) const {
    return vocab_.find(token_id) != vocab_.end();
}

bool TokenDecoder::IsSpecialTokenString(const std::string& text) const {
    // Check for special token markers like <|...|>
    if (text.size() >= 4 && text[0] == '<' && text[1] == '|' && 
        text[text.size()-2] == '|' && text[text.size()-1] == '>') {
        return true;
    }
    
    // Check for other special markers
    if (text == "<s>" || text == "</s>" || text == "<pad>") {
        return true;
    }
    
    return false;
}

std::string TokenDecoder::ProcessBPE(const std::string& text, const DecodeConfig& config) {
    std::string result = text;
    
    // Handle "Ġ" (U+0120) space marker used in some BPE tokenizers
    size_t pos = 0;
    while ((pos = result.find("Ġ", pos)) != std::string::npos) {
        result.replace(pos, 2, " ");  // Ġ is 2 bytes in UTF-8
        pos += 1;
    }
    
    // Handle other BPE continuation markers
    // "##" for WordPiece, "Ċ" for newline, etc.
    pos = 0;
    while ((pos = result.find("##", pos)) != std::string::npos) {
        result.erase(pos, 2);
    }
    
    return result;
}

std::string TokenDecoder::HandleByteFallback(uint32_t token_id) const {
    // Byte fallback: token_id 3 = byte 0, token_id 4 = byte 1, etc.
    if (token_id >= 3 && token_id <= 258) {
        char byte_val = static_cast<char>(token_id - 3);
        return std::string(1, byte_val);
    }
    return "";
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::string DecodeTokens(const std::vector<uint32_t>& tokens,
                         const std::unordered_map<uint32_t, std::string>& vocab) {
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    return decoder.Decode(tokens);
}

std::string DecodeTokens(const std::vector<uint32_t>& tokens,
                         const std::unordered_map<uint32_t, std::string>& vocab,
                         const DecodeConfig& config) {
    TokenDecoder decoder;
    decoder.Initialize(vocab);
    return decoder.Decode(tokens, config);
}

std::string StripSpecialTokens(const std::string& text) {
    std::string result = text;
    
    // Remove <|...|> patterns
    size_t start = 0;
    while ((start = result.find("<|", start)) != std::string::npos) {
        size_t end = result.find("|>", start);
        if (end != std::string::npos) {
            result.erase(start, end - start + 2);
        } else {
            break;
        }
    }
    
    // Remove other special markers
    std::vector<std::string> markers = {"<s>", "</s>", "<pad>", "<unk>"};
    for (const auto& marker : markers) {
        size_t pos = 0;
        while ((pos = result.find(marker, pos)) != std::string::npos) {
            result.erase(pos, marker.length());
        }
    }
    
    return result;
}

std::string NormalizeWhitespace(const std::string& text) {
    std::string result;
    result.reserve(text.size());
    
    bool last_was_space = false;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!last_was_space) {
                result += ' ';
                last_was_space = true;
            }
        } else {
            result += c;
            last_was_space = false;
        }
    }
    
    // Trim leading/trailing whitespace
    size_t start = result.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    
    size_t end = result.find_last_not_of(" \t\n\r");
    return result.substr(start, end - start + 1);
}

// ============================================================================
// Common Vocabulary Helpers
// ============================================================================

std::unordered_map<uint32_t, std::string> CreateLlama3Vocab() {
    std::unordered_map<uint32_t, std::string> vocab;
    
    // Special tokens
    vocab[0] = "<pad>";
    vocab[1] = "<|begin_of_text|>";
    vocab[2] = "<|end_of_text|>";
    
    // Byte fallback tokens (3-258)
    for (int i = 0; i < 256; ++i) {
        vocab[3 + i] = std::string(1, static_cast<char>(i));
    }
    
    // Common tokens (simplified)
    vocab[259] = "the";
    vocab[260] = "Ġthe";  // " the" with space marker
    vocab[261] = "a";
    vocab[262] = "Ġa";
    vocab[263] = "is";
    vocab[264] = "Ġis";
    vocab[265] = "and";
    vocab[266] = "Ġand";
    vocab[267] = "of";
    vocab[268] = "Ġof";
    vocab[269] = "to";
    vocab[270] = "Ġto";
    vocab[271] = "in";
    vocab[272] = "Ġin";
    vocab[273] = "for";
    vocab[274] = "Ġfor";
    vocab[275] = "that";
    vocab[276] = "Ġthat";
    vocab[277] = "it";
    vocab[278] = "Ġit";
    vocab[279] = "with";
    vocab[280] = "Ġwith";
    vocab[281] = "as";
    vocab[282] = "Ġas";
    vocab[283] = "on";
    vocab[284] = "Ġon";
    vocab[285] = "was";
    vocab[286] = "Ġwas";
    vocab[287] = "at";
    vocab[288] = "Ġat";
    vocab[289] = "by";
    vocab[290] = "Ġby";
    vocab[291] = "from";
    vocab[292] = "Ġfrom";
    vocab[293] = "be";
    vocab[294] = "Ġbe";
    vocab[295] = "this";
    vocab[296] = "Ġthis";
    vocab[297] = "have";
    vocab[298] = "Ġhave";
    vocab[299] = "are";
    vocab[300] = "Ġare";
    
    // Punctuation
    vocab[301] = ".";
    vocab[302] = "Ġ.";
    vocab[303] = ",";
    vocab[304] = "Ġ,";
    vocab[305] = "!";
    vocab[306] = "Ġ!";
    vocab[307] = "?";
    vocab[308] = "Ġ?";
    vocab[309] = ";";
    vocab[310] = "Ġ;";
    vocab[311] = ":";
    vocab[312] = "Ġ:";
    vocab[313] = "'";
    vocab[314] = "Ġ'";
    vocab[315] = "\"";
    vocab[316] = "Ġ\"";
    
    // Newline and space
    vocab[317] = "\n";
    vocab[318] = "Ġ\n";
    vocab[319] = " ";
    
    // Common words
    vocab[320] = "Hello";
    vocab[321] = "ĠHello";
    vocab[322] = "world";
    vocab[323] = "Ġworld";
    vocab[324] = "how";
    vocab[325] = "Ġhow";
    vocab[326] = "are";
    vocab[327] = "Ġare";
    vocab[328] = "you";
    vocab[329] = "Ġyou";
    vocab[330] = "today";
    vocab[331] = "Ġtoday";
    vocab[332] = "I";
    vocab[333] = "ĠI";
    vocab[334] = "am";
    vocab[335] = "Ġam";
    vocab[336] = "doing";
    vocab[337] = "Ġdoing";
    vocab[338] = "well";
    vocab[339] = "Ġwell";
    vocab[340] = "thank";
    vocab[341] = "Ġthank";
    vocab[342] = "you";
    vocab[343] = "Ġyou";
    
    return vocab;
}

} // namespace seg
