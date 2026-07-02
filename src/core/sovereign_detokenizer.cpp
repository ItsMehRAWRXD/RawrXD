// =============================================================================
// sovereign_detokenizer.cpp
// Token ID to text conversion implementation
// =============================================================================

#include "sovereign_detokenizer.h"
#include <algorithm>

namespace Sovereign {

Detokenizer::Detokenizer() {}

Detokenizer::~Detokenizer() {}

bool Detokenizer::Initialize(const std::vector<std::string>& vocab) {
    vocab_ = vocab;
    return !vocab_.empty();
}

std::string Detokenizer::Detokenize(uint32_t token_id) const {
    if (token_id >= vocab_.size()) {
        fprintf(stderr, "[DETOKEN] Token %u out of range (vocab_size=%zu)\n", token_id, vocab_.size());
        return "";  // Unknown token
    }
    
    std::string token = vocab_[token_id];
    fprintf(stderr, "[DETOKEN] Raw token[%u] = '%s' (len=%zu)\n", token_id, token.c_str(), token.size());
    std::string cleaned = CleanToken(token);
    fprintf(stderr, "[DETOKEN] Cleaned = '%s' (len=%zu)\n", cleaned.c_str(), cleaned.size());
    return cleaned;
}

std::string Detokenizer::DetokenizeSequence(const std::vector<uint32_t>& tokens) const {
    std::string result;
    result.reserve(tokens.size() * 8);  // Rough estimate
    
    for (uint32_t token_id : tokens) {
        std::string token = Detokenize(token_id);
        result += token;
    }
    
    return result;
}

std::string Detokenizer::CleanToken(const std::string& token) const {
    std::string cleaned = token;
    
    // Replace "▁" (U+2581) with space - this is SentencePiece's space marker
    // In UTF-8, ▁ is 0xE2 0x96 0x81
    size_t pos = 0;
    while ((pos = cleaned.find("\xE2\x96\x81", pos)) != std::string::npos) {
        cleaned.replace(pos, 3, " ");
        pos += 1;
    }
    
    // Replace "Ġ" (U+0120) with space - this is Llama's BPE space marker
    // In UTF-8, Ġ is 0xC4 0xA0
    pos = 0;
    while ((pos = cleaned.find("\xC4\xA0", pos)) != std::string::npos) {
        cleaned.replace(pos, 2, " ");
        pos += 1;
    }
    
    // Replace "Ċ" (U+010A) with newline - BPE newline marker
    // In UTF-8, Ċ is 0xC4 0x8A
    pos = 0;
    while ((pos = cleaned.find("\xC4\x8A", pos)) != std::string::npos) {
        cleaned.replace(pos, 2, "\n");
        pos += 1;
    }
    
    // Replace "ĉ" (U+0109) with tab - BPE tab marker
    // In UTF-8, ĉ is 0xC4 0x89
    pos = 0;
    while ((pos = cleaned.find("\xC4\x89", pos)) != std::string::npos) {
        cleaned.replace(pos, 2, "\t");
        pos += 1;
    }
    
    // Handle byte fallback tokens (Llama 3 uses these)
    // Tokens like "<0x00>" through "<0xFF>" represent raw bytes
    if (cleaned.length() >= 4 && cleaned[0] == '<' && cleaned[cleaned.length()-1] == '>') {
        // Check if it's a byte token like "<0x20>"
        if (cleaned.length() == 6 && cleaned[1] == '0' && cleaned[2] == 'x') {
            try {
                int byte_val = std::stoi(cleaned.substr(3, 2), nullptr, 16);
                if (byte_val >= 0x20 && byte_val < 0x7F) {
                    // Printable ASCII
                    cleaned = std::string(1, static_cast<char>(byte_val));
                } else if (byte_val == 0x0A) {
                    cleaned = "\n";
                } else if (byte_val == 0x09) {
                    cleaned = "\t";
                } else if (byte_val == 0x00) {
                    cleaned = "";
                }
            } catch (...) {
                // Not a valid hex number, keep original
            }
        }
    }
    
    return cleaned;
}

} // namespace Sovereign