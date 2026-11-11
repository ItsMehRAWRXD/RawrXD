#include "tokenizer_advanced.h"
#include <algorithm>
#include <cctype>

namespace rawrxd {
namespace tokenizer {

// ============================================================================
// MappedVocabBuffer Implementation
// ============================================================================

bool MappedVocabBuffer::MapFile(const wchar_t* file_path) {
    Unmap();
    
    file_handle_ = CreateFileW(
        file_path,
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file_handle_, &file_size)) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    size_ = static_cast<size_t>(file_size.QuadPart);
    
    mapping_handle_ = CreateFileMapping(
        file_handle_,
        nullptr,
        PAGE_READONLY,
        0, 0,
        nullptr
    );
    
    if (!mapping_handle_) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    data_ = MapViewOfFile(mapping_handle_, FILE_MAP_READ, 0, 0, 0);
    if (!data_) {
        CloseHandle(mapping_handle_);
        CloseHandle(file_handle_);
        mapping_handle_ = nullptr;
        file_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    return true;
}

void MappedVocabBuffer::Unmap() {
    if (data_) {
        UnmapViewOfFile(data_);
        data_ = nullptr;
    }
    if (mapping_handle_) {
        CloseHandle(mapping_handle_);
        mapping_handle_ = nullptr;
    }
    if (file_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
    }
    size_ = 0;
}

// ============================================================================
// AVX512UTF8Splitter Implementation
// ============================================================================

AVX512UTF8Splitter::AVX512UTF8Splitter() {
    // Initialize dual-nibble lookup table
    // High nibble: character class category
    // Low nibble: specific classification
    for (int i = 0; i < 16; ++i) {
        uint8_t flags = 0;
        if (i >= 0x0 && i <= 0x9) {
            flags = CLASS_DIGIT;
        } else if (i >= 0x0A && i <= 0x0F) {
            // A-F (hex), treat as alpha
            flags = CLASS_ALPHA;
        }
        nibble_lut_[i] = flags;
    }
    
    // Override specific classifications
    nibble_lut_[0x0] = CLASS_WHITESPACE;  // NUL (treat as whitespace)
    nibble_lut_[0x1] = CLASS_WHITESPACE;  // SOH
    nibble_lut_[0x2] = CLASS_WHITESPACE;  // STX
    nibble_lut_[0x3] = CLASS_WHITESPACE;  // ETX
    nibble_lut_[0x4] = CLASS_WHITESPACE;  // EOT
    nibble_lut_[0x5] = CLASS_WHITESPACE;  // ENQ
    nibble_lut_[0x6] = CLASS_WHITESPACE;  // ACK
    nibble_lut_[0x7] = CLASS_WHITESPACE;  // BEL
    nibble_lut_[0x8] = CLASS_WHITESPACE;  // BS
    nibble_lut_[0x9] = CLASS_WHITESPACE;  // TAB
    nibble_lut_[0xA] = CLASS_WHITESPACE;  // LF
    nibble_lut_[0xB] = CLASS_WHITESPACE;  // VT
    nibble_lut_[0xC] = CLASS_WHITESPACE;  // FF
    nibble_lut_[0xD] = CLASS_WHITESPACE;  // CR
    nibble_lut_[0xE] = CLASS_WHITESPACE;  // SO
    nibble_lut_[0xF] = CLASS_WHITESPACE;  // SI
}

std::vector<size_t> AVX512UTF8Splitter::Split(const char* text, size_t length) {
    std::vector<size_t> boundaries;
    boundaries.reserve(length / 4);  // Estimate: average 4 chars per sub-word
    
    // Always include start boundary
    boundaries.push_back(0);
    
    size_t i = 0;
    
    // Process 64-byte aligned blocks with AVX-512
    while (i + 64 <= length) {
        // Align to 64-byte boundary for optimal performance
        size_t aligned_start = (i + 63) & ~63ULL;
        if (aligned_start > i && aligned_start < i + 64) {
            // Process unaligned prefix
            ProcessUTF8Continuations(text + i, aligned_start - i, boundaries);
            i = aligned_start;
            continue;
        }
        
        ProcessBlock64(text + i, 64, boundaries, i);
        i += 64;
    }
    
    // Process remaining bytes
    if (i < length) {
        ProcessUTF8Continuations(text + i, length - i, boundaries);
    }
    
    // Always include end boundary
    boundaries.push_back(length);
    
    return boundaries;
}

void AVX512UTF8Splitter::ProcessBlock64(const char* block, size_t block_len,
                                       std::vector<size_t>& boundaries, size_t base_offset) {
    // Load 64 bytes into ZMM register
    __m512i chars = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(block));
    
    // Classify characters
    __m512i classifications = ClassifyASCII64(chars);
    
    // Create masks for different character types
    __mmask64 whitespace_mask = _mm512_test_epi8_mask(classifications, 
                                                       _mm512_set1_epi8(CLASS_WHITESPACE));
    __mmask64 punct_mask = _mm512_test_epi8_mask(classifications,
                                                  _mm512_set1_epi8(CLASS_PUNCT));
    __mmask64 alpha_mask = _mm512_test_epi8_mask(classifications,
                                                  _mm512_set1_epi8(CLASS_ALPHA));
    __mmask64 digit_mask = _mm512_test_epi8_mask(classifications,
                                                  _mm512_set1_epi8(CLASS_DIGIT));
    
    // Detect boundaries: whitespace transitions, punctuation, alpha->digit/digit->alpha
    // Shift masks to detect transitions
    __mmask64 whitespace_trans = whitespace_mask ^ (whitespace_mask >> 1);
    __mmask64 punct_boundary = punct_mask;
    __mmask64 alpha_digit_boundary = (alpha_mask & (digit_mask >> 1)) | 
                                      (digit_mask & (alpha_mask >> 1));
    
    // Combine all boundary masks
    __mmask64 all_boundaries = whitespace_trans | punct_boundary | alpha_digit_boundary;
    
    // Extract boundary positions
    while (all_boundaries != 0) {
        int bit_pos = _tzcnt_u64(all_boundaries);
        if (bit_pos < static_cast<int>(block_len)) {
            boundaries.push_back(base_offset + bit_pos);
        }
        all_boundaries &= all_boundaries - 1;  // Clear lowest set bit
    }
}

__m512i AVX512UTF8Splitter::ClassifyASCII64(__m512i chars) {
    // Extract high and low nibbles
    __m512i high_nibble = _mm512_srli_epi16(chars, 4);
    high_nibble = _mm512_and_si512(high_nibble, _mm512_set1_epi8(0x0F));
    
    __m512i low_nibble = _mm512_and_si512(chars, _mm512_set1_epi8(0x0F));
    
    // Use shuffle to look up classification from high nibble
    __m512i high_class = _mm512_shuffle_epi8(
        _mm512_loadu_si512(reinterpret_cast<const __m512i*>(nibble_lut_)),
        high_nibble
    );
    
    // Refine with low nibble for specific cases
    __m512i low_class = _mm512_shuffle_epi8(
        _mm512_loadu_si512(reinterpret_cast<const __m512i*>(nibble_lut_)),
        low_nibble
    );
    
    // Combine classifications
    return _mm512_or_si512(high_class, low_class);
}

void AVX512UTF8Splitter::ProcessUTF8Continuations(const char* text, size_t length,
                                                   std::vector<size_t>& boundaries) {
    for (size_t i = 0; i < length; ) {
        unsigned char c = static_cast<unsigned char>(text[i]);
        
        // Check for UTF-8 multi-byte sequences
        if ((c & 0x80) == 0) {
            // ASCII: check for boundary characters
            if (std::isspace(c) || std::ispunct(c)) {
                boundaries.push_back(i);
            }
            ++i;
        } else if ((c & 0xE0) == 0xC0) {
            // 2-byte sequence
            boundaries.push_back(i);
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            // 3-byte sequence
            boundaries.push_back(i);
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            // 4-byte sequence
            boundaries.push_back(i);
            i += 4;
        } else {
            // Invalid UTF-8, skip
            ++i;
        }
    }
}

// ============================================================================
// SIMDBPETokenizer Implementation
// ============================================================================

SIMDBPETokenizer::SIMDBPETokenizer()
    : splitter_(std::make_unique<AVX512UTF8Splitter>())
    , vocab_loaded_(false)
    , vocab_size_(0)
    , unk_token_id_(0)
    , bos_token_id_(1)
    , eos_token_id_(2) {
}

bool SIMDBPETokenizer::LoadFromGGUFMMap(const wchar_t* gguf_path) {
    if (!vocab_buffer_.MapFile(gguf_path)) {
        return false;
    }
    
    // Parse GGUF header and vocabulary
    // This is a simplified implementation - full GGUF parsing would be more complex
    const uint8_t* data = vocab_buffer_.Data();
    size_t size = vocab_buffer_.Size();
    
    if (size < 64) {
        vocab_buffer_.Unmap();
        return false;
    }
    
    // Check GGUF magic number
    if (data[0] != 'G' || data[1] != 'G' || data[2] != 'U' || data[3] != 'F') {
        vocab_buffer_.Unmap();
        return false;
    }
    
    // Parse vocabulary entries (simplified)
    // In a real implementation, this would parse the full GGUF structure
    // For now, we'll populate with basic tokens
    
    // Add common tokens
    token_to_id_["<unk>"] = 0;
    token_to_id_["<s>"] = 1;
    token_to_id_["</s>"] = 2;
    
    id_to_token_[0] = "<unk>";
    id_to_token_[1] = "<s>";
    id_to_token_[2] = "</s>";
    
    vocab_size_ = 3;
    vocab_loaded_ = true;
    
    return true;
}

std::vector<int32_t> SIMDBPETokenizer::Encode(const std::string& text) {
    std::vector<int32_t> tokens;
    
    if (!vocab_loaded_) {
        return tokens;
    }
    
    // Add BOS token
    tokens.push_back(bos_token_id_);
    
    // Split text into sub-words
    std::vector<size_t> boundaries = splitter_->Split(text.c_str(), text.length());
    
    // Tokenize each sub-word
    for (size_t i = 0; i + 1 < boundaries.size(); ++i) {
        size_t start = boundaries[i];
        size_t end = boundaries[i + 1];
        std::string subword = text.substr(start, end - start);
        
        std::vector<int32_t> sub_tokens = TokenizeSubword(subword);
        tokens.insert(tokens.end(), sub_tokens.begin(), sub_tokens.end());
    }
    
    // Apply BPE merges
    ApplyBPEMerges(tokens);
    
    // Add EOS token
    tokens.push_back(eos_token_id_);
    
    return tokens;
}

std::string SIMDBPETokenizer::Decode(const std::vector<int32_t>& tokens) {
    std::string result;
    
    for (int32_t token : tokens) {
        auto it = id_to_token_.find(token);
        if (it != id_to_token_.end()) {
            const std::string& piece = it->second;
            // Skip special tokens in output
            if (piece != "<unk>" && piece != "<s>" && piece != "</s>") {
                result += piece;
            }
        }
    }
    
    return result;
}

void SIMDBPETokenizer::ApplyBPEMerges(std::vector<int32_t>& tokens) {
    if (tokens.size() < 2) {
        return;
    }
    
    bool merged = true;
    while (merged) {
        merged = false;
        size_t merge_pos;
        int32_t merged_token;
        
        if (FindBestMerge(tokens, merge_pos, merged_token)) {
            // Apply merge
            tokens[merge_pos] = merged_token;
            tokens.erase(tokens.begin() + merge_pos + 1);
            merged = true;
        }
    }
}

bool SIMDBPETokenizer::FindBestMerge(const std::vector<int32_t>& tokens,
                                      size_t& merge_pos, int32_t& merged_token) {
    // Find the highest priority merge pair
    // In a real implementation, this would use the merge priority from the BPE model
    
    for (size_t i = 0; i + 1 < tokens.size(); ++i) {
        PackedTokenPair pair;
        pair.tokens.first = tokens[i];
        pair.tokens.second = tokens[i + 1];
        
        auto it = merge_pairs_.find(pair);
        if (it != merge_pairs_.end()) {
            merge_pos = i;
            merged_token = it->second;
            return true;
        }
    }
    
    return false;
}

std::vector<int32_t> SIMDBPETokenizer::TokenizeSubword(const std::string& subword) {
    std::vector<int32_t> tokens;
    
    // Try to find the subword in vocabulary
    auto it = token_to_id_.find(subword);
    if (it != token_to_id_.end()) {
        tokens.push_back(it->second);
        return tokens;
    }
    
    // Try with space prefix (for word-initial pieces)
    std::string with_space = " " + subword;
    it = token_to_id_.find(with_space);
    if (it != token_to_id_.end()) {
        tokens.push_back(it->second);
        return tokens;
    }
    
    // Character-level fallback
    for (char c : subword) {
        std::string char_str(1, c);
        it = token_to_id_.find(char_str);
        if (it != token_to_id_.end()) {
            tokens.push_back(it->second);
        } else {
            tokens.push_back(unk_token_id_);
        }
    }
    
    return tokens;
}

} // namespace tokenizer
} // namespace rawrxd
