#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <immintrin.h>
#include <windows.h>

namespace rawrxd {
namespace tokenizer {

// Bit-level character classification flags
enum CharClassFlag : uint8_t {
    CLASS_ALPHA = 1 << 0,
    CLASS_DIGIT = 1 << 1,
    CLASS_WHITESPACE = 1 << 2,
    CLASS_PUNCT = 1 << 3,
    CLASS_CONTRACTION = 1 << 4,
    CLASS_UTF8_LEAD = 1 << 5,
    CLASS_UTF8_TRAIL = 1 << 6
};

// Packed token pair for efficient hash table storage
union PackedTokenPair {
    struct {
        uint32_t first;
        uint32_t second;
    } tokens;
    uint64_t packed;
    
    bool operator==(const PackedTokenPair& other) const {
        return packed == other.packed;
    }
};

struct FastPairHash {
    size_t operator()(const PackedTokenPair& p) const noexcept {
        return std::hash<uint64_t>{}(p.packed);
    }
};

// RAII handle for memory-mapped vocabulary buffer
class MappedVocabBuffer {
public:
    MappedVocabBuffer() : file_handle_(INVALID_HANDLE_VALUE), 
                          mapping_handle_(nullptr), 
                          data_(nullptr), 
                          size_(0) {}
    
    ~MappedVocabBuffer() {
        Unmap();
    }
    
    // Disable copy, enable move
    MappedVocabBuffer(const MappedVocabBuffer&) = delete;
    MappedVocabBuffer& operator=(const MappedVocabBuffer&) = delete;
    
    MappedVocabBuffer(MappedVocabBuffer&& other) noexcept
        : file_handle_(other.file_handle_)
        , mapping_handle_(other.mapping_handle_)
        , data_(other.data_)
        , size_(other.size_) {
        other.file_handle_ = INVALID_HANDLE_VALUE;
        other.mapping_handle_ = nullptr;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    
    MappedVocabBuffer& operator=(MappedVocabBuffer&& other) noexcept {
        if (this != &other) {
            Unmap();
            file_handle_ = other.file_handle_;
            mapping_handle_ = other.mapping_handle_;
            data_ = other.data_;
            size_ = other.size_;
            other.file_handle_ = INVALID_HANDLE_VALUE;
            other.mapping_handle_ = nullptr;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }
    
    bool MapFile(const wchar_t* file_path);
    void Unmap();
    
    const uint8_t* Data() const { return static_cast<const uint8_t*>(data_); }
    size_t Size() const { return size_; }
    bool IsValid() const { return data_ != nullptr; }
    
private:
    HANDLE file_handle_;
    HANDLE mapping_handle_;
    void* data_;
    size_t size_;
};

// AVX-512 UTF-8 sub-word splitter
class AVX512UTF8Splitter {
public:
    AVX512UTF8Splitter();
    
    // Split text into sub-words using AVX-512 parallel processing
    // Returns vector of byte offsets for each sub-word boundary
    std::vector<size_t> Split(const char* text, size_t length);
    
    // Process 64 bytes at a time with AVX-512
    void ProcessBlock64(const char* block, size_t block_len, 
                        std::vector<size_t>& boundaries, size_t base_offset);
    
private:
    // Classify 64 ASCII characters in parallel
    __m512i ClassifyASCII64(__m512i chars);
    
    // Process UTF-8 continuation bytes
    void ProcessUTF8Continuations(const char* text, size_t length,
                                   std::vector<size_t>& boundaries);
    
    // Dual-nibble lookup table for character classification
    alignas(64) uint8_t nibble_lut_[16];
};

// SIMD-optimized BPE tokenizer
class SIMDBPETokenizer {
public:
    SIMDBPETokenizer();
    ~SIMDBPETokenizer() = default;
    
    // Load vocabulary from GGUF file using zero-copy memory mapping
    bool LoadFromGGUFMMap(const wchar_t* gguf_path);
    
    // Encode text to token IDs
    std::vector<int32_t> Encode(const std::string& text);
    
    // Decode token IDs to text
    std::string Decode(const std::vector<int32_t>& tokens);
    
    // Check if vocabulary is loaded
    bool IsLoaded() const { return vocab_loaded_; }
    
private:
    // BPE merge operations
    void ApplyBPEMerges(std::vector<int32_t>& tokens);
    
    // Find best merge pair
    bool FindBestMerge(const std::vector<int32_t>& tokens, 
                       size_t& merge_pos, int32_t& merged_token);
    
    // Tokenize sub-word using vocabulary
    std::vector<int32_t> TokenizeSubword(const std::string& subword);
    
    // Member variables
    std::unique_ptr<AVX512UTF8Splitter> splitter_;
    MappedVocabBuffer vocab_buffer_;
    
    // Vocabulary mappings
    std::unordered_map<std::string, int32_t> token_to_id_;
    std::unordered_map<int32_t, std::string> id_to_token_;
    std::unordered_map<PackedTokenPair, int32_t, FastPairHash> merge_pairs_;
    
    bool vocab_loaded_;
    int32_t vocab_size_;
    int32_t unk_token_id_;
    int32_t bos_token_id_;
    int32_t eos_token_id_;
};

// Convenience typedef for external use
using AdvancedTokenizer = SIMDBPETokenizer;

} // namespace tokenizer
} // namespace rawrxd
