#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <fstream>

namespace Deep2Rom::Inference {

    enum class TokenType : uint32_t {
        Normal = 1,
        Unknown = 2,
        Control = 3,
        Byte = 4,
        UserDefined = 5,
    };

    // A single vocab entry from a GGUF file
    struct VocabEntry {
        std::string token;       // The piece text
        float score;             // BPE merge score (lower = better)
        TokenType type;          // Token type
        uint32_t id;             // Token ID (position in vocab array)
    };

    // Tokenizer configuration
    struct TokenizerConfig {
        uint32_t vocabSize = 0;
        uint32_t bosTokenId = 1;
        uint32_t eosTokenId = 2;
        uint32_t unkTokenId = 3;
        uint32_t padTokenId = 0;
        std::string modelArch;   // llama, phi3, qwen, gemma, etc.
    };

    class Tokenizer {
    public:
        Tokenizer() = default;
        ~Tokenizer() = default;

        // Load tokenizer data from a GGUF file
        // Reads tokenizer.ggml.tokens, tokenizer.ggml.scores, tokenizer.ggml.token_type
        bool loadFromGGUF(const std::string& ggufPath);

        // Load tokenizer data from a ROM manifest (for pre-converted models)
        bool loadFromROM(const std::string& romPath);

        // Check if tokenizer is ready
        bool isReady() const { return m_ready; }

        // Get vocab size
        uint32_t vocabSize() const { return m_config.vocabSize; }

        // Get special token IDs
        uint32_t bosTokenId() const { return m_config.bosTokenId; }
        uint32_t eosTokenId() const { return m_config.eosTokenId; }
        uint32_t unkTokenId() const { return m_config.unkTokenId; }
        uint32_t padTokenId() const { return m_config.padTokenId; }

        // Encode text to token IDs (with optional BOS/EOS)
        std::vector<uint32_t> encode(const std::string& text, bool addBos = true, bool addEos = false) const;

        // Decode token IDs back to text
        std::string decode(const std::vector<uint32_t>& tokens, bool skipSpecial = true) const;

        // Encode and return as vector<int> (for compatibility with older APIs)
        std::vector<int> encodeInt(const std::string& text, bool addBos = true, bool addEos = false) const;

        const TokenizerConfig& config() const { return m_config; }

    private:
        // Byte-level encoding (GPT-2 style): map each byte to a printable Unicode char
        void initByteEncoder();

        // Convert a single UTF-8 character to its byte representation
        std::string byteToUnicode(uint8_t byte) const;
        uint8_t unicodeToByte(char32_t ch) const;

        // Apply BPE merges to a list of byte-units
        void applyBPE(std::vector<std::string>& pieces) const;

        // Find the best merge pair in a piece list (lowest score)
        // Returns pair index and score, or -1 if no merge possible
        int findBestMerge(const std::vector<std::string>& pieces, float& bestScore) const;

        // Merge two adjacent pieces at index i
        void mergePair(std::vector<std::string>& pieces, int i) const;

        // Vocab: piece string -> token ID
        std::unordered_map<std::string, uint32_t> m_vocab;

        // Reverse vocab: token ID -> piece string
        std::unordered_map<uint32_t, std::string> m_reverseVocab;

        // Merges: (piece1, piece2) -> score
        std::unordered_map<uint64_t, float> m_merges;

        // Token types
        std::unordered_map<uint32_t, TokenType> m_tokenTypes;

        // Byte encoder: byte -> unicode char
        std::unordered_map<uint8_t, char32_t> m_byteEncoder;
        // Byte decoder: unicode char -> byte
        std::unordered_map<char32_t, uint8_t> m_byteDecoder;

        TokenizerConfig m_config;
        bool m_ready = false;
    };

} // namespace Deep2Rom::Inference
