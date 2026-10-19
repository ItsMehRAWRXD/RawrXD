#pragma once
//
// GgufTokenizer - llama.cpp-compatible tokenizer for GGUF models.
//
// Two tokenizer families are supported, selected by `tokenizer.ggml.model`:
//
//   "llama" -> SentencePiece (SPM). Phi-3, TinyLlama, Llama-2.
//       The vocabulary stores U+2581 ('▁') for word boundaries and the GGUF
//       carries no merge table. Tokens are produced by greedily merging
//       adjacent characters, highest token score first.
//
//   "gpt2"  -> byte-level BPE. DeepSeek-V2, Qwen, Gemma.
//       The vocabulary stores the GPT-2 byte-to-unicode mapping and the GGUF
//       carries an explicit merge table.
//
// Reference implementation: llama.cpp `src/llama-vocab.cpp`
//   - llm_tokenizer_spm_session   (SPM merge + resegment)
//   - llm_tokenizer_bpe_session   (BPE merge by rank)
//

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace Deep2Rom::Inference {

enum class GgufTokenizerType {
    Unknown,
    Spm,  // "llama" - SentencePiece
    Bpe,  // "gpt2"  - byte-level BPE
};

// A tokenizer loaded directly from a GGUF file.
class GgufTokenizer {
public:
    GgufTokenizer() = default;

    // Load vocabulary, scores, token types and merge rules from a GGUF file.
    bool loadFromGGUF(const std::string& ggufPath);

    bool isReady() const { return m_ready; }
    GgufTokenizerType type() const { return m_type; }

    uint32_t vocabSize() const { return static_cast<uint32_t>(m_vocab.size()); }
    uint32_t bosTokenId() const { return m_bosId; }
    uint32_t eosTokenId() const { return m_eosId; }
    uint32_t unkTokenId() const { return m_unkId; }
    // True when the model's GGUF declares an unknown token. When it does not,
    // unkTokenId() returns kNoUnknownToken, which no real token can match.
    bool hasUnknownToken() const { return m_unkId != kNoUnknownToken; }
    uint32_t padTokenId() const { return m_padId; }

    // Token text for an id, or an empty string when the id is unknown.
    const std::string& piece(uint32_t id) const;

    // Encode text to token ids. BOS is NOT prepended; callers decide.
    std::vector<uint32_t> encode(const std::string& text) const;

    // Decode a single id back to text.
    std::string decode(uint32_t id) const;

    // Decode a sequence of ids back to text.
    std::string decode(const std::vector<uint32_t>& ids) const;

    // True when the id is a control/special token.
    bool isControl(uint32_t id) const;

private:
    // SPM
    std::vector<uint32_t> encodeSpm(const std::string& text) const;
    // BPE
    std::vector<uint32_t> encodeBpe(const std::string& text) const;
    // BPE pre-tokenizer split, selected by tokenizer.ggml.pre.
    std::vector<std::string> pretokenize(const std::string& text) const;

    // Map a raw byte onto the id of its byte-fallback token ("<0x41>").
    uint32_t byteToToken(uint8_t byte) const;

    // GPT-2 byte <-> unicode codepoint mapping.
    static uint32_t byteToCodepoint(uint8_t byte);
    static std::string codepointToUtf8(uint32_t cp);

    std::vector<std::string> m_vocab;                             // id -> piece
    std::vector<float> m_scores;                                  // id -> score
    std::vector<uint32_t> m_tokenTypes;                           // id -> type
    std::unordered_map<std::string, uint32_t> m_tokenToId;        // piece -> id
    std::unordered_map<uint64_t, uint32_t> m_mergeRanks;          // (a<<32|b) -> rank
    std::vector<std::pair<std::string, std::string>> m_merges;    // BPE rules, GGUF order

    uint32_t m_bosId = 1;
    uint32_t m_eosId = 2;
    // Id used when the GGUF declares no unknown token. A real token can never
    // carry this id, so an unresolvable byte can never alias a live token.
    // Defaulting this to 0 is wrong: in a GPT-2 style vocabulary id 0 is the
    // token for '!', so a byte-fallback failure would silently emit '!'.
    static constexpr uint32_t kNoUnknownToken = 0xFFFFFFFFu;
    uint32_t m_unkId = kNoUnknownToken;
    uint32_t m_padId = 0;

    GgufTokenizerType m_type = GgufTokenizerType::Unknown;
    std::string m_preType = "default";  // tokenizer.ggml.pre
    bool m_addSpacePrefix = false;   // SPM: prepend a space before encoding
    bool m_cleanSpaces = false;      // SPM: collapse runs of whitespace
    bool m_ready = false;
};

}  // namespace Deep2Rom::Inference
