#pragma once
// ============================================================================
// Tokenizer.hpp — Batch 7 no-dependency GGUF tokenizer
// Supports:
//   tokenizer.ggml.model = gpt2       -> byte-level BPE
//   tokenizer.ggml.model = llama      -> SentencePiece-style unigram/Viterbi
//   tokenizer.ggml.model = replit     -> SentencePiece-style unigram/Viterbi
//   tokenizer.ggml.model = rwkv       -> raw-byte longest-match
// ============================================================================
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace Deep2 {

class GGUFLoader;

struct ITokenizer {
    virtual ~ITokenizer() = default;
    virtual std::vector<int> encode(const std::string& text) = 0;
    virtual std::string decode(const std::vector<int>& tokens) = 0;
    virtual std::string decode(int token) = 0;
    virtual size_t vocabSize() const = 0;
};

class BPETokenizer : public ITokenizer {
public:
    enum class Kind : uint8_t {
        Unknown = 0,
        GPT2BPE,
        SentencePiece,
        RWKV
    };

    bool loadFromFile(const std::string& vocabPath);

    // Legacy raw-buffer entry point retained for source compatibility.
    // GGUF parsing authority is GGUFLoader; callers should use the overload below.
    bool loadFromGGUF(const void* ggufData, size_t len);

    // Batch 7 authority: bind tokenizer.ggml.* directly from parsed GGUF metadata.
    bool loadFromGGUF(const GGUFLoader& loader);

    std::vector<int> encode(const std::string& text) override;
    std::string decode(const std::vector<int>& tokens) override;
    std::string decode(int token) override;
    size_t vocabSize() const override { return idToToken_.size(); }

    bool ready() const { return ready_; }
    Kind kind() const { return kind_; }
    const std::string& modelName() const { return modelName_; }

    int bosTokenId() const { return bosId_; }
    int eosTokenId() const { return eosId_; }
    int unknownTokenId() const { return unkId_; }
    int paddingTokenId() const { return padId_; }

    bool addBos() const { return addBos_; }
    bool addEos() const { return addEos_; }
    bool isEos(int token) const { return eosId_ >= 0 && token == eosId_; }
    bool isSpecial(int token) const;

private:
    struct TrieNode {
        std::unordered_map<unsigned char, size_t> next;
        int tokenId = -1;
    };

    struct DPCell {
        float score = -3.402823466e+38F;
        size_t prev = 0;
        int tokenId = -1;
        bool reachable = false;
    };

    void clear();
    void buildAuxiliaryIndexes();

    std::vector<int> encodeOrdinary(const std::string& text);
    std::vector<int> encodeGPT2(const std::string& text);
    std::vector<int> encodeSentencePiece(const std::string& text,
                                         bool addDummyPrefix);
    std::vector<int> encodeRWKV(const std::string& text);

    std::vector<std::string> splitGPT2Pretokens(const std::string& text) const;
    std::vector<std::string> bpeMerge(const std::string& raw) const;

    std::string byteEncodeString(const std::string& raw) const;
    std::string byteDecodeString(const std::string& encoded) const;

    static std::string utf8FromCodepoint(uint32_t cp);
    static size_t utf8CodepointBytes(unsigned char lead);
    static std::string pairKey(const std::string& a, const std::string& b);
    static bool parseByteToken(const std::string& token, uint8_t& value);
    static bool looksSpecial(const std::string& token);

    bool tokenUsableInTrie(int id) const;
    void trieInsert(const std::string& token, int id);
    std::vector<std::pair<size_t, int>> trieMatches(const std::string& text,
                                                     size_t pos) const;

    std::string decodeTokenRaw(int token) const;
    std::string decodeSentencePieceToken(const std::string& token) const;

    std::unordered_map<std::string, int> tokenToId_;
    std::vector<std::string> idToToken_;
    std::vector<float> scores_;
    std::vector<int32_t> tokenTypes_;

    std::unordered_map<std::string, size_t> mergeRanks_;

    std::array<std::string, 256> byteToUnicode_{};
    std::unordered_map<std::string, uint8_t> unicodeToByte_;
    std::array<int, 256> byteTokenIds_{};

    std::vector<TrieNode> trie_;
    std::vector<std::pair<std::string, int>> literalSpecials_;

    Kind kind_ = Kind::Unknown;
    std::string modelName_;
    bool ready_ = false;
    bool addBos_ = false;
    bool addEos_ = false;

    int bosId_ = -1;
    int eosId_ = -1;
    int unkId_ = -1;
    int sepId_ = -1;
    int padId_ = -1;
};

} // namespace Deep2
