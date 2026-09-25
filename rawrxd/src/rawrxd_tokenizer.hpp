#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <regex>

namespace rawrxd {

enum class TokenizerType {
    BPE = 0,
    SPM = 1,
    WordPiece = 2,
    Char = 3,
    Custom = 4
};

struct TokenizerConfig {
    TokenizerType type = TokenizerType::BPE;
    bool add_bos = false;
    bool add_eos = false;
    bool add_prefix_space = false;
    bool trim_whitespace = false;
    bool clean_up_tokenization_spaces = true;
    std::string bos_token = "<s>";
    std::string eos_token = "</s>";
    std::string unk_token = "<unk>";
    std::string pad_token = "<pad>";
    uint32_t bos_id = 1;
    uint32_t eos_id = 2;
    uint32_t unk_id = 0;
    uint32_t pad_id = 0;
};

struct VocabEntry {
    std::string token;
    float score = 0.0f;
    uint32_t type = 0;
};

struct SpecialToken {
    std::string token;
    uint32_t id;
};

class Tokenizer {
public:
    Tokenizer();
    ~Tokenizer();

    bool LoadFromGGUF(const std::string& path);
    bool LoadFromFile(const std::string& path);
    bool LoadFromMemory(const std::vector<uint8_t>& vocab_data,
                        const std::vector<uint8_t>& merges_data);
    bool LoadVocab(const std::map<std::string, uint32_t>& vocab,
                   const std::vector<std::pair<std::string, std::string>>& merges);

    bool IsLoaded() const;

    std::vector<uint32_t> Encode(const std::string& text) const;
    std::string Decode(const std::vector<uint32_t>& tokens) const;
    std::string DecodePiece(uint32_t token) const;

    size_t VocabSize() const;
    std::vector<std::string> VocabStrings() const;
    std::optional<std::string> IdToToken(uint32_t id) const;
    std::optional<uint32_t> TokenToId(const std::string& token) const;

    std::vector<uint32_t> EncodeWithPreTokenization(const std::string& text) const;

    void SetConfig(const TokenizerConfig& config);
    const TokenizerConfig& GetConfig() const;

    bool Save(const std::string& path) const;

    static std::vector<std::string> PreTokenize(const std::string& text,
                                                const std::string& pattern = R"('(?:[sdmt]|ll|ve|re)| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+)");

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd