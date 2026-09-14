#pragma once
/* Real BPE Tokenizer — loads vocab + merges from GGUF or external file */
#include <string>
#include <vector>
#include <unordered_map>

namespace Deep2 {

struct ITokenizer {
    virtual ~ITokenizer() = default;
    virtual std::vector<int> encode(const std::string& text) = 0;
    virtual std::string decode(const std::vector<int>& tokens) = 0;
    virtual std::string decode(int token) = 0;
    virtual size_t vocabSize() const = 0;
};

class BPETokenizer : public ITokenizer {
public:
    bool loadFromFile(const std::string& vocabPath);
    bool loadFromGGUF(const void* ggufData, size_t len);
    std::vector<int> encode(const std::string& text) override;
    std::string decode(const std::vector<int>& tokens) override;
    std::string decode(int token) override;
    size_t vocabSize() const override { return idToToken_.size(); }

private:
    std::unordered_map<std::string, int> tokenToId_;
    std::unordered_map<int, std::string> idToToken_;
    std::vector<std::pair<std::string, std::string>> merges_;

    std::vector<std::string> byteEncode(const std::string& s);
    std::vector<std::string> splitToWords(const std::string& s);
};

} // namespace Deep2
