#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>

namespace rawrxd {

struct VocabToken {
    std::string text;
    float score = 0.0f;
    uint32_t type = 0;
    std::vector<uint8_t> raw_bytes;
};

struct VocabEntry {
    uint32_t id;
    VocabToken token;
};

struct SpecialTokenMap {
    uint32_t bos_id = std::numeric_limits<uint32_t>::max();
    uint32_t eos_id = std::numeric_limits<uint32_t>::max();
    uint32_t unk_id = std::numeric_limits<uint32_t>::max();
    uint32_t pad_id = std::numeric_limits<uint32_t>::max();
    uint32_t mask_id = std::numeric_limits<uint32_t>::max();
    uint32_t newline_id = std::numeric_limits<uint32_t>::max();
    std::map<std::string, uint32_t> extra;
};

enum class VocabFormat {
    Unknown = 0,
    SentencePiece = 1,
    BPE = 2,
    Raw = 3
};

class GGUFVocabResolver {
public:
    GGUFVocabResolver();
    ~GGUFVocabResolver();

    bool LoadFromGGUF(const std::string& gguf_path);
    bool LoadFromMemory(const std::vector<uint8_t>& vocab_data,
                        const std::vector<uint8_t>& score_data,
                        VocabFormat format = VocabFormat::SentencePiece);

    bool IsLoaded() const;

    std::optional<VocabToken> Lookup(uint32_t id) const;
    std::optional<uint32_t> Lookup(const std::string& text) const;
    std::optional<uint32_t> LookupBytes(const std::vector<uint8_t>& raw) const;

    const std::map<uint32_t, VocabToken>& GetVocab() const;
    size_t VocabSize() const;

    SpecialTokenMap& GetSpecialTokens();
    const SpecialTokenMap& GetSpecialTokens() const;

    std::string DecodeId(uint32_t id) const;
    std::vector<std::string> DecodeIds(const std::vector<uint32_t>& ids) const;

    std::vector<uint32_t> EncodeText(const std::string& text) const;
    std::string DecodeTokens(const std::vector<uint32_t>& tokens) const;

    void AddOverride(uint32_t id, const VocabToken& token);
    void RemoveOverride(uint32_t id);

    void Clear();

    static VocabFormat DetectFormat(const std::vector<uint8_t>& header);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rawrxd
