#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::parity {

struct Piece {
    std::string text;
    float score = 0.0f;
    int32_t type = 1;
};

class GgufParityTokenizer {
public:
    bool load(const std::string& ggufPath, std::string* error = nullptr);

    std::vector<int32_t> encode(const std::string& text, bool addBos = true) const;
    std::string decode(const std::vector<int32_t>& ids) const;

    int32_t bosId() const { return bos_id_; }
    int32_t eosId() const { return eos_id_; }
    int32_t unkId() const { return unk_id_; }
    size_t vocabSize() const { return pieces_.size(); }

private:
    std::vector<Piece> pieces_;
    std::unordered_map<std::string, int32_t> exact_;
    std::vector<int32_t> special_ids_;
    int32_t bos_id_ = 1;
    int32_t eos_id_ = 2;
    int32_t unk_id_ = 0;
    bool model_add_bos_ = true;

    std::vector<int32_t> encodeNormalSpan(const std::string& utf8) const;
    bool matchSpecial(const std::string& text, size_t pos, int32_t& id, size_t& bytes) const;
};

} // namespace rawrxd::parity
