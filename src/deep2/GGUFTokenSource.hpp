#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>

namespace RawrXD {

class GGUFTokenSource {
public:
    bool Initialize(
        const std::vector<std::string>& tokens,
        int32_t bos,
        int32_t eos)
    {
        tokens_ = tokens;
        bos_ = bos;
        eos_ = eos;

        lookup_.clear();
        lookup_.reserve(tokens_.size() * 2 + 1);

        for (uint32_t i = 0;
             i < static_cast<uint32_t>(tokens_.size());
             ++i) {

            if (lookup_.find(tokens_[i]) == lookup_.end())
                lookup_.emplace(tokens_[i], i);
        }

        return !tokens_.empty();
    }

    bool Empty() const noexcept {
        return tokens_.empty();
    }

    size_t Size() const noexcept {
        return tokens_.size();
    }

    const std::string& Decode(uint32_t id) const {
        static const std::string empty;

        if (id >= tokens_.size())
            return empty;

        return tokens_[id];
    }

    int32_t BOS() const noexcept {
        return bos_;
    }

    int32_t EOS() const noexcept {
        return eos_;
    }

    int32_t Find(std::string_view value) const {
        auto it = lookup_.find(std::string(value));

        if (it == lookup_.end())
            return -1;

        return static_cast<int32_t>(it->second);
    }

private:
    std::vector<std::string> tokens_;
    std::unordered_map<std::string, uint32_t> lookup_;

    int32_t bos_ = -1;
    int32_t eos_ = -1;
};

} // namespace RawrXD
