#pragma once
#include <cstdint>
#include <limits>
#include <string_view>

namespace Deep2 { namespace ReapBank {
// Uniform expert bank across the entire checkpoint, not per shard. Dense-only
// shards are valid and never reset the count collected from earlier shards.
struct Contract {
    uint32_t original = 0;
    uint32_t topK = 0;
    bool ObserveAxis(uint64_t axis) noexcept {
        if (!axis || axis > std::numeric_limits<uint32_t>::max() ||
            (original && original != axis)) return false;
        original = static_cast<uint32_t>(axis);
        return true;
    }
    bool ObserveTopK(uint64_t count) noexcept {
        if (!count || count > std::numeric_limits<uint32_t>::max() ||
            (topK && topK != count)) return false;
        topK = static_cast<uint32_t>(count);
        return true;
    }
    bool Allows(uint32_t retained) const noexcept {
        return original && retained && retained <= original &&
            (!topK || (topK <= original && retained >= topK));
    }
};
inline bool HasField(std::string_view key, std::string_view field) noexcept {
    if (key.size() <= field.size()) return false;
    const auto start = key.size() - field.size();
    return key[start-1] == '.' && key.substr(start) == field;
}
} } // namespace Deep2::ReapBank
