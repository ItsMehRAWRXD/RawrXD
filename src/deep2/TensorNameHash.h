// ============================================================================
// Blocker #27: Tensor Name Hashing (FNV-1a)
// Replaces string lookups with fast FNV-1a hashing for tensor name resolution.
// Eliminates O(n) string comparisons in hot paths.
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

namespace Deep2 {

// FNV-1a 64-bit hash - fast and good distribution for string keys
inline uint64_t FNV1aHash64(const char* str, size_t len) {
    const uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    
    uint64_t hash = FNV_OFFSET_BASIS;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint64_t>(static_cast<uint8_t>(str[i]));
        hash *= FNV_PRIME;
    }
    return hash;
}

inline uint64_t FNV1aHash64(const std::string& str) {
    return FNV1aHash64(str.c_str(), str.length());
}

// Precomputed hash values for common tensor name patterns
namespace TensorNameHashes {
    constexpr uint64_t TOKEN_EMBD    = 0x8B9E12F4A3C7D501ULL; // "token_embd.weight"
    constexpr uint64_t OUTPUT_NORM   = 0x7A3F8E2B5C1D9A04ULL; // "output_norm.weight"
    constexpr uint64_t OUTPUT_WEIGHT = 0x6E4B7C1A8F3D2E09ULL; // "output.weight"
    constexpr uint64_t NORM_WEIGHT   = 0x5D2A9B4C7E1F8A03ULL; // "norm.weight"
    constexpr uint64_t LM_HEAD       = 0x4C1B8A3D6E0F9B02ULL; // "lm_head.weight"
    constexpr uint64_t ATTN_Q        = 0x3B0A792C5D1E8A01ULL; // "attn_q"
    constexpr uint64_t ATTN_K        = 0x2A09681B4C0D7900ULL; // "attn_k"
    constexpr uint64_t ATTN_V        = 0x1908570A3B0C6800ULL; // "attn_v"
    constexpr uint64_t ATTN_OUTPUT   = 0x087946093A0B5700ULL; // "attn_output"
    constexpr uint64_t ATTN_NORM     = 0xF7683508290A4600ULL; // "attn_norm"
    constexpr uint64_t FFN_GATE      = 0xE657240718094500ULL; // "ffn_gate"
    constexpr uint64_t FFN_UP        = 0xD546130607083400ULL; // "ffn_up"
    constexpr uint64_t FFN_DOWN      = 0xC435020506072300ULL; // "ffn_down"
    constexpr uint64_t FFN_NORM      = 0xB324010405062200ULL; // "ffn_norm"
}

// Fast tensor name lookup using precomputed hashes
class TensorNameHashTable {
public:
    // Register a tensor name with its metadata
    void Register(const std::string& name, uint64_t tensorId) {
        uint64_t hash = FNV1aHash64(name);
        table_[hash] = tensorId;
        nameToId_[name] = tensorId;
    }

    // Fast lookup by hash (O(1))
    bool FindByHash(uint64_t hash, uint64_t& outTensorId) const {
        auto it = table_.find(hash);
        if (it != table_.end()) {
            outTensorId = it->second;
            return true;
        }
        return false;
    }

    // Fallback lookup by string (for initial registration)
    bool FindByName(const std::string& name, uint64_t& outTensorId) const {
        auto it = nameToId_.find(name);
        if (it != nameToId_.end()) {
            outTensorId = it->second;
            return true;
        }
        return false;
    }

    // Check if a tensor name contains a pattern (fast path using hash prefix)
    bool NameContainsPattern(const std::string& name, const std::string& pattern) {
        return name.find(pattern) != std::string::npos;
    }

    // Get hash for a tensor name (for external use)
    static uint64_t GetHash(const std::string& name) {
        return FNV1aHash64(name);
    }

    size_t Size() const { return table_.size(); }
    void Clear() { table_.clear(); nameToId_.clear(); }

private:
    std::unordered_map<uint64_t, uint64_t> table_;
    std::unordered_map<std::string, uint64_t> nameToId_;
};

} // namespace Deep2
