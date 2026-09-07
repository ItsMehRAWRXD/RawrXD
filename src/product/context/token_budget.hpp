#pragma once
#include "../abi/runtime_abi.hpp"
#include <cstdint>
#include <string>
namespace rawr::product {

struct TokenBudget {
    uint32_t maxTokens = 4096;
    uint32_t reservedOut = 1024;
    uint32_t used = 0;
    uint32_t available() const {
        if (used + reservedOut >= maxTokens) return 0;
        return maxTokens - reservedOut - used;
    }
    bool fit(uint32_t t) const { return t <= available(); }
    bool take(uint32_t t) {
        if (!fit(t)) return false;
        used += t;
        return true;
    }
};

inline uint32_t EstTokens(const std::string& s) {
    return RawrTokenEst((uint32_t)s.size());
}

} // namespace rawr::product
