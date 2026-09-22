#pragma once
#include "Common.hpp"
#include <span>

namespace rawrxd::closure {

struct ContextCandidate {
    std::string id;
    std::string path;
    std::string text;
    uint32_t token_estimate{};
    double lexical_score{};
    double symbol_score{};
    double recency_score{};
    bool dirty_buffer{};
};

struct ContextSelection {
    std::vector<size_t> indices;
    uint32_t estimated_tokens{};
};

class ContextPlanner {
public:
    static ContextSelection select(std::span<const ContextCandidate> candidates,
                                   uint32_t token_budget);
};

} // namespace rawrxd::closure
