// rawr_context_compactor.hpp — keep last N turns / budget chars
#pragma once
#include <string>
#include <vector>

namespace rawr::style {

struct CompactTurn {
    std::string role;
    std::string content;
};

inline std::vector<CompactTurn>
CompactTurns(const std::vector<CompactTurn>& in, size_t keepLast,
             size_t maxChars) {
    std::vector<CompactTurn> out;
    size_t start = in.size() > keepLast ? in.size() - keepLast : 0;
    size_t used = 0;
    for (size_t i = start; i < in.size(); ++i) {
        size_t n = in[i].content.size() + in[i].role.size() + 2;
        if (used + n > maxChars && !out.empty()) break;
        out.push_back(in[i]);
        used += n;
    }
    return out;
}

inline std::string CompactSummary(const std::vector<CompactTurn>& dropped) {
    if (dropped.empty()) return {};
    return "[compacted " + std::to_string(dropped.size()) + " earlier turns]";
}

} // namespace rawr::style
