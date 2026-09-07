#pragma once
#include "file_window.hpp"
#include "token_budget.hpp"
#include <algorithm>
#include <string>
#include <vector>
namespace rawr::product {

enum class CtxPri : uint8_t { Crit = 0, High = 1, Med = 2, Low = 3 };

struct CtxItem {
    CtxPri pri = CtxPri::Med;
    std::string kind;
    std::string source;
    std::string text;
    uint32_t tokens = 0;
};

inline uint32_t RankScore(const CtxItem& it, const EditorSnap& e) {
    uint32_t s = 100u - (uint32_t)it.pri * 20u;
    if (it.source == e.path) s += 40;
    if (it.kind == "cursor" || it.kind == "diag") s += 30;
    if (it.kind == "import" || it.kind == "symbol") s += 10;
    return s;
}

inline void RankItems(std::vector<CtxItem>& items, const EditorSnap& e) {
    std::sort(items.begin(), items.end(), [&](const CtxItem& a, const CtxItem& b) {
        return RankScore(a, e) > RankScore(b, e);
    });
}

inline std::vector<CtxItem> PackBudget(const std::vector<CtxItem>& ranked,
                                       TokenBudget& bud) {
    std::vector<CtxItem> out;
    for (const auto& it : ranked) {
        uint32_t t = it.tokens ? it.tokens : EstTokens(it.text);
        if (!bud.take(t)) continue;
        out.push_back(it);
        out.back().tokens = t;
    }
    return out;
}

} // namespace rawr::product
