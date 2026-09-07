#pragma once
#include "../context/priority_ranker.hpp"
#include "hybrid_search.hpp"
#include "repo_scanner.hpp"
#include "symbol_graph.hpp"
namespace rawr::product {

inline std::vector<CtxItem> SymbolsToContext(const std::vector<Hit>& hits) {
    std::vector<CtxItem> items;
    for (const auto& h : hits) {
        CtxPri p = h.score >= 80 ? CtxPri::High : CtxPri::Med;
        std::string t = h.kind + " " + h.name + " L" + std::to_string(h.line);
        items.push_back(CtxItem{p, "symbol", h.file, t, 0});
    }
    return items;
}

} // namespace rawr::product
