#pragma once
#include "symbol_graph.hpp"
#include <set>
#include <string>
#include <vector>
namespace rawr::product {

struct Impact {
    std::string file;
    std::vector<std::string> direct;
    std::vector<std::string> tests;
    int risk = 0;
};

inline Impact AnalyzeImpact(const SymbolGraph& g, const std::string& file) {
    Impact im;
    im.file = file;
    std::set<std::string> seen;
    for (const auto& e : g.edges) {
        if (e.from == file || e.to == file) {
            std::string other = e.from == file ? e.to : e.from;
            if (seen.insert(other).second) im.direct.push_back(other);
        }
    }
    for (const auto& n : im.direct) {
        if (n.find("test") != std::string::npos ||
            n.find("cert") != std::string::npos)
            im.tests.push_back(n);
    }
    im.risk = (int)im.direct.size() * 8;
    if (im.risk > 100) im.risk = 100;
    return im;
}

} // namespace rawr::product
