#pragma once
#include "../abi/runtime_abi.hpp"
#include "cpp_scan.hpp"
#include <algorithm>
#include <string>
#include <vector>
namespace rawr::product {

struct Hit {
    std::string name;
    std::string file;
    std::string kind;
    int line = 0;
    uint32_t score = 0;
};

inline uint32_t ScoreHit(const Sym& s, const std::string& q) {
    uint32_t sc = 0;
    if (s.name == q) sc += 100;
    else if (s.name.find(q) != std::string::npos) sc += 40;
    if (s.kind == "fn") sc += 8;
    if (s.kind == "class") sc += 6;
    uint32_t h = RawrFnv1a32(s.name.data(), (uint32_t)s.name.size());
    sc += (h & 7);
    return sc;
}

inline std::vector<Hit> HybridSearch(const std::vector<Sym>& syms,
                                     const std::string& query, int limit = 16) {
    std::vector<Hit> out;
    if (query.empty()) return out;
    for (const auto& s : syms) {
        uint32_t sc = ScoreHit(s, query);
        if (sc < 8) continue;
        Hit h{s.name, s.file, s.kind, s.line, sc};
        out.push_back(h);
    }
    std::sort(out.begin(), out.end(),
              [](const Hit& a, const Hit& b) { return a.score > b.score; });
    if ((int)out.size() > limit) out.resize((size_t)limit);
    return out;
}

} // namespace rawr::product
