#pragma once
#include "cpp_scan.hpp"
#include <map>
#include <set>
#include <string>
#include <vector>
namespace rawr::product {

struct GraphEdge {
    std::string from;
    std::string to;
    std::string kind; // include|call
};

struct SymbolGraph {
    std::map<std::string, Sym> nodes;
    std::vector<GraphEdge> edges;

    void add(const Sym& s) {
        std::string k = s.kind + ":" + s.name + "@" + s.file;
        nodes[k] = s;
    }

    void link(const std::string& a, const std::string& b, const char* kind) {
        edges.push_back(GraphEdge{a, b, kind ? kind : "call"});
    }

    std::vector<std::string> neighbors(const std::string& name) const {
        std::vector<std::string> out;
        for (const auto& e : edges)
            if (e.from == name) out.push_back(e.to);
        return out;
    }
};

inline SymbolGraph BuildGraph(const std::vector<Sym>& syms) {
    SymbolGraph g;
    std::set<std::string> fns;
    for (const auto& s : syms) {
        g.add(s);
        if (s.kind == "fn") fns.insert(s.name);
    }
    for (const auto& s : syms) {
        if (s.kind == "include") g.link(s.file, s.name, "include");
        if (s.kind == "fn") {
            for (const auto& other : fns)
                if (other != s.name && s.name.find(other) != std::string::npos)
                    g.link(s.name, other, "call");
        }
    }
    return g;
}

} // namespace rawr::product
