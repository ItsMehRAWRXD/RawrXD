// rust_parser.hpp — Stub for build compatibility
#pragma once
#include <string>
#include <vector>

namespace rawrxd {
namespace parser {

struct Symbol {
    std::string name;
    std::string kind;
    size_t line = 0;
    size_t column = 0;
};

struct ParseResult {
    std::vector<Symbol> symbols;
    bool success = false;
};

inline ParseResult parseRust(const std::string& /*source*/) {
    return ParseResult{};
}

} // namespace parser

namespace ast {

struct Symbol {
    std::string name;
    std::string kind;
    size_t line = 0;
    size_t column = 0;
    bool is_public = true;
};

class SymbolTable {
public:
    std::vector<Symbol> symbols;
    void add(const Symbol& s) { symbols.push_back(s); }
};

} // namespace ast
} // namespace rawrxd
