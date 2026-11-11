// symbol_table.hpp — Stub for build compatibility
#pragma once
#include <string>
#include <vector>
#include <unordered_map>

namespace rawrxd {
namespace bridge {

struct SymbolEntry {
    std::string name;
    std::string kind;
    size_t line = 0;
    size_t column = 0;
};

class SymbolTable {
public:
    void add(const std::string& file, const SymbolEntry& entry) {}
    std::vector<SymbolEntry> query(const std::string& file, const std::string& prefix) const {
        return {};
    }
};

} // namespace bridge
} // namespace rawrxd
