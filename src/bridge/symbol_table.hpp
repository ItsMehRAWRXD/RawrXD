// symbol_table.hpp — Symbol table for IDE bridge
#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>

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
    void add(const std::string& file, const SymbolEntry& entry) {
        entries_[file].push_back(entry);
    }

    std::vector<SymbolEntry> query(const std::string& file, const std::string& prefix) const {
        auto it = entries_.find(file);
        if (it == entries_.end()) {
            return {};
        }

        std::vector<SymbolEntry> result;
        for (const auto& entry : it->second) {
            if (entry.name.compare(0, prefix.size(), prefix) == 0) {
                result.push_back(entry);
            }
        }
        return result;
    }

    std::vector<SymbolEntry> queryAll(const std::string& prefix) const {
        std::vector<SymbolEntry> result;
        for (const auto& [file, entries] : entries_) {
            for (const auto& entry : entries) {
                if (entry.name.compare(0, prefix.size(), prefix) == 0) {
                    result.push_back(entry);
                }
            }
        }
        return result;
    }

    size_t size() const {
        size_t count = 0;
        for (const auto& [file, entries] : entries_) {
            count += entries.size();
        }
        return count;
    }

private:
    std::unordered_map<std::string, std::vector<SymbolEntry>> entries_;
};

} // namespace bridge
} // namespace rawrxd
