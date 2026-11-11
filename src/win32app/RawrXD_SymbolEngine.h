#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace RawrXD::SymbolEngine {

class Symbol;

using SymbolPtr = std::shared_ptr<Symbol>;

class Symbol {
public:
    UINT64 id = 0;
    std::vector<SymbolPtr> children;
};

class SymbolDatabase {
public:
    std::vector<SymbolPtr> SearchWorkspace(std::wstring_view query, int maxResults) const;
    SymbolPtr FindById(UINT64 id) const;
    std::vector<SymbolPtr> GetSymbolsAtLine(std::wstring_view uri, UINT line) const;
    void IndexDocument(std::wstring_view uri, SymbolPtr root);
    SymbolPtr GetDocumentRoot(std::wstring_view uri) const;
    void removeFromWorkspaceIndex(const SymbolPtr& sym);
};

SymbolDatabase& GlobalSymbolDatabase();

} // namespace RawrXD::SymbolEngine
