// ============================================================================
// SymbolTable.hpp - Symbol Database
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>
#include <functional>

namespace RawrXD {
namespace IDE {

enum class SymbolKind {
    Unknown, Namespace, Class, Struct, Enum,
    Function, Method, Variable, Field, Parameter,
    Template, Concept, Macro, Typedef, Using
};

struct SymbolLocation {
    std::string filePath;
    size_t line;
    size_t column;
    size_t length;
};

struct SymbolInfo {
    std::string name;
    std::string qualifiedName;
    SymbolKind kind;
    SymbolLocation location;
    std::string type;
    std::string signature;
    std::string parentScope;
    std::vector<std::string> modifiers;
    std::string documentation;
    std::vector<SymbolLocation> references;
    std::vector<std::string> children;
};

class SymbolTable {
public:
    SymbolTable();
    ~SymbolTable();

    void Insert(const SymbolInfo& symbol);
    void Remove(const std::string& name, const std::string& filePath);
    void RemoveFile(const std::string& filePath);
    void Clear();

    std::vector<SymbolInfo> Lookup(const std::string& name) const;
    std::vector<SymbolInfo> LookupInScope(const std::string& scope) const;
    std::vector<SymbolInfo> GetChildren(const std::string& parentName) const;
    std::vector<SymbolInfo> GetSymbolsInFile(const std::string& filePath) const;
    std::vector<SymbolInfo> GetSymbolsByKind(SymbolKind kind) const;
    std::vector<SymbolInfo> GetAllSymbols() const;

    void AddReference(const std::string& symbolName, const SymbolLocation& ref);
    std::vector<SymbolLocation> GetReferences(const std::string& symbolName) const;

    size_t GetSymbolCount() const;
    size_t GetReferenceCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
