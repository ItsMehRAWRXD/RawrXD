// ============================================================================
// ContextEngine.hpp - Workspace Intelligence and Symbol Indexing
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <functional>

namespace Sovereign {

// Symbol types for code indexing
enum class SymbolType {
    FUNCTION,
    CLASS,
    STRUCT,
    ENUM,
    VARIABLE,
    TYPEDEF,
    MACRO,
    NAMESPACE,
    UNKNOWN
};

// Symbol representation
struct Symbol {
    std::string name;
    std::string qualifiedName;
    SymbolType type;
    std::string filePath;
    size_t lineNumber;
    size_t column;
    std::string signature;
    std::string documentation;
    std::vector<std::string> parameters;
    std::string returnType;
    std::vector<std::string> references;
};

// File metadata
struct FileInfo {
    std::string path;
    size_t size;
    uint64_t lastModified;
    std::string hash;
    std::string language;
    bool isIndexed;
};

// Dependency graph edge
struct Dependency {
    std::string from;
    std::string to;
    std::string type; // include, call, inherit, etc.
};

// Context selection result
struct ContextSelection {
    std::vector<std::string> files;
    std::vector<Symbol> symbols;
    std::string summary;
    size_t estimatedTokens;
};

// Main Context Engine
class ContextEngine {
public:
    ContextEngine();
    ~ContextEngine();

    // Workspace scanning
    void ScanWorkspace(const std::string& rootPath);
    void ScanFile(const std::string& filePath);
    void RemoveFile(const std::string& filePath);
    void UpdateFile(const std::string& filePath);

    // Symbol indexing
    void IndexSymbol(const Symbol& symbol);
    void IndexSymbols(const std::vector<Symbol>& symbols);
    std::vector<Symbol> FindSymbols(const std::string& query);
    std::vector<Symbol> FindSymbolsByType(SymbolType type);
    std::optional<Symbol> FindSymbolByName(const std::string& name);
    std::vector<Symbol> FindReferences(const std::string& symbolName);

    // Dependency tracking
    void AddDependency(const Dependency& dep);
    std::vector<std::string> GetDependencies(const std::string& file);
    std::vector<std::string> GetDependents(const std::string& file);
    std::vector<std::vector<std::string>> FindCycles();

    // Context selection for model
    ContextSelection SelectContext(const std::string& task, size_t tokenBudget);
    ContextSelection SelectContextForSymbol(const std::string& symbolName, size_t tokenBudget);

    // Semantic search
    std::vector<Symbol> SemanticSearch(const std::string& query, size_t topK = 10);

    // Call graph
    std::vector<std::string> GetCallers(const std::string& function);
    std::vector<std::string> GetCallees(const std::string& function);
    std::vector<std::vector<std::string>> GetCallPaths(const std::string& from, const std::string& to);

    // Statistics
    size_t GetIndexedFileCount() const;
    size_t GetSymbolCount() const;
    size_t GetDependencyCount() const;

    // Persistence
    void SaveIndex(const std::string& path);
    void LoadIndex(const std::string& path);

    // Incremental updates
    void StartWatching();
    void StopWatching();

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// Language-specific parsers
class ILanguageParser {
public:
    virtual ~ILanguageParser() = default;
    virtual std::vector<Symbol> Parse(const std::string& filePath, const std::string& content) = 0;
    virtual std::vector<Dependency> ParseDependencies(const std::string& content) = 0;
    virtual std::string GetLanguage() const = 0;
};

// C/C++ Parser
class CppParser : public ILanguageParser {
public:
    std::vector<Symbol> Parse(const std::string& filePath, const std::string& content) override;
    std::vector<Dependency> ParseDependencies(const std::string& content) override;
    std::string GetLanguage() const override { return "cpp"; }
};

// Python Parser
class PythonParser : public ILanguageParser {
public:
    std::vector<Symbol> Parse(const std::string& filePath, const std::string& content) override;
    std::vector<Dependency> ParseDependencies(const std::string& content) override;
    std::string GetLanguage() const override { return "python"; }
};

} // namespace Sovereign
