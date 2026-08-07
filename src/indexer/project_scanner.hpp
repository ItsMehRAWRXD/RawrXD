#pragma once

#include <string>
#include <vector>
#include <functional>
#include <filesystem>

namespace rawrxd {
namespace indexer {

struct IndexedFile {
    std::string path;
    std::string extension;
    uint64_t size;
    uint64_t last_modified;
    std::string hash;
};

struct CodeSymbol {
    std::string name;
    std::string qualified_name;
    std::string kind;       // "function", "class", "variable", "namespace", etc.
    std::string file;
    uint32_t line;
    uint32_t column;
    std::vector<std::string> references;
};

struct DependencyEdge {
    std::string from_file;
    std::string to_file;
    std::string kind;       // "include", "import", "using"
};

class ProjectScanner {
public:
    ProjectScanner();
    ~ProjectScanner();

    bool scanDirectory(const std::string& root_path);
    std::vector<IndexedFile> getFiles() const;
    std::vector<std::string> getExtensions() const;

private:
    std::vector<IndexedFile> files_;
    std::vector<std::string> extensions_;
};

class SymbolIndex {
public:
    SymbolIndex();
    ~SymbolIndex();

    void addSymbol(const CodeSymbol& symbol);
    std::vector<CodeSymbol> findByName(const std::string& name) const;
    std::vector<CodeSymbol> findByFile(const std::string& file) const;
    std::vector<CodeSymbol> findByKind(const std::string& kind) const;
    std::vector<CodeSymbol> search(const std::string& query) const;
    size_t count() const;

private:
    std::vector<CodeSymbol> symbols_;
};

class DependencyGraph {
public:
    DependencyGraph();
    ~DependencyGraph();

    void addEdge(const DependencyEdge& edge);
    std::vector<std::string> getDependencies(const std::string& file) const;
    std::vector<std::string> getDependents(const std::string& file) const;
    bool hasCycle() const;

private:
    std::vector<DependencyEdge> edges_;
};

class ContextBuilder {
public:
    ContextBuilder();
    ~ContextBuilder();

    void setScanner(std::shared_ptr<ProjectScanner> scanner);
    void setSymbolIndex(std::shared_ptr<SymbolIndex> index);
    void setDependencyGraph(std::shared_ptr<DependencyGraph> graph);

    std::string buildContext(const std::string& query, size_t max_tokens);
    std::string buildFileContext(const std::string& file_path);

private:
    std::shared_ptr<ProjectScanner> scanner_;
    std::shared_ptr<SymbolIndex> symbol_index_;
    std::shared_ptr<DependencyGraph> dep_graph_;
};

} // namespace indexer
} // namespace rawrxd
