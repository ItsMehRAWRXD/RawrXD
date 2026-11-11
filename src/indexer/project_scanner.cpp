#include "project_scanner.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <set>

namespace rawrxd {
namespace indexer {

ProjectScanner::ProjectScanner() = default;
ProjectScanner::~ProjectScanner() = default;

bool ProjectScanner::scanDirectory(const std::string& root_path) {
    files_.clear();
    extensions_.clear();
    std::set<std::string> ext_set;

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(root_path)) {
            if (!entry.is_regular_file()) continue;

            IndexedFile file;
            file.path = entry.path().string();
            file.extension = entry.path().extension().string();
            file.size = entry.file_size();
            file.last_modified = std::filesystem::last_write_time(entry.path()).time_since_epoch().count();

            // Compute simple hash
            std::ifstream f(file.path);
            if (f) {
                std::stringstream buf;
                buf << f.rdbuf();
                file.hash = std::to_string(std::hash<std::string>{}(buf.str()));
            }

            files_.push_back(file);
            ext_set.insert(file.extension);
        }
    } catch (const std::exception& e) {
        std::cerr << "[ProjectScanner] Error scanning: " << e.what() << std::endl;
        return false;
    }

    extensions_.assign(ext_set.begin(), ext_set.end());
    std::cout << "[ProjectScanner] Scanned " << files_.size() << " files, "
              << extensions_.size() << " extensions" << std::endl;
    return true;
}

std::vector<IndexedFile> ProjectScanner::getFiles() const { return files_; }
std::vector<std::string> ProjectScanner::getExtensions() const { return extensions_; }

// SymbolIndex
SymbolIndex::SymbolIndex() = default;
SymbolIndex::~SymbolIndex() = default;

void SymbolIndex::addSymbol(const CodeSymbol& symbol) {
    symbols_.push_back(symbol);
}

std::vector<CodeSymbol> SymbolIndex::findByName(const std::string& name) const {
    std::vector<CodeSymbol> results;
    for (const auto& s : symbols_) {
        if (s.name == name || s.qualified_name == name) {
            results.push_back(s);
        }
    }
    return results;
}

std::vector<CodeSymbol> SymbolIndex::findByFile(const std::string& file) const {
    std::vector<CodeSymbol> results;
    for (const auto& s : symbols_) {
        if (s.file == file) {
            results.push_back(s);
        }
    }
    return results;
}

std::vector<CodeSymbol> SymbolIndex::findByKind(const std::string& kind) const {
    std::vector<CodeSymbol> results;
    for (const auto& s : symbols_) {
        if (s.kind == kind) {
            results.push_back(s);
        }
    }
    return results;
}

std::vector<CodeSymbol> SymbolIndex::search(const std::string& query) const {
    std::vector<CodeSymbol> results;
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(), lower_query.begin(), ::tolower);

    for (const auto& s : symbols_) {
        std::string lower_name = s.name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
        if (lower_name.find(lower_query) != std::string::npos) {
            results.push_back(s);
        }
    }
    return results;
}

size_t SymbolIndex::count() const { return symbols_.size(); }

// DependencyGraph
DependencyGraph::DependencyGraph() = default;
DependencyGraph::~DependencyGraph() = default;

void DependencyGraph::addEdge(const DependencyEdge& edge) {
    edges_.push_back(edge);
}

std::vector<std::string> DependencyGraph::getDependencies(const std::string& file) const {
    std::vector<std::string> deps;
    for (const auto& e : edges_) {
        if (e.from_file == file) {
            deps.push_back(e.to_file);
        }
    }
    return deps;
}

std::vector<std::string> DependencyGraph::getDependents(const std::string& file) const {
    std::vector<std::string> deps;
    for (const auto& e : edges_) {
        if (e.to_file == file) {
            deps.push_back(e.from_file);
        }
    }
    return deps;
}

bool DependencyGraph::hasCycle() const {
    // Simple DFS cycle detection
    std::set<std::string> visited;
    std::set<std::string> in_stack;

    std::function<bool(const std::string&)> dfs = [&](const std::string& node) -> bool {
        visited.insert(node);
        in_stack.insert(node);

        for (const auto& e : edges_) {
            if (e.from_file == node) {
                if (in_stack.count(e.to_file)) return true;
                if (!visited.count(e.to_file)) {
                    if (dfs(e.to_file)) return true;
                }
            }
        }

        in_stack.erase(node);
        return false;
    };

    for (const auto& e : edges_) {
        if (!visited.count(e.from_file)) {
            if (dfs(e.from_file)) return true;
        }
    }
    return false;
}

// ContextBuilder
ContextBuilder::ContextBuilder() = default;
ContextBuilder::~ContextBuilder() = default;

void ContextBuilder::setScanner(std::shared_ptr<ProjectScanner> scanner) { scanner_ = scanner; }
void ContextBuilder::setSymbolIndex(std::shared_ptr<SymbolIndex> index) { symbol_index_ = index; }
void ContextBuilder::setDependencyGraph(std::shared_ptr<DependencyGraph> graph) { dep_graph_ = graph; }

std::string ContextBuilder::buildContext(const std::string& query, size_t max_tokens) {
    std::string context;

    // Add project overview
    if (scanner_) {
        auto files = scanner_->getFiles();
        context += "Project has " + std::to_string(files.size()) + " files.\n";
    }

    // Add relevant symbols
    if (symbol_index_) {
        auto symbols = symbol_index_->search(query);
        if (!symbols.empty()) {
            context += "Relevant symbols (" + std::to_string(symbols.size()) + "):\n";
            for (const auto& s : symbols) {
                context += "  " + s.kind + " " + s.name + " in " + s.file + ":" +
                          std::to_string(s.line) + "\n";
            }
        }
    }

    // Truncate to max_tokens (approximate)
    if (context.size() > max_tokens * 4) {
        context = context.substr(0, max_tokens * 4);
    }

    return context;
}

std::string ContextBuilder::buildFileContext(const std::string& file_path) {
    std::ifstream file(file_path);
    if (!file) return "";

    std::stringstream buf;
    buf << file.rdbuf();
    return buf.str();
}

} // namespace indexer
} // namespace rawrxd
