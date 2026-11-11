// ============================================================================
// SearchTools.hpp - Code Search and Semantic Search Tools
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <regex>

namespace Sovereign {

// Search result
struct SearchResult {
    std::string file;
    int line;
    int column;
    std::string content;
    std::string context;
    float relevance;
};

// Search configuration
struct SearchConfig {
    bool caseSensitive = false;
    bool useRegex = false;
    bool wholeWord = false;
    size_t maxResults = 100;
    size_t contextLines = 2;
    std::vector<std::string> includePatterns;
    std::vector<std::string> excludePatterns;
    std::vector<std::string> searchPaths;
};

// Code search tools
class SearchTools {
public:
    SearchTools();
    ~SearchTools();

    // Text search
    std::vector<SearchResult> SearchText(const std::string& query, const SearchConfig& config = {});
    std::vector<SearchResult> SearchTextInFile(const std::string& file, const std::string& query, 
                                                const SearchConfig& config = {});

    // File search
    std::vector<std::string> SearchFiles(const std::string& pattern, const std::string& root = "");
    std::vector<std::string> SearchFilesByExtension(const std::string& ext, const std::string& root = "");

    // Symbol search
    std::vector<SearchResult> SearchSymbol(const std::string& symbol, const std::string& root = "");
    std::vector<SearchResult> SearchFunction(const std::string& name, const std::string& root = "");
    std::vector<SearchResult> SearchClass(const std::string& name, const std::string& root = "");

    // Semantic search (simplified)
    std::vector<SearchResult> SemanticSearch(const std::string& query, const std::string& root = "",
                                              size_t maxResults = 10);

    // Grep-like search
    std::vector<SearchResult> Grep(const std::string& pattern, const std::string& root = "",
                                    const SearchConfig& config = {});

    // Find references
    std::vector<SearchResult> FindReferences(const std::string& symbol, const std::string& root = "");

    // Find definitions
    std::vector<SearchResult> FindDefinitions(const std::string& symbol, const std::string& root = "");

    // Index management
    void BuildIndex(const std::string& root);
    void UpdateIndex(const std::string& file);
    void ClearIndex();

    // Statistics
    size_t GetIndexedFileCount() const;
    size_t GetIndexedSymbolCount() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl;
    
    std::vector<std::string> GetSearchRoots(const std::string& root) const;
    std::vector<std::string> GetFiles(const std::string& root, const SearchConfig& config) const;
    bool MatchesPattern(const std::string& file, const std::vector<std::string>& patterns) const;
    std::string ReadFileContent(const std::string& path) const;
};

} // namespace Sovereign
