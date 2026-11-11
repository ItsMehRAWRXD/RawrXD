// ============================================================================
// SearchIndex.hpp - Full-Text Search Index
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>

namespace RawrXD {
namespace IDE {

struct SearchResult {
    std::string filePath;
    size_t line;
    size_t column;
    size_t length;
    std::string lineContent;
    std::string context;
    float score;
};

class SearchIndex {
public:
    SearchIndex();
    ~SearchIndex();

    void IndexFile(const std::string& filePath);
    void RemoveFile(const std::string& filePath);
    
    std::vector<SearchResult> Search(const std::string& query, size_t maxResults = 50);
    std::vector<SearchResult> RegexSearch(const std::string& pattern, size_t maxResults = 50);
    std::vector<SearchResult> FuzzySearch(const std::string& query, size_t maxResults = 20);
    
    void Clear();
    size_t GetDocumentCount() const;
    size_t GetTokenCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
