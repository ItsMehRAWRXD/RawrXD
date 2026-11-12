#pragma once
// Shared Project RAG / semantic index (C53) — local-first TF index.
#include <string>
#include <vector>

namespace RawrXD {
namespace Search {

struct SearchResult {
    std::string filePath;
    float relevanceScore = 0.0f;
    std::string matchedExcerpt;
    size_t lineNumber = 0;
};

void IndexProjectFile(const std::string& filePath, const std::string& content);
std::vector<SearchResult> SearchProject(const std::string& query, size_t maxResults = 10);

}  // namespace Search
}  // namespace RawrXD
