// ============================================================================
// SearchPanel.hpp - Search Panel for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

struct SearchQuery {
    std::string text;
    std::string path;
    bool caseSensitive = false;
    bool wholeWord = false;
    bool useRegex = false;
    bool includeHidden = false;
    size_t maxResults = 1000;
    std::vector<std::string> includePatterns;
    std::vector<std::string> excludePatterns;
};

struct SearchMatch {
    std::string file;
    int line;
    int column;
    std::string content;
    std::string lineContent;
    float relevance;
};

struct SearchResult {
    std::string file;
    std::vector<SearchMatch> matches;
    size_t totalMatches;
    double searchTimeMs;
};

class SearchPanel {
public:
    SearchPanel();
    ~SearchPanel();

    bool Initialize();
    void Shutdown();

    SearchResult Search(const SearchQuery& query);
    SearchResult SearchInFiles(const SearchQuery& query, const std::vector<std::string>& files);
    SearchResult SearchInWorkspace(const SearchQuery& query, const std::string& workspaceRoot);

    void SetResultCallback(std::function<void(const SearchResult&)> callback);
    void SetProgressCallback(std::function<void(double)> callback);

    void ClearResults();
    std::vector<SearchResult> GetHistory() const { return history_; }

    struct SearchStats {
        uint64_t totalSearches;
        uint64_t totalResults;
        double avgSearchTimeMs;
    };
    SearchStats GetStats() const { return stats_; }

private:
    std::vector<SearchResult> history_;
    SearchStats stats_;
    std::function<void(const SearchResult&)> resultCallback_;
    std::function<void(double)> progressCallback_;
    mutable std::mutex mutex_;
    
    std::vector<std::string> GetFiles(const std::string& root, const SearchQuery& query) const;
    bool MatchesPattern(const std::string& file, const std::vector<std::string>& patterns) const;
};

} // namespace Sovereign
