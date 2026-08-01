// ============================================================================
// SearchIndex.cpp - Full-Text Search Index
// WORKING IMPLEMENTATION
// ============================================================================

#include "SearchIndex.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>
#include <set>

namespace RawrXD {
namespace IDE {

struct SearchIndex::Impl {
    // Inverted index: token -> list of (filePath, line, column, length)
    std::unordered_map<std::string, std::vector<std::tuple<std::string, size_t, size_t, size_t>>> index_;
    
    // File content cache
    std::unordered_map<std::string, std::vector<std::string>> fileLines_;
    
    // Token statistics
    size_t totalTokens_ = 0;
    size_t totalDocuments_ = 0;
    
    mutable std::shared_mutex mutex_;
    
    // Tokenize text into words
    std::vector<std::string> Tokenize(const std::string& text) {
        std::vector<std::string> tokens;
        std::string current;
        
        for (char c : text) {
            if (isalnum(c) || c == '_') {
                current += tolower(c);
            } else {
                if (current.length() >= 2) {
                    tokens.push_back(current);
                }
                current.clear();
            }
        }
        if (current.length() >= 2) {
            tokens.push_back(current);
        }
        
        return tokens;
    }
    
    // Compute TF-IDF score
    float ComputeScore(const std::string& token, const std::string& filePath) {
        auto& occurrences = index_[token];
        
        // Term frequency in this document
        size_t tf = 0;
        for (const auto& [fp, line, col, len] : occurrences) {
            if (fp == filePath) tf++;
        }
        
        // Inverse document frequency
        std::set<std::string> docsWithToken;
        for (const auto& [fp, line, col, len] : occurrences) {
            docsWithToken.insert(fp);
        }
        float idf = logf((float)totalDocuments_ / (1.0f + (float)docsWithToken.size()));
        
        return (float)tf * idf;
    }
};

SearchIndex::SearchIndex() : impl_(std::make_unique<Impl>()) {}
SearchIndex::~SearchIndex() = default;

void SearchIndex::IndexFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return;
    
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    // Remove old index for this file
    RemoveFile(filePath);
    
    std::string line;
    size_t lineNum = 0;
    std::vector<std::string> lines;
    
    while (std::getline(file, line)) {
        lineNum++;
        lines.push_back(line);
        
        auto tokens = impl_->Tokenize(line);
        size_t col = 0;
        
        for (const auto& token : tokens) {
            // Find column position
            size_t pos = line.find(token, col);
            if (pos != std::string::npos) {
                impl_->index_[token].push_back({filePath, lineNum, pos, token.length()});
                impl_->totalTokens_++;
                col = pos + token.length();
            }
        }
    }
    
    impl_->fileLines_[filePath] = lines;
    impl_->totalDocuments_++;
}

void SearchIndex::RemoveFile(const std::string& filePath) {
    // Remove all entries for this file
    for (auto& [token, occurrences] : impl_->index_) {
        occurrences.erase(
            std::remove_if(occurrences.begin(), occurrences.end(),
                [&](const auto& entry) {
                    return std::get<0>(entry) == filePath;
                }),
            occurrences.end());
    }
    
    impl_->fileLines_.erase(filePath);
    impl_->totalDocuments_ = impl_->fileLines_.size();
}

std::vector<SearchResult> SearchIndex::Search(const std::string& query, size_t maxResults) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto queryTokens = impl_->Tokenize(query);
    if (queryTokens.empty()) return {};
    
    // Score each occurrence
    std::vector<std::pair<SearchResult, float>> scored;
    std::unordered_map<std::string, size_t> fileMatchCount;
    
    for (const auto& token : queryTokens) {
        auto it = impl_->index_.find(token);
        if (it == impl_->index_.end()) continue;
        
        for (const auto& [filePath, line, col, len] : it->second) {
            SearchResult result;
            result.filePath = filePath;
            result.line = line;
            result.column = col;
            result.length = len;
            
            // Get line content
            auto linesIt = impl_->fileLines_.find(filePath);
            if (linesIt != impl_->fileLines_.end() && line <= linesIt->second.size()) {
                result.lineContent = linesIt->second[line - 1];
            }
            
            // Compute score
            float score = impl_->ComputeScore(token, filePath);
            result.score = score;
            
            scored.push_back({result, score});
            fileMatchCount[filePath]++;
        }
    }
    
    // Sort by score
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        });
    
    // Deduplicate and limit
    std::vector<SearchResult> results;
    std::set<std::tuple<std::string, size_t, size_t>> seen;
    
    for (auto& [result, score] : scored) {
        auto key = std::make_tuple(result.filePath, result.line, result.column);
        if (seen.insert(key).second) {
            results.push_back(result);
            if (results.size() >= maxResults) break;
        }
    }
    
    return results;
}

std::vector<SearchResult> SearchIndex::RegexSearch(const std::string& pattern, size_t maxResults) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<SearchResult> results;
    std::regex re(pattern, std::regex::ECMAScript | std::regex::icase);
    
    for (const auto& [filePath, lines] : impl_->fileLines_) {
        for (size_t i = 0; i < lines.size(); i++) {
            std::sregex_iterator it(lines[i].begin(), lines[i].end(), re);
            std::sregex_iterator end;
            
            for (; it != end; ++it) {
                SearchResult result;
                result.filePath = filePath;
                result.line = i + 1;
                result.column = it->position();
                result.length = it->length();
                result.lineContent = lines[i];
                result.score = 1.0f;
                results.push_back(result);
                
                if (results.size() >= maxResults) break;
            }
            if (results.size() >= maxResults) break;
        }
        if (results.size() >= maxResults) break;
    }
    
    return results;
}

std::vector<SearchResult> SearchIndex::FuzzySearch(const std::string& query, size_t maxResults) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::pair<SearchResult, int>> scored;
    
    // Levenshtein-based fuzzy matching
    auto levenshteinDistance = [](const std::string& s1, const std::string& s2) -> int {
        size_t m = s1.size(), n = s2.size();
        std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
        
        for (size_t i = 0; i <= m; i++) dp[i][0] = i;
        for (size_t j = 0; j <= n; j++) dp[0][j] = j;
        
        for (size_t i = 1; i <= m; i++) {
            for (size_t j = 1; j <= n; j++) {
                int cost = (s1[i-1] == s2[j-1]) ? 0 : 1;
                dp[i][j] = std::min({dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + cost});
            }
        }
        return dp[m][n];
    };
    
    std::string lowerQuery;
    for (char c : query) lowerQuery += tolower(c);
    
    for (const auto& [token, occurrences] : impl_->index_) {
        int dist = levenshteinDistance(lowerQuery, token);
        if (dist <= 3) { // Allow up to 3 edits
            for (const auto& [filePath, line, col, len] : occurrences) {
                SearchResult result;
                result.filePath = filePath;
                result.line = line;
                result.column = col;
                result.length = len;
                result.score = 1.0f / (1.0f + dist);
                
                auto linesIt = impl_->fileLines_.find(filePath);
                if (linesIt != impl_->fileLines_.end() && line <= linesIt->second.size()) {
                    result.lineContent = linesIt->second[line - 1];
                }
                
                scored.push_back({result, dist});
            }
        }
    }
    
    // Sort by edit distance
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.second < b.second; });
    
    std::vector<SearchResult> results;
    std::set<std::tuple<std::string, size_t, size_t>> seen;
    
    for (auto& [result, _] : scored) {
        auto key = std::make_tuple(result.filePath, result.line, result.column);
        if (seen.insert(key).second) {
            results.push_back(result);
            if (results.size() >= maxResults) break;
        }
    }
    
    return results;
}

void SearchIndex::Clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->index_.clear();
    impl_->fileLines_.clear();
    impl_->totalTokens_ = 0;
    impl_->totalDocuments_ = 0;
}

size_t SearchIndex::GetDocumentCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->totalDocuments_;
}

size_t SearchIndex::GetTokenCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->totalTokens_;
}

} // namespace IDE
} // namespace RawrXD
