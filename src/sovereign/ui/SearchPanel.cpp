// ============================================================================
// SearchPanel.cpp - Search Panel Implementation
// ============================================================================

#include "SearchPanel.hpp"
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <algorithm>
#include <iostream>

namespace fs = std::filesystem;
namespace Sovereign {

SearchPanel::SearchPanel() = default;
SearchPanel::~SearchPanel() = default;

bool SearchPanel::Initialize() { return true; }
void SearchPanel::Shutdown() { history_.clear(); }

SearchResult SearchPanel::Search(const SearchQuery& query) {
    SearchResult result;
    auto start = std::chrono::high_resolution_clock::now();
    
    std::regex pattern;
    if (query.useRegex) {
        pattern = query.caseSensitive ? std::regex(query.text) : std::regex(query.text, std::regex::icase);
    }
    
    std::string searchPath = query.path.empty() ? "." : query.path;
    auto files = GetFiles(searchPath, query);
    
    for (const auto& file : files) {
        std::ifstream f(file);
        if (!f) continue;
        
        std::string line;
        int lineNum = 0;
        SearchMatch match;
        match.file = file;
        
        while (std::getline(f, line)) {
            lineNum++;
            bool found = false;
            int col = 0;
            
            if (query.useRegex) {
                std::smatch m;
                if (std::regex_search(line, m, pattern)) {
                    found = true;
                    col = m.position();
                }
            } else if (query.caseSensitive) {
                auto pos = line.find(query.text);
                if (pos != std::string::npos) { found = true; col = pos; }
            } else {
                auto lowerLine = line;
                std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);
                auto lowerQuery = query.text;
                std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
                auto pos = lowerLine.find(lowerQuery);
                if (pos != std::string::npos) { found = true; col = pos; }
            }
            
            if (found) {
                match.line = lineNum;
                match.column = col + 1;
                match.lineContent = line;
                match.content = line;
                result.matches.push_back(match);
                result.totalMatches++;
                
                if (result.matches.size() >= query.maxResults) break;
            }
        }
        
        if (!result.matches.empty()) {
            result.file = file;
        }
        
        if (result.matches.size() >= query.maxResults) break;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    result.searchTimeMs = std::chrono::duration<double, std::milli>(end - start).count();
    
    stats_.totalSearches++;
    stats_.totalResults += result.totalMatches;
    stats_.avgSearchTimeMs = (stats_.avgSearchTimeMs * (stats_.totalSearches - 1) + result.searchTimeMs) / stats_.totalSearches;
    
    history_.push_back(result);
    if (resultCallback_) resultCallback_(result);
    
    return result;
}

std::vector<std::string> SearchPanel::GetFiles(const std::string& root, const SearchQuery& query) const {
    std::vector<std::string> files;
    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        auto path = entry.path().string();
        if (!query.includeHidden && path.find("/.") != std::string::npos) continue;
        if (!query.includePatterns.empty() && !MatchesPattern(path, query.includePatterns)) continue;
        if (!query.excludePatterns.empty() && MatchesPattern(path, query.excludePatterns)) continue;
        files.push_back(path);
    }
    return files;
}

bool SearchPanel::MatchesPattern(const std::string& file, const std::vector<std::string>& patterns) const {
    for (const auto& p : patterns) {
        if (file.find(p) != std::string::npos) return true;
    }
    return false;
}

void SearchPanel::ClearResults() { history_.clear(); }

} // namespace Sovereign
