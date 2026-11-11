// ============================================================================
// SearchTools.cpp - Code Search Implementation
// ============================================================================

#include "SearchTools.hpp"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace Sovereign {

struct SearchTools::Impl {
    std::unordered_map<std::string, std::vector<std::string>> fileIndex_;
    std::unordered_map<std::string, std::vector<std::pair<int, std::string>>> symbolIndex_;
    std::vector<std::string> indexedFiles_;
    std::mutex mutex_;
};

SearchTools::SearchTools() : pImpl(std::make_unique<Impl>()) {}
SearchTools::~SearchTools() = default;

std::vector<SearchResult> SearchTools::SearchText(const std::string& query, const SearchConfig& config) {
    std::vector<SearchResult> results;
    auto roots = GetSearchRoots(config.searchPaths.empty() ? "." : config.searchPaths[0]);
    
    for (const auto& root : roots) {
        auto files = GetFiles(root, config);
        
        for (const auto& file : files) {
            auto fileResults = SearchTextInFile(file, query, config);
            results.insert(results.end(), fileResults.begin(), fileResults.end());
            
            if (results.size() >= config.maxResults) {
                results.resize(config.maxResults);
                return results;
            }
        }
    }
    
    return results;
}

std::vector<SearchResult> SearchTools::SearchTextInFile(const std::string& file, const std::string& query,
                                                         const SearchConfig& config) {
    std::vector<SearchResult> results;
    std::ifstream f(file);
    if (!f) return results;
    
    std::regex pattern;
    if (config.useRegex) {
        pattern = config.caseSensitive ? std::regex(query) : std::regex(query, std::regex::icase);
    }
    
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(line);
    }
    
    for (size_t i = 0; i < lines.size(); ++i) {
        bool match = false;
        size_t col = 0;
        
        if (config.useRegex) {
            std::smatch m;
            if (std::regex_search(lines[i], m, pattern)) {
                match = true;
                col = m.position();
            }
        } else if (config.caseSensitive) {
            auto pos = lines[i].find(query);
            if (pos != std::string::npos) {
                match = true;
                col = pos;
            }
        } else {
            auto lowerLine = lines[i];
            auto lowerQuery = query;
            std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);
            std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
            auto pos = lowerLine.find(lowerQuery);
            if (pos != std::string::npos) {
                match = true;
                col = pos;
            }
        }
        
        if (match) {
            SearchResult result;
            result.file = file;
            result.line = i + 1;
            result.column = col + 1;
            result.content = lines[i];
            
            // Context
            int startLine = std::max(0, (int)i - (int)config.contextLines);
            int endLine = std::min((int)lines.size() - 1, (int)i + (int)config.contextLines);
            for (int j = startLine; j <= endLine; ++j) {
                result.context += lines[j] + "\n";
            }
            
            result.relevance = 1.0f;
            results.push_back(result);
        }
    }
    
    return results;
}

std::vector<std::string> SearchTools::SearchFiles(const std::string& pattern, const std::string& root) {
    std::vector<std::string> results;
    std::regex re(pattern, std::regex::icase);
    auto searchRoot = root.empty() ? "." : root;
    
    for (const auto& entry : fs::recursive_directory_iterator(searchRoot, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file()) {
            if (std::regex_search(entry.path().filename().string(), re)) {
                results.push_back(entry.path().string());
            }
        }
    }
    
    return results;
}

std::vector<std::string> SearchTools::SearchFilesByExtension(const std::string& ext, const std::string& root) {
    std::vector<std::string> results;
    auto searchRoot = root.empty() ? "." : root;
    
    for (const auto& entry : fs::recursive_directory_iterator(searchRoot, fs::directory_options::skip_permission_denied)) {
        if (entry.is_regular_file() && entry.path().extension() == ext) {
            results.push_back(entry.path().string());
        }
    }
    
    return results;
}

std::vector<SearchResult> SearchTools::Grep(const std::string& pattern, const std::string& root,
                                             const SearchConfig& config) {
    SearchConfig cfg = config;
    cfg.useRegex = true;
    return SearchText(pattern, cfg);
}

std::vector<SearchResult> SearchTools::FindReferences(const std::string& symbol, const std::string& root) {
    SearchConfig config;
    config.wholeWord = true;
    return SearchText(symbol, config);
}

std::vector<SearchResult> SearchTools::FindDefinitions(const std::string& symbol, const std::string& root) {
    // Simplified: search for common definition patterns
    std::vector<SearchResult> results;
    
    // C++ definitions
    auto cppResults = SearchText(symbol + "(", config);
    results.insert(results.end(), cppResults.begin(), cppResults.end());
    
    auto classResults = SearchText("class " + symbol, config);
    results.insert(results.end(), classResults.begin(), classResults.end());
    
    auto structResults = SearchText("struct " + symbol, config);
    results.insert(results.end(), structResults.begin(), structResults.end());
    
    return results;
}

std::vector<std::string> SearchTools::GetSearchRoots(const std::string& root) const {
    if (root.empty() || root == ".") {
        return {fs::current_path().string()};
    }
    return {root};
}

std::vector<std::string> SearchTools::GetFiles(const std::string& root, const SearchConfig& config) const {
    std::vector<std::string> files;
    
    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        
        auto path = entry.path().string();
        
        // Check include patterns
        if (!config.includePatterns.empty() && !MatchesPattern(path, config.includePatterns)) continue;
        
        // Check exclude patterns
        if (!config.excludePatterns.empty() && MatchesPattern(path, config.excludePatterns)) continue;
        
        files.push_back(path);
    }
    
    return files;
}

bool SearchTools::MatchesPattern(const std::string& file, const std::vector<std::string>& patterns) const {
    for (const auto& pattern : patterns) {
        if (file.find(pattern) != std::string::npos) return true;
    }
    return false;
}

std::string SearchTools::ReadFileContent(const std::string& path) const {
    std::ifstream file(path);
    if (!file) return "";
    std::stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

void SearchTools::BuildIndex(const std::string& root) {
    pImpl->indexedFiles_.clear();
    pImpl->symbolIndex_.clear();
    
    for (const auto& entry : fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension().string();
        if (ext == ".cpp" || ext == ".hpp" || ext == ".h" || ext == ".c" || ext == ".py") {
            pImpl->indexedFiles_.push_back(entry.path().string());
        }
    }
}

void SearchTools::ClearIndex() {
    pImpl->indexedFiles_.clear();
    pImpl->symbolIndex_.clear();
}

size_t SearchTools::GetIndexedFileCount() const {
    return pImpl->indexedFiles_.size();
}

} // namespace Sovereign
