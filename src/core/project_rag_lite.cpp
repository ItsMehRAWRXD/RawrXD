#include "project_rag_lite.hpp"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace RawrXD {
namespace Search {

namespace {

struct DocumentEmbedding {
    std::string filePath;
    std::string content;
    std::map<std::string, float> termFrequencies;
    std::chrono::system_clock::time_point lastIndexed{};
    size_t tokenCount = 0;
};

std::vector<std::string> Tokenize(const std::string& text) {
    std::vector<std::string> tokens;
    std::string current;
    for (char c : text) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            current += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        } else if (!current.empty()) {
            tokens.push_back(current);
            current.clear();
        }
    }
    if (!current.empty()) tokens.push_back(current);
    return tokens;
}

class ProjectRagLite {
public:
    static ProjectRagLite& Instance() {
        static ProjectRagLite inst;
        return inst;
    }

    void IndexFile(const std::string& filePath, const std::string& content) {
        auto emb = std::make_shared<DocumentEmbedding>();
        emb->filePath = filePath;
        emb->content = content;
        emb->tokenCount = Tokenize(content).size();
        emb->lastIndexed = std::chrono::system_clock::now();
        for (const auto& tok : Tokenize(content)) emb->termFrequencies[tok] += 1.0f;
        std::lock_guard<std::mutex> lock(mutex_);
        documents_[filePath] = emb;
    }

    std::vector<SearchResult> Search(const std::string& query, size_t maxResults) {
        std::vector<SearchResult> results;
        auto qTokens = Tokenize(query);
        if (qTokens.empty()) return results;
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [path, doc] : documents_) {
            float score = 0.0f;
            for (const auto& q : qTokens) {
                auto it = doc->termFrequencies.find(q);
                if (it != doc->termFrequencies.end()) score += it->second;
            }
            if (score > 0.0f) results.push_back({path, score, "", 0});
        }
        std::sort(results.begin(), results.end(),
                  [](const SearchResult& a, const SearchResult& b) {
                      return a.relevanceScore > b.relevanceScore;
                  });
        if (results.size() > maxResults) results.resize(maxResults);
        return results;
    }

private:
    ProjectRagLite() = default;
    std::mutex mutex_;
    std::map<std::string, std::shared_ptr<DocumentEmbedding>> documents_;
};

}  // namespace

void IndexProjectFile(const std::string& filePath, const std::string& content) {
    ProjectRagLite::Instance().IndexFile(filePath, content);
}

std::vector<SearchResult> SearchProject(const std::string& query, size_t maxResults) {
    return ProjectRagLite::Instance().Search(query, maxResults);
}

}  // namespace Search
}  // namespace RawrXD
