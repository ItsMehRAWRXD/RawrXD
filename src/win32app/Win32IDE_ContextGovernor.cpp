// Win32IDE_ContextGovernor.cpp — Context Assembly (Batch 6 R05)
// Prioritize relevant files, respect token budget
#include "Win32IDE_ContextGovernor.h"
#include <algorithm>
#include <string>

namespace ContextGovernor {

ContextGovernor& ContextGovernor::Instance() {
    static ContextGovernor inst;
    return inst;
}

void ContextGovernor::SetTokenBudget(size_t tokens) {
    m_tokenBudget = tokens;
}

size_t ContextGovernor::GetTokenBudget() const {
    return m_tokenBudget;
}

void ContextGovernor::AddFileContext(const std::string& filePath, float relevanceScore) {
    m_fileRelevance[filePath] = relevanceScore;
}

std::vector<std::string> ContextGovernor::GetPrioritizedFiles() const {
    std::vector<std::pair<std::string, float>> sorted;
    for (const auto& [path, score] : m_fileRelevance) {
        sorted.push_back({path, score});
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    std::vector<std::string> result;
    size_t estimatedTokens = 0;
    const size_t avgTokensPerFile = 256;

    for (const auto& [path, score] : sorted) {
        if (estimatedTokens + avgTokensPerFile > m_tokenBudget) break;
        result.push_back(path);
        estimatedTokens += avgTokensPerFile;
    }

    return result;
}

void ContextGovernor::Clear() {
    m_fileRelevance.clear();
}

} // namespace ContextGovernor
