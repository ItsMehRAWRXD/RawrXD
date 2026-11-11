// Win32IDE_ContextGovernor.h — Context Assembly (Batch 6 R05)
// Prioritize relevant files, respect token budget
#pragma once

#include <string>
#include <vector>
#include <map>

namespace ContextGovernor {

class ContextGovernor {
public:
    static ContextGovernor& Instance();

    void SetTokenBudget(size_t tokens);
    size_t GetTokenBudget() const;

    void AddFileContext(const std::string& filePath, float relevanceScore);
    std::vector<std::string> GetPrioritizedFiles() const;

    void Clear();

private:
    ContextGovernor() = default;
    size_t m_tokenBudget = 4096;
    std::map<std::string, float> m_fileRelevance;
};

} // namespace ContextGovernor
