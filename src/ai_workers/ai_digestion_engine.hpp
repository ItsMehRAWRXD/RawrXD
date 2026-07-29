#pragma once

#include "ai_types.hpp"
<<<<<<< HEAD
#include <cstdint>
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <vector>
#include <string>
#include <map>

struct FileAnalysisResult {
    std::string path;
    int64_t tokenCount;
    std::vector<std::string> todos;
    std::vector<std::string> functions;
    bool isBinary = false;
};

class AIDigestionEngine {
public:
    AIDigestionEngine();
    ~AIDigestionEngine();

    std::vector<FileAnalysisResult> digest(const std::vector<std::string>& files, const DigestionConfig& config);
    FileAnalysisResult analyzeFile(const std::string& path, const DigestionConfig& config);

    int64_t getTotalTokens() const { return m_totalTokens; }

private:
    int64_t m_totalTokens = 0;
};
