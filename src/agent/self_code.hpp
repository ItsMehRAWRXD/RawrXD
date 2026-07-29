#pragma once
<<<<<<< HEAD
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

class SelfCode {
public:
    bool editSource(const std::string& filePath, const std::string& oldSnippet, const std::string& newSnippet);
    bool addInclude(const std::string& hppFile, const std::string& includeLine);
    bool regenerateMOC(const std::string& header);
    bool rebuildTarget(const std::string& target, const std::string& config = "Release");
    std::string lastError() const { return m_lastError; }
private:
    std::string m_lastError;
    bool replaceInFile(const std::string& path, const std::string& oldText, const std::string& newText);
    bool insertAfterIncludeGuard(const std::string& hpp, const std::string& includeLine);
    bool runProcess(const std::string& program, const std::vector<std::string>& args);
=======


class SelfCode {
public:
    // High-level helpers
    bool editSource(const std::string& filePath,
                    const std::string& oldSnippet,
                    const std::string& newSnippet);

    bool addInclude(const std::string& hppFile,
                    const std::string& includeLine);

    bool regenerateMOC(const std::string& header);

    bool createFile(const std::string& filePath,
                    const std::string& content);

    bool rebuildTarget(const std::string& target,
                       const std::string& config = "Release");

    std::string lastError() const { return m_lastError; }

private:
    std::string m_lastError;

    // Low-level helpers
    bool replaceInFile(const std::string& path,
                       const std::string& oldText,
                       const std::string& newText);
    bool insertAfterIncludeGuard(const std::string& hpp,
                                 const std::string& includeLine);
    bool runProcess(const std::string& program,
                    const std::vector<std::string>& args);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};

