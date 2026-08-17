#pragma once
#include <string>
#include <vector>
#include <unordered_map>

namespace RawrXD {

struct Symbol {
    std::string name;
    std::string kind;       // function, class, variable
    std::string file;
    size_t line;
    std::string signature;
};

struct ProjectContext {
    std::string rootPath;
    std::vector<std::string> files;
    std::vector<Symbol> symbols;
    std::string currentFile;
    size_t cursorLine;
    std::string currentFunction;
    std::string compilerErrors;
};

class ContextEngine {
public:
    ContextEngine();

    void IndexProject(const std::string& rootPath);
    void UpdateFile(const std::string& filePath, const std::string& content);
    void SetCursor(const std::string& file, size_t line);
    void SetCompilerErrors(const std::string& errors);
    
    std::string BuildContextPrompt(size_t maxTokens = 2048) const;
    std::vector<Symbol> FindRelatedSymbols(const std::string& name) const;
    
    const ProjectContext& GetCurrentContext() const { return context_; }

private:
    void ParseSymbols(const std::string& filePath, const std::string& content);

    ProjectContext context_;
    std::unordered_map<std::string, std::string> fileContents_;
};

} // namespace RawrXD
