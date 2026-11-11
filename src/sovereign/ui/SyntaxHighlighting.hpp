// ============================================================================
// SyntaxHighlighting.hpp - GPU-Accelerated Syntax Highlighting Engine
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

// Token types for syntax highlighting
enum class HighlightTokenType {
    KEYWORD, TYPE, FUNCTION, VARIABLE, CONSTANT, STRING, COMMENT,
    NUMBER, OPERATOR, PREPROCESSOR, ANNOTATION, ATTRIBUTE, NAMESPACE,
    CLASS, METHOD, PARAMETER, PROPERTY, REGEX, ESCAPE, PLAIN_TEXT
};

// Highlight token
struct HighlightToken {
    HighlightTokenType type;
    uint32_t start;
    uint32_t length;
    uint32_t color;
    bool bold;
    bool italic;
};

// Highlight line
struct HighlightLine {
    uint32_t lineNumber;
    std::vector<HighlightToken> tokens;
    std::string text;
};

// Language definition
struct LanguageDefinition {
    std::string name;
    std::vector<std::string> extensions;
    std::vector<std::pair<std::string, HighlightTokenType>> keywords;
    std::vector<std::pair<std::string, HighlightTokenType>> types;
    std::vector<std::pair<std::regex, HighlightTokenType>> patterns;
    std::pair<std::string, std::string> lineComment;
    std::pair<std::string, std::string> blockComment;
    std::vector<std::string> stringDelimiters;
    bool caseSensitive;
};

// Syntax highlighting engine
class SyntaxHighlighting {
public:
    SyntaxHighlighting();
    ~SyntaxHighlighting();

    bool Initialize();
    void Shutdown();

    void RegisterLanguage(const LanguageDefinition& lang);
    LanguageDefinition GetLanguage(const std::string& extension) const;
    std::string DetectLanguage(const std::string& filename) const;

    std::vector<HighlightLine> Highlight(const std::string& code, const std::string& language);
    std::vector<HighlightLine> HighlightFile(const std::string& path);
    std::vector<HighlightToken> TokenizeLine(const std::string& line, const LanguageDefinition& lang);

    // Color scheme
    void SetColorScheme(const std::unordered_map<HighlightTokenType, uint32_t>& colors);
    uint32_t GetColor(HighlightTokenType type) const;

    // Incremental highlighting
    std::vector<HighlightLine> HighlightIncremental(const std::string& code, const std::string& language, uint32_t startLine, uint32_t endLine);

    struct HighlightStats {
        uint64_t totalLines;
        uint64_t totalTokens;
        uint64_t totalFiles;
        double avgTimePerLineUs;
    };
    HighlightStats GetStats() const { return stats_; }

private:
    std::unordered_map<std::string, LanguageDefinition> languages_;
    std::unordered_map<HighlightTokenType, uint32_t> colorScheme_;
    HighlightStats stats_;
    mutable std::mutex mutex_;
    
    void InitializeDefaultLanguages();
    void InitializeDefaultColorScheme();
    void AddCPPLanguage();
    void AddPythonLanguage();
    void AddJavaScriptLanguage();
    void AddMASMLanguage();
};

} // namespace Sovereign
