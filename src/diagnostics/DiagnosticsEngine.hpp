// ============================================================================
// DiagnosticsEngine.hpp - Code Diagnostics & Linting
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace IDE {

struct Diagnostic {
    std::string filePath;
    size_t startLine;
    size_t startColumn;
    size_t endLine;
    size_t endColumn;
    std::string message;
    std::string code;
    enum Severity { Hint, Information, Warning, Error };
    Severity severity;
    std::string source; // "compiler", "linter", "static-analysis"
    
    struct Fix {
        std::string description;
        std::string replacement;
        size_t replaceStart;
        size_t replaceEnd;
    };
    std::vector<Fix> fixes;
};

class DiagnosticsEngine {
public:
    DiagnosticsEngine();
    ~DiagnosticsEngine();

    void SetCompilerPath(const std::string& path);
    void SetBuildDirectory(const std::string& dir);
    
    // Run diagnostics on a file
    std::vector<Diagnostic> AnalyzeFile(const std::string& filePath);
    std::vector<Diagnostic> AnalyzeProject();
    
    // Incremental analysis
    std::vector<Diagnostic> AnalyzeChanges(const std::string& filePath, 
                                            const std::string& oldContent,
                                            const std::string& newContent);
    
    // Quick fix
    std::vector<Diagnostic::Fix> GetFixes(const Diagnostic& diag);
    bool ApplyFix(const Diagnostic& diag, const Diagnostic::Fix& fix);
    
    // Configuration
    void EnableLinter(bool enable);
    void EnableStaticAnalysis(bool enable);
    void SetWarningLevel(int level);
    
    using DiagnosticCallback = std::function<void(const std::vector<Diagnostic>&)>;
    void SetDiagnosticCallback(DiagnosticCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
