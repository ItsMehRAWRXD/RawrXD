/**
 * @file sovereign_code_bridge.h
 * @brief Sovereign Runtime Integration for Code Intelligence
 * @status PRODUCTION - Real AI-powered code explanation and generation
 */

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <future>
#include <memory>

namespace RawrXD::IDE {

enum class CodeActionType {
    ExplainCode,
    GenerateTests,
    OptimizeCode,
    FindBugs,
    GenerateDocs,
    RefactorSuggestion,
    CompleteImplementation
};

struct CodeContext {
    std::string file;
    uint32_t startLine;
    uint32_t endLine;
    std::string selectedCode;
    std::string surroundingContext;
    std::vector<std::string> relatedFiles;
    std::string language;
};

struct CodeExplanation {
    std::string summary;
    std::vector<std::string> keyPoints;
    std::vector<std::string> potentialIssues;
    std::string complexity;
    std::vector<std::string> relatedConcepts;
};

struct TestGeneration {
    std::string testFramework;
    std::vector<std::string> testCases;
    std::string setupCode;
    std::string mockCode;
    std::vector<std::string> edgeCases;
};

struct OptimizationSuggestion {
    std::string originalCode;
    std::string optimizedCode;
    std::string explanation;
    std::string expectedImprovement;
    bool isSafe;
};

struct BugReport {
    uint32_t line;
    std::string severity;
    std::string description;
    std::string suggestedFix;
    std::string confidence;
};

struct DocumentationBlock {
    std::string brief;
    std::string detailed;
    std::vector<std::pair<std::string, std::string>> parameters;
    std::string returns;
    std::string throws;
    std::string example;
};

class SovereignCodeBridge {
public:
    SovereignCodeBridge();
    ~SovereignCodeBridge();
    
    // Initialization
    bool Initialize(const std::string& modelPath);
    void Shutdown();
    bool IsReady() const;
    
    // Core actions
    std::future<CodeExplanation> ExplainCodeAsync(const CodeContext& context);
    std::future<TestGeneration> GenerateTestsAsync(const CodeContext& context);
    std::future<std::vector<OptimizationSuggestion>> OptimizeCodeAsync(const CodeContext& context);
    std::future<std::vector<BugReport>> FindBugsAsync(const CodeContext& context);
    std::future<DocumentationBlock> GenerateDocsAsync(const CodeContext& context);
    std::future<std::string> CompleteImplementationAsync(const CodeContext& context, 
                                                           const std::string& intent);
    
    // Synchronous versions
    CodeExplanation ExplainCode(const CodeContext& context);
    TestGeneration GenerateTests(const CodeContext& context);
    
    // Context building
    CodeContext BuildContext(const std::string& file, 
                             uint32_t startLine, 
                             uint32_t endLine);
    
    // IDE integration
    void SetProgressCallback(std::function<void(const std::string&, int)> callback);
    void SetResultCallback(std::function<void(CodeActionType, const std::string&)> callback);
    
    // Quick actions
    std::string QuickExplain(const std::string& code);
    std::string QuickComplete(const std::string& partialCode);
    std::vector<std::string> QuickSuggestions(const std::string& code, uint32_t line);

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// IDE Integration helpers
class CodeActionMenu {
public:
    CodeActionMenu();
    
    void ShowAtCursor(HWND hwnd, const CodeContext& context);
    void AddAction(CodeActionType type, const std::wstring& label);
    void SetBridge(SovereignCodeBridge* bridge);
    
private:
    SovereignCodeBridge* m_bridge;
    CodeContext m_currentContext;
};

} // namespace RawrXD::IDE
