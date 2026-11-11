#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <set>
#include <regex>

namespace rawrxd {
namespace swarm {

// Code pattern for refactoring
struct CodePattern {
    std::string name;
    std::regex pattern;
    std::string replacement;
    std::string description;
    std::vector<std::string> languages; // "cpp", "js", "py", etc.
    bool safe{true}; // Can be auto-applied
};

// Refactoring operation
struct RefactorOperation {
    enum Type {
        RENAME,
        EXTRACT,
        INLINE,
        MOVE,
        DELETE_UNUSED,
        MODERNIZE,
        OPTIMIZE,
        SECURITY_FIX
    };
    
    Type type;
    std::string targetFile;
    int startLine{0};
    int endLine{0};
    std::string description;
    std::string beforeCode;
    std::string afterCode;
    bool applied{false};
    std::string errorMessage;
};

// Dependency graph node
struct DependencyNode {
    std::string path;
    std::vector<std::string> imports;
    std::vector<std::string> exports;
    std::vector<std::string> dependsOn;
    std::vector<std::string> dependedBy;
    int depth{0}; // In dependency tree
    bool isEntryPoint{false};
};

// Code metrics
struct CodeMetrics {
    int linesOfCode{0};
    int linesOfComments{0};
    int cyclomaticComplexity{0};
    int functionCount{0};
    int classCount{0};
    double duplicationPercentage{0.0};
    double testCoverage{0.0};
    std::vector<std::string> codeSmells;
};

// Modernization target
struct ModernizationTarget {
    std::string fromVersion;
    std::string toVersion;
    std::string language;
    std::vector<CodePattern> patterns;
    std::vector<std::string> deprecatedApis;
    std::map<std::string, std::string> apiReplacements;
};

// Legacy Refactor Module - Automated codebase modernization
class LegacyRefactorModule {
public:
    // Pattern management
    void registerPattern(const CodePattern& pattern);
    void unregisterPattern(const std::string& name);
    std::vector<CodePattern> getPatternsForLanguage(const std::string& language) const;
    
    // Code analysis
    CodeMetrics analyzeFile(const std::string& path);
    CodeMetrics analyzeProject(const std::string& rootPath);
    std::vector<std::string> findCodeSmells(const std::string& path);
    std::vector<std::string> findDuplicatedCode(const std::vector<std::string>& paths);
    
    // Dependency analysis
    std::map<std::string, DependencyNode> buildDependencyGraph(const std::string& rootPath);
    std::vector<std::string> findCircularDependencies(const std::map<std::string, DependencyNode>& graph);
    std::vector<std::string> findUnusedCode(const std::map<std::string, DependencyNode>& graph);
    std::vector<std::string> calculateBuildOrder(const std::map<std::string, DependencyNode>& graph);
    
    // Refactoring operations
    std::vector<RefactorOperation> generateRefactorPlan(const std::string& targetPath);
    bool applyOperation(RefactorOperation& op);
    bool applyOperations(std::vector<RefactorOperation>& ops);
    bool previewOperation(const RefactorOperation& op, std::string& diff);
    
    // Automated refactoring
    std::vector<RefactorOperation> autoRefactor(const std::string& path, bool safeOnly = true);
    std::vector<RefactorOperation> removeUnusedCode(const std::string& path);
    std::vector<RefactorOperation> modernizeSyntax(const std::string& path, const ModernizationTarget& target);
    std::vector<RefactorOperation> optimizePerformance(const std::string& path);
    std::vector<RefactorOperation> fixSecurityIssues(const std::string& path);
    
    // Language-specific refactorings
    std::vector<RefactorOperation> modernizeCpp(const std::string& path, int fromStandard, int toStandard);
    std::vector<RefactorOperation> modernizeJavaScript(const std::string& path, const std::string& fromVersion, 
                                                         const std::string& toVersion);
    std::vector<RefactorOperation> modernizePython(const std::string& path, const std::string& fromVersion,
                                                      const std::string& toVersion);
    
    // C++ specific
    std::vector<RefactorOperation> convertRawPointersToSmartPointers(const std::string& path);
    std::vector<RefactorOperation> addConstCorrectness(const std::string& path);
    std::vector<RefactorOperation> useAutoTypeDeduction(const std::string& path);
    std::vector<RefactorOperation> modernizeLoops(const std::string& path);
    std::vector<RefactorOperation> addOverrideKeywords(const std::string& path);
    std::vector<RefactorOperation> useDefaultMemberInitializers(const std::string& path);
    
    // JavaScript/TypeScript specific
    std::vector<RefactorOperation> convertToAsyncAwait(const std::string& path);
    std::vector<RefactorOperation> convertToArrowFunctions(const std::string& path);
    std::vector<RefactorOperation> addTypeScriptTypes(const std::string& path);
    std::vector<RefactorOperation> convertToESModules(const std::string& path);
    
    // Python specific
    std::vector<RefactorOperation> convertToFStrings(const std::string& path);
    std::vector<RefactorOperation> useTypeHints(const std::string& path);
    std::vector<RefactorOperation> modernizeImports(const std::string& path);
    
    // Security fixes
    std::vector<RefactorOperation> fixSqlInjection(const std::string& path);
    std::vector<RefactorOperation> fixXssVulnerabilities(const std::string& path);
    std::vector<RefactorOperation> fixInsecureCrypto(const std::string& path);
    std::vector<RefactorOperation> fixPathTraversal(const std::string& path);
    
    // Performance optimizations
    std::vector<RefactorOperation> optimizeLoops(const std::string& path);
    std::vector<RefactorOperation> optimizeMemoryAccess(const std::string& path);
    std::vector<RefactorOperation> vectorizeOperations(const std::string& path);
    
    // Batch operations
    std::vector<RefactorOperation> refactorProject(const std::string& rootPath, 
                                                      const std::vector<CodePattern>& patterns);
    bool applyProjectRefactoring(const std::string& rootPath, 
                                  std::vector<RefactorOperation>& ops);
    
    // Undo/Redo
    bool undoLastOperation();
    bool redoLastOperation();
    void clearHistory();
    
    // Validation
    bool validateRefactoring(const RefactorOperation& op);
    bool validateProjectAfterRefactoring(const std::string& rootPath);
    std::vector<std::string> runTests(const std::string& rootPath);
    
    // Reporting
    std::string generateReport(const std::vector<RefactorOperation>& ops);
    std::string generateMetricsReport(const std::string& rootPath);
    
private:
    std::vector<CodePattern> patterns_;
    std::vector<RefactorOperation> history_;
    std::vector<RefactorOperation> redoStack_;
    
    // Language detection
    std::string detectLanguage(const std::string& path) const;
    
    // File operations
    std::string readFile(const std::string& path);
    bool writeFile(const std::string& path, const std::string& content);
    bool backupFile(const std::string& path);
    
    // Pattern matching
    std::vector<std::pair<int, int>> findMatches(const std::string& content, const std::regex& pattern);
    
    // Complexity calculation
    int calculateCyclomaticComplexity(const std::string& code);
};

} // namespace swarm
} // namespace rawrxd
