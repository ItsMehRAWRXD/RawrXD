// ============================================================================
// SpecializedAgents.hpp - Code Completion, Documentation, Security, Dependency Agents
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

// Code completion agent
class CodeCompletionAgent {
public:
    CodeCompletionAgent();
    ~CodeCompletionAgent();

    bool Initialize(const std::string& modelPath);
    void Shutdown();

    std::vector<std::string> Complete(const std::string& context, const std::string& prefix, size_t maxSuggestions = 5);
    std::vector<std::string> CompleteLine(const std::string& line, const std::string& fileExtension);
    std::vector<std::string> CompleteSymbol(const std::string& symbolName, const std::vector<std::string>& availableSymbols);

    struct CompletionStats { uint64_t totalCompletions; uint64_t acceptedCompletions; double avgLatencyMs; };
    CompletionStats GetStats() const { return stats_; }

private:
    bool initialized_ = false;
    CompletionStats stats_;
    mutable std::mutex mutex_;
};

// Documentation agent
class DocumentationAgent {
public:
    DocumentationAgent();
    ~DocumentationAgent();

    bool Initialize();
    void Shutdown();

    std::string GenerateDoc(const std::string& code, const std::string& language);
    std::string GenerateFunctionDoc(const std::string& functionName, const std::vector<std::string>& params, const std::string& returnType);
    std::string GenerateClassDoc(const std::string& className, const std::vector<std::string>& methods);
    std::string GenerateFileHeader(const std::string& fileName, const std::string& author, const std::string& description);

    struct DocStats { uint64_t totalDocs; uint64_t totalTokens; };
    DocStats GetStats() const { return stats_; }

private:
    DocStats stats_;
    mutable std::mutex mutex_;
};

// Security audit agent
class SecurityAuditAgent {
public:
    SecurityAuditAgent();
    ~SecurityAuditAgent();

    bool Initialize();
    void Shutdown();

    std::vector<std::string> AuditFile(const std::string& filePath);
    std::vector<std::string> AuditCode(const std::string& code, const std::string& language);
    std::vector<std::string> AuditDependencies(const std::vector<std::string>& dependencies);

    struct SecurityStats { uint64_t totalAudits; uint64_t totalFindings; uint64_t criticalFindings; };
    SecurityStats GetStats() const { return stats_; }

private:
    SecurityStats stats_;
    mutable std::mutex mutex_;
    
    std::vector<std::string> CheckForSecrets(const std::string& code);
    std::vector<std::string> CheckForInjections(const std::string& code);
    std::vector<std::string> CheckForUnsafeFunctions(const std::string& code);
};

// Dependency update agent
class DependencyUpdateAgent {
public:
    DependencyUpdateAgent();
    ~DependencyUpdateAgent();

    bool Initialize();
    void Shutdown();

    std::vector<std::pair<std::string, std::string>> CheckUpdates(const std::string& projectPath);
    bool UpdateDependency(const std::string& name, const std::string& newVersion);
    std::vector<std::string> GetOutdatedDependencies(const std::string& projectPath);

    struct DepStats { uint64_t totalChecks; uint64_t totalUpdates; };
    DepStats GetStats() const { return stats_; }

private:
    DepStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
