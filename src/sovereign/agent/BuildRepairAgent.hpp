// ============================================================================
// BuildRepairAgent.hpp - Autonomous Build Repair Agent
// Detects build failures and applies fixes
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

// Build error
struct BuildError {
    std::string file;
    int line;
    int column;
    std::string message;
    std::string code;
    std::string type; // error, warning, note
    std::string suggestedFix;
};

// Build result
struct BuildResult {
    bool success;
    int exitCode;
    std::vector<BuildError> errors;
    std::vector<BuildError> warnings;
    std::string output;
    double durationMs;
};

// Fix strategy
struct FixStrategy {
    std::string type;
    std::string description;
    std::string file;
    int line;
    std::string oldText;
    std::string newText;
    int confidence; // 0-100
};

// Build repair agent
class BuildRepairAgent {
public:
    BuildRepairAgent();
    ~BuildRepairAgent();

    // Build execution
    BuildResult RunBuild(const std::string& buildCommand, const std::string& workspace);
    BuildResult RunCMake(const std::string& workspace);
    BuildResult RunNinja(const std::string& workspace);

    // Error analysis
    std::vector<BuildError> ParseBuildOutput(const std::string& output);
    std::vector<BuildError> ParseMSVCErrors(const std::string& output);
    std::vector<BuildError> ParseGCCErrors(const std::string& output);
    std::vector<BuildError> ParseClangErrors(const std::string& output);

    // Fix generation
    std::vector<FixStrategy> GenerateFixes(const std::vector<BuildError>& errors);
    FixStrategy FixIncludeError(const BuildError& error);
    FixStrategy FixSyntaxError(const BuildError& error);
    FixStrategy FixLinkerError(const BuildError& error);
    FixStrategy FixTypeError(const BuildError& error);
    FixStrategy FixUndefinedSymbol(const BuildError& error);

    // Auto-repair
    bool ApplyFix(const FixStrategy& fix);
    BuildResult BuildAndRepair(const std::string& workspace, int maxAttempts = 3);

    // Statistics
    int GetTotalRepairs() const { return totalRepairs_; }
    int GetSuccessfulRepairs() const { return successfulRepairs_; }
    double GetSuccessRate() const;

private:
    int totalRepairs_ = 0;
    int successfulRepairs_ = 0;
    
    std::string ExecuteCommand(const std::string& command);
    bool ApplyTextFix(const std::string& file, int line, const std::string& oldText, 
                      const std::string& newText);
    std::string ReadFile(const std::string& path);
    bool WriteFile(const std::string& path, const std::string& content);
};

} // namespace Sovereign
