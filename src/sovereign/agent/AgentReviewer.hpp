// ============================================================================
// AgentReviewer.hpp - Code Review Agent
// Automated code review with static analysis
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

// Review severity
enum class ReviewSeverity {
    CRITICAL,
    WARNING,
    INFO,
    STYLE
};

// Review finding
struct ReviewFinding {
    std::string file;
    int line;
    int column;
    ReviewSeverity severity;
    std::string message;
    std::string rule;
    std::string suggestion;
    std::string code;
};

// Review result
struct ReviewResult {
    std::vector<ReviewFinding> findings;
    int totalIssues;
    int criticalIssues;
    int warnings;
    int infoItems;
    int styleIssues;
    double score; // 0-100
    std::string summary;
};

// Review configuration
struct ReviewConfig {
    bool checkSecurity = true;
    bool checkPerformance = true;
    bool checkStyle = true;
    bool checkDocumentation = true;
    bool checkComplexity = true;
    int maxComplexity = 10;
    int maxFunctionLength = 100;
    int maxLineLength = 120;
    std::vector<std::string> enabledRules;
    std::vector<std::string> disabledRules;
};

// Code reviewer
class AgentReviewer {
public:
    AgentReviewer();
    ~AgentReviewer();

    // Configure
    void Configure(const ReviewConfig& config);
    const ReviewConfig& GetConfig() const { return config_; }

    // Review operations
    ReviewResult ReviewFile(const std::string& filePath);
    ReviewResult ReviewCode(const std::string& code, const std::string& language);
    ReviewResult ReviewChanges(const std::string& oldCode, const std::string& newCode);
    ReviewResult ReviewDirectory(const std::string& path);

    // Specific checks
    std::vector<ReviewFinding> CheckSecurity(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> CheckPerformance(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> CheckStyle(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> CheckComplexity(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> CheckDocumentation(const std::string& code, const std::string& file);

    // PR review
    ReviewResult ReviewPullRequest(const std::string& repoPath, int prNumber);
    ReviewResult ReviewDiff(const std::string& diffContent);

    // Scoring
    double CalculateScore(const ReviewResult& result);
    std::string GenerateSummary(const ReviewResult& result);

    // Fix suggestions
    std::string SuggestFix(const ReviewFinding& finding);
    bool AutoFix(const ReviewFinding& finding);

private:
    ReviewConfig config_;
    
    // Analysis engines
    std::vector<ReviewFinding> AnalyzeLineLength(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeFunctionLength(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeNaming(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeMemory(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeNullSafety(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeIncludes(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeTodo(const std::string& code, const std::string& file);
    std::vector<ReviewFinding> AnalyzeMagicNumbers(const std::string& code, const std::string& file);
};

} // namespace Sovereign
