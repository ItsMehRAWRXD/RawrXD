/**
 * ============================================================================
 * AI Code Review - Automated Code Review Assistant
 * ============================================================================
 * 
 * Features:
 * - PR-style code review comments
 * - Security vulnerability detection
 * - Performance issue identification
 * - Style guide enforcement
 * - Best practice suggestions
 * - Architecture review
 * 
 * Reference: GitHub Copilot Code Review, CodeRabbit
 * ============================================================================
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <functional>
#include <vector>
#include <optional>
#include <functional>

namespace RawrXD {
namespace AI {

// Review comment severity
enum class ReviewSeverity {
    Info,       // Style, suggestions
    Warning,    // Potential issues
    Error,      // Bugs, security
    Critical    // Security vulnerabilities
};

// Review category
enum class ReviewCategory {
    Security,
    Performance,
    Maintainability,
    Style,
    Documentation,
    Architecture,
    Testing,
    Accessibility
};

// Review comment
struct ReviewComment {
    std::string filePath;
    int line;
    int column;
    ReviewSeverity severity;
    ReviewCategory category;
    std::string message;
    std::string suggestion;      // Proposed fix
    std::string codeSnippet;     // Relevant code
    float confidence;
    bool isAutoFixable;
    std::vector<std::string> references;  // Links to docs, standards
};

// Review summary
struct ReviewSummary {
    int totalComments;
    int infoCount;
    int warningCount;
    int errorCount;
    int criticalCount;
    std::string overallAssessment;
    std::vector<std::string> strengths;
    std::vector<std::string> concerns;
    float qualityScore;  // 0-100
};

// Code review request
struct ReviewRequest {
    std::string filePath;
    std::string code;
    std::string language;
    std::string context;         // Surrounding code/files
    std::string diff;            // If reviewing changes
    std::string baseBranch;      // For comparison
    std::vector<std::string> reviewFocus;  // Areas to focus on
};

// Security vulnerability
enum class SecuritySeverity {
    Low,
    Medium,
    High,
    Critical
};

struct SecurityVulnerability {
    std::string cweId;           // CWE-XXX
    SecuritySeverity severity;
    std::string description;
    std::string vulnerableCode;
    std::string remediation;
    std::vector<std::string> affectedLines;
    bool isExploitable;
    float confidence = 0.0f;
    std::string mitigation;
    int line = 0;
};

// Performance issue
enum class PerformanceCategory {
    General,
    Algorithmic,
    Memory,
    Cache,
    Concurrency
};

enum class PerformanceSeverity {
    Low,
    Medium,
    High,
    Critical
};

struct PerformanceIssue {
    std::string description;
    std::string problematicCode;
    std::string optimizedAlternative;
    float estimatedSpeedup;
    std::string complexity;      // O(n), O(n^2), etc.
    PerformanceCategory category = PerformanceCategory::General;
    PerformanceSeverity severity = PerformanceSeverity::Medium;
    std::string suggestion;
    int line = 0;
    float impact = 0.0f;
    float confidence = 0.0f;
};

class AICodeReview {
public:
    AICodeReview();
    ~AICodeReview();

    // Main review API
    std::vector<ReviewComment> reviewCode(
        const ReviewRequest& request
    );

    // Review with summary
    struct FullReview {
        std::vector<ReviewComment> comments;
        ReviewSummary summary;
        std::vector<SecurityVulnerability> securityIssues;
        std::vector<PerformanceIssue> performanceIssues;
    };
    
    FullReview reviewCodeFull(
        const ReviewRequest& request
    );

    // Specialized reviews
    std::vector<SecurityVulnerability> securityReview(
        const std::string& code,
        const std::string& language
    );
    
    std::vector<PerformanceIssue> performanceReview(
        const std::string& code,
        const std::string& language
    );
    
    std::vector<ReviewComment> styleReview(
        const std::string& code,
        const std::string& styleGuide
    );
    
    std::vector<ReviewComment> architectureReview(
        const std::vector<ReviewRequest>& files
    );

    // Diff review (for PRs)
    std::vector<ReviewComment> reviewDiff(
        const std::string& diff,
        const std::string& baseCode,
        const std::string& newCode
    );

    // Auto-fix generation
    std::optional<std::string> generateFix(
        const ReviewComment& comment
    );
    
    bool applyFix(
        const std::string& filePath,
        const ReviewComment& comment
    );

    // Review configuration
    void setReviewRules(const std::vector<std::string>& rules);
    void setStyleGuide(const std::string& styleGuideName);
    void setSecurityLevel(int level);  // 1-5
    void setPerformanceThreshold(float threshold);

    // Batch review
    std::vector<FullReview> reviewBatch(
        const std::vector<ReviewRequest>& requests
    );

    // Learning
    void recordFeedback(
        const ReviewComment& comment,
        bool wasHelpful
    );
    
    void trainOnCodebase(
        const std::vector<std::string>& filePaths
    );

private:
    std::string buildReviewPrompt(const ReviewRequest& request);
    std::vector<ReviewComment> parseReviewResponse(
        const std::string& response
    );
    
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// Global instance
AICodeReview& GetAICodeReview();

} // namespace AI
} // namespace RawrXD
