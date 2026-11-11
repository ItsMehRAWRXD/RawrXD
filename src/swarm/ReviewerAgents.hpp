#pragma once

#include "SwarmOrchestrator.hpp"
#include <vector>
#include <string>
#include <map>
#include <set>

namespace rawrxd {
namespace swarm {

// Code review finding
struct ReviewFinding {
    enum Severity { INFO, WARNING, ERROR, CRITICAL };
    
    Severity severity;
    std::string file;
    int line{0};
    int column{0};
    std::string rule;
    std::string message;
    std::string suggestion;
    std::string category; // "security", "performance", "style", "maintainability"
};

// Security pattern
struct SecurityPattern {
    std::string name;
    std::string description;
    std::vector<std::string> dangerousPatterns;
    std::vector<std::string> safeAlternatives;
    ReviewFinding::Severity severity;
};

// Dependency vulnerability
struct Vulnerability {
    std::string package;
    std::string currentVersion;
    std::string fixedVersion;
    std::string severity; // "low", "moderate", "high", "critical"
    std::string description;
    std::string cve;
};

// Reviewer Agents - 29 parallel code review agents
class ReviewerAgents {
public:
    struct ReviewReport {
        std::string file;
        std::vector<ReviewFinding> findings;
        int totalLines{0};
        int codeLines{0};
        int commentLines{0};
        double complexity{0.0};
        double maintainabilityIndex{0.0};
        std::vector<std::string> suggestions;
    };
    
    struct SecurityReport {
        std::vector<ReviewFinding> vulnerabilities;
        std::vector<Vulnerability> dependencyVulns;
        std::vector<std::string> exposedSecrets;
        std::vector<std::string> insecureConfigs;
        int riskScore{0}; // 0-100
    };
    
    struct DependencyReport {
        std::vector<std::string> outdated;
        std::vector<std::string> unused;
        std::vector<std::string> duplicates;
        std::vector<Vulnerability> vulnerabilities;
        std::vector<std::string> licenseIssues;
        int totalDependencies{0};
        int directDependencies{0};
    };
    
    // Main review functions - parallel execution
    std::vector<ReviewReport> reviewCodebase(const std::vector<std::string>& files);
    SecurityReport securityAudit(const std::vector<std::string>& files);
    DependencyReport analyzeDependencies(const std::string& packageJson);
    
    // Individual review agents
    ReviewReport reviewFile(const std::string& file);
    
    // Security review
    std::vector<ReviewFinding> checkSecurityPatterns(const std::string& code);
    std::vector<ReviewFinding> checkInputValidation(const std::string& code);
    std::vector<ReviewFinding> checkAuthPatterns(const std::string& code);
    std::vector<ReviewFinding> checkCryptoUsage(const std::string& code);
    std::vector<ReviewFinding> checkSecrets(const std::string& code);
    std::vector<ReviewFinding> checkCORSConfig(const std::string& code);
    std::vector<ReviewFinding> checkSQLInjection(const std::string& code);
    std::vector<ReviewFinding> checkXSSVulnerabilities(const std::string& code);
    
    // Clean code review
    std::vector<ReviewFinding> checkCodeStyle(const std::string& code);
    std::vector<ReviewFinding> checkNamingConventions(const std::string& code);
    std::vector<ReviewFinding> checkFunctionLength(const std::string& code);
    std::vector<ReviewFinding> checkComplexity(const std::string& code);
    std::vector<ReviewFinding> checkComments(const std::string& code);
    std::vector<ReviewFinding> checkDocumentation(const std::string& code);
    
    // Performance review
    std::vector<ReviewFinding> checkPerformance(const std::string& code);
    std::vector<ReviewFinding> checkMemoryUsage(const std::string& code);
    std::vector<ReviewFinding> checkAsyncPatterns(const std::string& code);
    std::vector<ReviewFinding> checkRenderingPerformance(const std::string& code);
    
    // Dependency analysis
    DependencyReport analyzeNodeDependencies(const std::string& packageJson);
    DependencyReport analyzePythonDependencies(const std::string& requirements);
    std::vector<Vulnerability> scanForVulnerabilities(const std::vector<std::string>& packages);
    std::vector<std::string> findUnusedDependencies(const std::string& sourceDir);
    std::vector<std::string> findDuplicateDependencies(const std::string& lockFile);
    
    // Architecture review
    std::vector<ReviewFinding> checkArchitecture(const std::vector<std::string>& files);
    std::vector<ReviewFinding> checkSOLIDPrinciples(const std::string& code);
    std::vector<ReviewFinding> checkDRYViolations(const std::vector<std::string>& files);
    std::vector<ReviewFinding> checkCoupling(const std::vector<std::string>& files);
    
    // Framework-specific reviews
    std::vector<ReviewFinding> reviewReactCode(const std::string& code);
    std::vector<ReviewFinding> reviewVueCode(const std::string& code);
    std::vector<ReviewFinding> reviewNodeCode(const std::string& code);
    std::vector<ReviewFinding> reviewPythonCode(const std::string& code);
    
    // Auto-fix suggestions
    std::string generateFix(const ReviewFinding& finding);
    std::map<std::string, std::string> generateFixes(const std::vector<ReviewFinding>& findings);
    bool applyFix(const std::string& file, const ReviewFinding& finding);
    
    // Review configuration
    void addSecurityPattern(const SecurityPattern& pattern);
    void setSeverityThreshold(ReviewFinding::Severity threshold);
    void ignoreRule(const std::string& rule);
    void ignoreFile(const std::string& pattern);
    
    // Reporting
    std::string generateMarkdownReport(const std::vector<ReviewReport>& reports);
    std::string generateSARIFReport(const std::vector<ReviewReport>& reports);
    std::string generateSummary(const std::vector<ReviewReport>& reports);
    
private:
    std::vector<SecurityPattern> securityPatterns_;
    ReviewFinding::Severity severityThreshold_ = ReviewFinding::INFO;
    std::set<std::string> ignoredRules_;
    std::set<std::string> ignoredFiles_;
};

} // namespace swarm
} // namespace rawrxd
