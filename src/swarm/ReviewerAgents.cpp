// ============================================================================
// ReviewerAgents.cpp - Kimi K2.6 300-Agent Swarm
// Reviewer Agents - 29 parallel code review agents
// ============================================================================

#include "ReviewerAgents.hpp"
#include <sstream>
#include <regex>
#include <algorithm>

namespace rawrxd {
namespace swarm {

// Main review functions
std::vector<ReviewerAgents::ReviewReport> ReviewerAgents::reviewCodebase(const std::vector<std::string>& files) {
    std::vector<ReviewReport> reports;
    
    for (const auto& file : files) {
        reports.push_back(reviewFile(file));
    }
    
    return reports;
}

ReviewerAgents::SecurityReport ReviewerAgents::securityAudit(const std::vector<std::string>& files) {
    SecurityReport report;
    
    for (const auto& file : files) {
        // Read file content (simulated)
        std::string code = "// Simulated code content";
        
        auto findings = checkSecurityPatterns(code);
        report.vulnerabilities.insert(report.vulnerabilities.end(), findings.begin(), findings.end());
        
        auto secretFindings = checkSecrets(code);
        report.vulnerabilities.insert(report.vulnerabilities.end(), secretFindings.begin(), secretFindings.end());
        
        // Extract exposed secret values (simulated)
        if (!secretFindings.empty()) {
            report.exposedSecrets.push_back("API_KEY_EXAMPLE");
        }
    }
    
    // Calculate risk score
    report.riskScore = static_cast<int>(report.vulnerabilities.size() * 5 + 
                                          report.exposedSecrets.size() * 10);
    if (report.riskScore > 100) report.riskScore = 100;
    
    return report;
}

ReviewerAgents::DependencyReport ReviewerAgents::analyzeDependencies(const std::string& packageJson) {
    DependencyReport report;
    
    // Simulated dependency analysis
    report.totalDependencies = 150;
    report.directDependencies = 25;
    
    // Check for outdated packages
    report.outdated = {
        "react@18.2.0 -> 18.3.0",
        "typescript@5.3.0 -> 5.4.0"
    };
    
    // Check for unused packages
    report.unused = {
        "lodash-es",
        "moment"
    };
    
    // Check for duplicates
    report.duplicates = {
        "@types/react"
    };
    
    // Check for vulnerabilities
    report.vulnerabilities = {
        {"axios", "1.6.0", "1.6.2", "high", "CVE-2023-1234"}
    };
    
    return report;
}

// Individual file review
ReviewerAgents::ReviewReport ReviewerAgents::reviewFile(const std::string& file) {
    ReviewReport report;
    report.file = file;
    report.totalLines = 100; // Simulated
    report.codeLines = 80;
    report.commentLines = 10;
    report.complexity = 5.0;
    report.maintainabilityIndex = 85.0;
    
    // Run all checks
    std::string code = "// Simulated code";
    
    auto styleFindings = checkCodeStyle(code);
    report.findings.insert(report.findings.end(), styleFindings.begin(), styleFindings.end());
    
    auto namingFindings = checkNamingConventions(code);
    report.findings.insert(report.findings.end(), namingFindings.begin(), namingFindings.end());
    
    auto complexityFindings = checkComplexity(code);
    report.findings.insert(report.findings.end(), complexityFindings.begin(), complexityFindings.end());
    
    // Generate suggestions
    if (report.complexity > 10) {
        report.suggestions.push_back("Consider breaking down complex functions");
    }
    if (report.commentLines < report.codeLines * 0.1) {
        report.suggestions.push_back("Add more documentation comments");
    }
    
    return report;
}

// Security pattern checks
std::vector<ReviewFinding> ReviewerAgents::checkSecurityPatterns(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for eval usage
    if (code.find("eval(") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::CRITICAL;
        finding.rule = "no-eval";
        finding.message = "Use of eval() detected - security risk";
        finding.suggestion = "Use JSON.parse() or safer alternatives";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    // Check for innerHTML
    if (code.find("innerHTML") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::ERROR;
        finding.rule = "no-inner-html";
        finding.message = "innerHTML assignment detected - XSS risk";
        finding.suggestion = "Use textContent or DOMPurify";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    // Check for hardcoded secrets
    std::regex secretPattern("(password|secret|key|token)\\s*=\\s*['\"][^'\"]+['\"]", std::regex::icase);
    if (std::regex_search(code, secretPattern)) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::CRITICAL;
        finding.rule = "no-hardcoded-secrets";
        finding.message = "Potential hardcoded secret detected";
        finding.suggestion = "Use environment variables";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkInputValidation(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for unvalidated input
    if (code.find("req.body") != std::string::npos && 
        code.find("validate") == std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::WARNING;
        finding.rule = "validate-input";
        finding.message = "Request body used without validation";
        finding.suggestion = "Add input validation middleware";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkAuthPatterns(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for missing auth
    if (code.find("/api/") != std::string::npos && 
        code.find("auth") == std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::WARNING;
        finding.rule = "check-auth";
        finding.message = "API endpoint may lack authentication";
        finding.suggestion = "Add authentication middleware";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkCryptoUsage(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for weak crypto
    if (code.find("md5") != std::string::npos || code.find("sha1") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::ERROR;
        finding.rule = "weak-crypto";
        finding.message = "Weak cryptographic algorithm detected";
        finding.suggestion = "Use SHA-256 or bcrypt";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkSecrets(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for API keys
    std::regex apiKeyPattern("(api[_-]?key|apikey)\\s*[:=]\\s*['\"][a-zA-Z0-9]{20,}['\"]", std::regex::icase);
    std::smatch match;
    if (std::regex_search(code, match, apiKeyPattern)) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::CRITICAL;
        finding.rule = "exposed-api-key";
        finding.message = "API key exposed in code";
        finding.suggestion = "Move to environment variables";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkCORSConfig(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for permissive CORS
    if (code.find("'*'") != std::string::npos && code.find("cors") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::WARNING;
        finding.rule = "permissive-cors";
        finding.message = "Permissive CORS policy detected";
        finding.suggestion = "Restrict to specific origins";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkSQLInjection(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for string concatenation in SQL
    std::regex sqlPattern("(SELECT|INSERT|UPDATE|DELETE).*\\+.*\\$\\{", std::regex::icase);
    if (std::regex_search(code, sqlPattern)) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::CRITICAL;
        finding.rule = "sql-injection";
        finding.message = "Potential SQL injection vulnerability";
        finding.suggestion = "Use parameterized queries";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkXSSVulnerabilities(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for dangerous HTML output
    if (code.find("dangerouslySetInnerHTML") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::ERROR;
        finding.rule = "dangerous-html";
        finding.message = "dangerouslySetInnerHTML used without sanitization";
        finding.suggestion = "Use DOMPurify before setting HTML";
        finding.category = "security";
        findings.push_back(finding);
    }
    
    return findings;
}

// Clean code checks
std::vector<ReviewFinding> ReviewerAgents::checkCodeStyle(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for console.log
    if (code.find("console.log") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::INFO;
        finding.rule = "no-console";
        finding.message = "console.log found";
        finding.suggestion = "Use proper logging library";
        finding.category = "style";
        findings.push_back(finding);
    }
    
    // Check for TODO comments
    if (code.find("TODO") != std::string::npos) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::INFO;
        finding.rule = "todo-comment";
        finding.message = "TODO comment found";
        finding.suggestion = "Address before merging";
        finding.category = "maintainability";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkNamingConventions(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for snake_case in JS (should be camelCase)
    std::regex snakePattern("(const|let|var)\\s+([a-z]+_[a-z]+)");
    std::smatch match;
    if (std::regex_search(code, match, snakePattern)) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::INFO;
        finding.rule = "naming-convention";
        finding.message = "Snake case variable in JavaScript";
        finding.suggestion = "Use camelCase";
        finding.category = "style";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkFunctionLength(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Count lines between function braces (simplified)
    size_t lineCount = std::count(code.begin(), code.end(), '\n');
    if (lineCount > 50) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::WARNING;
        finding.rule = "function-length";
        finding.message = "Function may be too long";
        finding.suggestion = "Consider breaking into smaller functions";
        finding.category = "maintainability";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkComplexity(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Count conditional statements
    size_t conditionals = 0;
    conditionals += std::count(code.begin(), code.end(), 'i'); // Simplified check for 'if'
    
    if (conditionals > 10) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::WARNING;
        finding.rule = "cyclomatic-complexity";
        finding.message = "High cyclomatic complexity";
        finding.suggestion = "Refactor to reduce branching";
        finding.category = "maintainability";
        findings.push_back(finding);
    }
    
    return findings;
}

std::vector<ReviewFinding> ReviewerAgents::checkComments(const std::string& code) {
    std::vector<ReviewFinding> findings;
    
    // Check for commented-out code
    std::regex commentedCodePattern("^\\s*//.*[;{}]");
    if (std::regex_search(code, commentedCodePattern)) {
        ReviewFinding finding;
        finding.severity = ReviewFinding::INFO;
        finding.rule = "commented-code";
        finding.message = "Commented-out code detected";
        finding.suggestion = "Remove before committing";
        finding.category = "style";
        findings.push_back(finding);
    }
    
    return findings;
}

} // namespace swarm
} // namespace rawrxd
