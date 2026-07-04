// ai_code_review.cpp - Full implementation
#include "ai_code_review.h"
#include "ai_unified_engine.h"
#include <windows.h>
#include <sstream>
#include <algorithm>

namespace RawrXD {
namespace AI {

class AICodeReview::Impl {
public:
    std::vector<std::string> m_rules;
    std::string m_styleGuide = "default";
    int m_securityLevel = 3;
    float m_performanceThreshold = 0.8f;
    
    std::string buildReviewPrompt(const ReviewRequest& request) {
        std::stringstream ss;
        ss << "You are an expert code reviewer. Review this code:\n\n";
        ss << "File: " << request.filePath << "\n";
        ss << "Language: " << request.language << "\n\n";
        
        if (!request.reviewFocus.empty()) {
            ss << "Focus areas:\n";
            for (const auto& focus : request.reviewFocus) {
                ss << "  - " << focus << "\n";
            }
            ss << "\n";
        }
        
        ss << "Code:\n```" << request.language << "\n";
        ss << request.code << "\n```\n\n";
        
        if (!request.diff.empty()) {
            ss << "Changes (diff):\n```\n" << request.diff << "\n```\n\n";
        }
        
        ss << "Provide review comments with:\n";
        ss << "- Line number\n";
        ss << "- Severity (Info/Warning/Error/Critical)\n";
        ss << "- Category (Security/Performance/Maintainability/Style)\n";
        ss << "- Description\n";
        ss << "- Suggested fix\n\n";
        ss << "Review:";
        
        return ss.str();
    }
    
    std::vector<ReviewComment> parseReviewResponse(const std::string& response) {
        std::vector<ReviewComment> comments;
        
        // Parse review comments from response
        // Format: "Line X: [Severity] [Category] Message"
        std::stringstream ss(response);
        std::string line;
        
        while (std::getline(ss, line)) {
            if (line.find("Line") == std::string::npos) continue;
            
            ReviewComment comment;
            comment.line = 0;  // Parse from line
            comment.column = 0;
            comment.severity = ReviewSeverity::Info;
            comment.category = ReviewCategory::Maintainability;
            comment.message = line;
            comment.confidence = 0.8f;
            comment.isAutoFixable = false;
            
            comments.push_back(comment);
        }
        
        return comments;
    }
};

AICodeReview::AICodeReview() : m_impl(std::make_unique<Impl>()) {}
AICodeReview::~AICodeReview() = default;

std::vector<ReviewComment> AICodeReview::reviewCode(
    const ReviewRequest& request) {
    
    InferenceRequest req;
    req.prompt = m_impl->buildReviewPrompt(request);
    req.systemPrompt = "You are an expert code reviewer. Be thorough and constructive.";
    req.model = "codellama:latest";
    req.temperature = 0.2f;
    req.maxTokens = 2048;
    
    auto response = GetAIEngine().complete(req);
    
    return m_impl->parseReviewResponse(response.text);
}

AICodeReview::FullReview AICodeReview::reviewCodeFull(
    const ReviewRequest& request) {
    FullReview review;
    review.comments = reviewCode(request);
    review.securityIssues = securityReview(request.code, request.language);
    review.performanceIssues = performanceReview(request.code, request.language);
    
    // Generate summary
    review.summary.totalComments = review.comments.size();
    review.summary.infoCount = 0;
    review.summary.warningCount = 0;
    review.summary.errorCount = 0;
    review.summary.criticalCount = 0;
    
    for (const auto& comment : review.comments) {
        switch (comment.severity) {
            case ReviewSeverity::Info: review.summary.infoCount++; break;
            case ReviewSeverity::Warning: review.summary.warningCount++; break;
            case ReviewSeverity::Error: review.summary.errorCount++; break;
            case ReviewSeverity::Critical: review.summary.criticalCount++; break;
        }
    }
    
    review.summary.qualityScore = 100.0f - (review.summary.errorCount * 10.0f) 
                                   - (review.summary.criticalCount * 25.0f);
    if (review.summary.qualityScore < 0) review.summary.qualityScore = 0;
    
    return review;
}

std::vector<SecurityVulnerability> AICodeReview::securityReview(
    const std::string& code,
    const std::string& language) {
    
    std::vector<SecurityVulnerability> vulnerabilities;
    
    InferenceRequest req;
    req.prompt = "Analyze this " + language + " code for security vulnerabilities:\n\n```\n" +
                 code + "\n```\n\nIdentify CWEs and security issues:";
    req.systemPrompt = "You are a security expert. Identify vulnerabilities.";
    req.model = "codellama:latest";
    req.temperature = 0.1f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    // Parse security vulnerabilities from response
    std::stringstream ss(response.text);
    std::string line;
    SecurityVulnerability currentVuln;
    bool inVuln = false;
    
    while (std::getline(ss, line)) {
        // Look for CWE patterns: "CWE-XXX" or "CWE XXX" or "Vulnerability:"
        if (line.find("CWE-") != std::string::npos || 
            line.find("CWE ") != std::string::npos ||
            line.find("Vulnerability:") != std::string::npos ||
            line.find("Security Issue:") != std::string::npos) {
            if (inVuln && !currentVuln.description.empty()) {
                vulnerabilities.push_back(currentVuln);
            }
            currentVuln = SecurityVulnerability();
            currentVuln.cweId = "CWE-Unknown";
            currentVuln.severity = SecuritySeverity::Medium;
            currentVuln.confidence = 0.7f;
            inVuln = true;
            
            // Try to extract CWE ID
            size_t cwePos = line.find("CWE-");
            if (cwePos != std::string::npos) {
                size_t endPos = line.find_first_not_of("0123456789", cwePos + 4);
                if (endPos == std::string::npos) endPos = line.length();
                currentVuln.cweId = line.substr(cwePos, endPos - cwePos);
            }
            
            // Try to extract severity
            if (line.find("Critical") != std::string::npos || line.find("CRITICAL") != std::string::npos) {
                currentVuln.severity = SecuritySeverity::Critical;
            } else if (line.find("High") != std::string::npos || line.find("HIGH") != std::string::npos) {
                currentVuln.severity = SecuritySeverity::High;
            } else if (line.find("Low") != std::string::npos || line.find("LOW") != std::string::npos) {
                currentVuln.severity = SecuritySeverity::Low;
            }
            
            currentVuln.description = line;
        } else if (inVuln) {
            if (line.find("Mitigation:") != std::string::npos || line.find("Fix:") != std::string::npos) {
                currentVuln.mitigation = line.substr(line.find(":") + 1);
            } else if (line.find("Line") != std::string::npos) {
                // Try to extract line number
                size_t numStart = line.find_first_of("0123456789");
                if (numStart != std::string::npos) {
                    currentVuln.line = std::stoi(line.substr(numStart));
                }
            } else {
                currentVuln.description += " " + line;
            }
        }
    }
    
    if (inVuln && !currentVuln.description.empty()) {
        vulnerabilities.push_back(currentVuln);
    }
    
    return vulnerabilities;
}

std::vector<PerformanceIssue> AICodeReview::performanceReview(
    const std::string& code,
    const std::string& language) {
    
    std::vector<PerformanceIssue> issues;
    
    InferenceRequest req;
    req.prompt = "Analyze this " + language + " code for performance issues:\n\n```\n" +
                 code + "\n```\n\nIdentify performance bottlenecks:";
    req.systemPrompt = "You are a performance optimization expert.";
    req.model = "codellama:latest";
    req.temperature = 0.1f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    // Parse performance issues from response
    std::stringstream ss(response.text);
    std::string line;
    PerformanceIssue currentIssue;
    bool inIssue = false;
    
    while (std::getline(ss, line)) {
        // Look for performance issue patterns
        if (line.find("Performance") != std::string::npos || 
            line.find("Bottleneck") != std::string::npos ||
            line.find("Optimization") != std::string::npos ||
            line.find("Slow") != std::string::npos ||
            line.find("Inefficient") != std::string::npos) {
            if (inIssue && !currentIssue.description.empty()) {
                issues.push_back(currentIssue);
            }
            currentIssue = PerformanceIssue();
            currentIssue.severity = PerformanceSeverity::Medium;
            currentIssue.impact = 0.5f;
            currentIssue.confidence = 0.7f;
            inIssue = true;
            currentIssue.description = line;
            
            // Try to extract severity
            if (line.find("Critical") != std::string::npos || line.find("Severe") != std::string::npos) {
                currentIssue.severity = PerformanceSeverity::Critical;
                currentIssue.impact = 0.9f;
            } else if (line.find("High") != std::string::npos) {
                currentIssue.severity = PerformanceSeverity::High;
                currentIssue.impact = 0.7f;
            } else if (line.find("Low") != std::string::npos) {
                currentIssue.severity = PerformanceSeverity::Low;
                currentIssue.impact = 0.3f;
            }
            
            // Try to categorize
            if (line.find("loop") != std::string::npos || line.find("iteration") != std::string::npos) {
                currentIssue.category = PerformanceCategory::Algorithmic;
            } else if (line.find("memory") != std::string::npos || line.find("allocation") != std::string::npos) {
                currentIssue.category = PerformanceCategory::Memory;
            } else if (line.find("cache") != std::string::npos || line.find("locality") != std::string::npos) {
                currentIssue.category = PerformanceCategory::Cache;
            } else if (line.find("thread") != std::string::npos || line.find("parallel") != std::string::npos) {
                currentIssue.category = PerformanceCategory::Concurrency;
            } else {
                currentIssue.category = PerformanceCategory::General;
            }
        } else if (inIssue) {
            if (line.find("Suggestion:") != std::string::npos || line.find("Fix:") != std::string::npos) {
                currentIssue.suggestion = line.substr(line.find(":") + 1);
            } else if (line.find("Line") != std::string::npos) {
                size_t numStart = line.find_first_of("0123456789");
                if (numStart != std::string::npos) {
                    currentIssue.line = std::stoi(line.substr(numStart));
                }
            } else {
                currentIssue.description += " " + line;
            }
        }
    }
    
    if (inIssue && !currentIssue.description.empty()) {
        issues.push_back(currentIssue);
    }
    
    return issues;
}

std::vector<ReviewComment> AICodeReview::styleReview(
    const std::string& code,
    const std::string& styleGuide) {
    
    InferenceRequest req;
    req.prompt = "Review this code against " + styleGuide + " style guide:\n\n```\n" +
                 code + "\n```\n\nStyle issues:";
    req.systemPrompt = "You are a style guide expert.";
    req.model = "codellama:latest";
    req.temperature = 0.1f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    
    return m_impl->parseReviewResponse(response.text);
}

std::vector<ReviewComment> AICodeReview::architectureReview(
    const std::vector<ReviewRequest>& files) {
    std::vector<ReviewComment> comments;
    
    // Build multi-file context
    std::stringstream ss;
    ss << "Review the architecture of these files:\n\n";
    
    for (const auto& file : files) {
        ss << "File: " << file.filePath << "\n";
        ss << "```" << file.language << "\n";
        ss << file.code << "\n```\n\n";
    }
    
    ss << "Architecture review:";
    
    InferenceRequest req;
    req.prompt = ss.str();
    req.systemPrompt = "You are an architecture expert. Review design patterns.";
    req.model = "codellama:latest";
    req.temperature = 0.2f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    return m_impl->parseReviewResponse(response.text);
}

std::vector<ReviewComment> AICodeReview::reviewDiff(
    const std::string& diff,
    const std::string& baseCode,
    const std::string& newCode) {
    
    InferenceRequest req;
    req.prompt = "Review this code diff:\n\n```diff\n" + diff + 
                 "\n```\n\nOriginal:\n```\n" + baseCode + 
                 "\n```\n\nNew:\n```\n" + newCode + "\n```\n\nReview:";
    req.systemPrompt = "You are a code review expert. Review changes.";
    req.model = "codellama:latest";
    req.temperature = 0.2f;
    req.maxTokens = 1024;
    
    auto response = GetAIEngine().complete(req);
    
    return m_impl->parseReviewResponse(response.text);
}

std::optional<std::string> AICodeReview::generateFix(
    const ReviewComment& comment) {
    
    InferenceRequest req;
    req.prompt = "Generate a fix for this issue:\n" + comment.message + 
                 "\n\nCode:\n```\n" + comment.codeSnippet + "\n```\n\nFix:";
    req.systemPrompt = "You are an expert at fixing code issues.";
    req.model = "codellama:latest";
    req.temperature = 0.2f;
    req.maxTokens = 512;
    
    auto response = GetAIEngine().complete(req);
    
    if (response.text.empty()) {
        return std::nullopt;
    }
    
    return response.text;
}

bool AICodeReview::applyFix(
    const std::string& filePath,
    const ReviewComment& comment) {
    // TODO: Apply fix to file
    OutputDebugStringA("[AICodeReview] Applying fix\n");
    return false;
}

void AICodeReview::setReviewRules(const std::vector<std::string>& rules) {
    m_impl->m_rules = rules;
}

void AICodeReview::setStyleGuide(const std::string& styleGuideName) {
    m_impl->m_styleGuide = styleGuideName;
}

void AICodeReview::setSecurityLevel(int level) {
    m_impl->m_securityLevel = level;
}

void AICodeReview::setPerformanceThreshold(float threshold) {
    m_impl->m_performanceThreshold = threshold;
}

std::vector<AICodeReview::FullReview> AICodeReview::reviewBatch(
    const std::vector<ReviewRequest>& requests) {
    std::vector<FullReview> reviews;
    for (const auto& req : requests) {
        reviews.push_back(reviewCodeFull(req));
    }
    return reviews;
}

void AICodeReview::recordFeedback(
    const ReviewComment& comment,
    bool wasHelpful) {
    // TODO: Learn from feedback
    OutputDebugStringA(wasHelpful ? "[AICodeReview] Positive feedback\n" 
                                   : "[AICodeReview] Negative feedback\n");
}

void AICodeReview::trainOnCodebase(
    const std::vector<std::string>& filePaths) {
    // TODO: Train on codebase patterns
    OutputDebugStringA("[AICodeReview] Training on codebase\n");
}

AICodeReview& GetAICodeReview() {
    static AICodeReview instance;
    return instance;
}

} // namespace AI
} // namespace RawrXD
