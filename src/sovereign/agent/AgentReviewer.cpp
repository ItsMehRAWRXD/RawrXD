// ============================================================================
// AgentReviewer.cpp - Code Review Agent Implementation
// ============================================================================

#include "AgentReviewer.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <cmath>
#include <iostream>

namespace Sovereign {

AgentReviewer::AgentReviewer() = default;
AgentReviewer::~AgentReviewer() = default;

void AgentReviewer::Configure(const ReviewConfig& config) {
    config_ = config;
}

ReviewResult AgentReviewer::ReviewFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file) {
        ReviewResult result;
        result.score = 0;
        result.summary = "Cannot open file: " + filePath;
        return result;
    }
    
    std::stringstream ss;
    ss << file.rdbuf();
    std::string code = ss.str();
    
    std::string ext = filePath.substr(filePath.find_last_of('.') + 1);
    std::string lang = (ext == "cpp" || ext == "hpp" || ext == "h" || ext == "c") ? "cpp" : "unknown";
    
    return ReviewCode(code, lang);
}

ReviewResult AgentReviewer::ReviewCode(const std::string& code, const std::string& language) {
    ReviewResult result;
    std::string file = "inline";
    
    // Run all enabled checks
    if (config_.checkSecurity) {
        auto findings = CheckSecurity(code, file);
        result.findings.insert(result.findings.end(), findings.begin(), findings.end());
    }
    
    if (config_.checkPerformance) {
        auto findings = CheckPerformance(code, file);
        result.findings.insert(result.findings.end(), findings.begin(), findings.end());
    }
    
    if (config_.checkStyle) {
        auto findings = CheckStyle(code, file);
        result.findings.insert(result.findings.end(), findings.begin(), findings.end());
    }
    
    if (config_.checkComplexity) {
        auto findings = CheckComplexity(code, file);
        result.findings.insert(result.findings.end(), findings.begin(), findings.end());
    }
    
    if (config_.checkDocumentation) {
        auto findings = CheckDocumentation(code, file);
        result.findings.insert(result.findings.end(), findings.begin(), findings.end());
    }
    
    // Aggregate statistics
    for (const auto& f : result.findings) {
        switch (f.severity) {
            case ReviewSeverity::CRITICAL: result.criticalIssues++; break;
            case ReviewSeverity::WARNING: result.warnings++; break;
            case ReviewSeverity::INFO: result.infoItems++; break;
            case ReviewSeverity::STYLE: result.styleIssues++; break;
        }
    }
    result.totalIssues = result.findings.size();
    result.score = CalculateScore(result);
    result.summary = GenerateSummary(result);
    
    return result;
}

ReviewResult AgentReviewer::ReviewChanges(const std::string& oldCode, const std::string& newCode) {
    // Simplified diff review
    return ReviewCode(newCode, "cpp");
}

ReviewResult AgentReviewer::ReviewDirectory(const std::string& path) {
    ReviewResult combined;
    
    for (const auto& entry : std::filesystem::recursive_directory_iterator(path)) {
        if (entry.is_regular_file()) {
            auto ext = entry.path().extension().string();
            if (ext == ".cpp" || ext == ".hpp" || ext == ".h" || ext == ".c" || ext == ".py") {
                auto result = ReviewFile(entry.path().string());
                combined.findings.insert(combined.findings.end(), 
                    result.findings.begin(), result.findings.end());
            }
        }
    }
    
    combined.totalIssues = combined.findings.size();
    combined.score = CalculateScore(combined);
    combined.summary = GenerateSummary(combined);
    
    return combined;
}

std::vector<ReviewFinding> AgentReviewer::CheckSecurity(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    
    // Check for dangerous functions
    std::vector<std::pair<std::regex, std::string>> securityPatterns = {
        {std::regex("strcpy\\("), "Unsafe strcpy - use strcpy_s or std::string"},
        {std::regex("strcat\\("), "Unsafe strcat - use strcat_s or std::string"},
        {std::regex("sprintf\\("), "Unsafe sprintf - use snprintf or std::format"},
        {std::regex("gets\\("), "Unsafe gets - use fgets"},
        {std::regex("scanf\\("), "Unsafe scanf - use scanf_s"},
        {std::regex("system\\("), "system() call - potential command injection"},
        {std::regex("popen\\("), "popen() call - potential command injection"},
        {std::regex("alloca\\("), "alloca() - potential stack overflow"},
        {std::regex("malloc\\([^)]*\\)[^;]*$"), "Unchecked malloc - check return value"},
    };
    
    while (std::getline(stream, line)) {
        lineNum++;
        for (const auto& [pattern, message] : securityPatterns) {
            if (std::regex_search(line, pattern)) {
                ReviewFinding finding;
                finding.file = file;
                finding.line = lineNum;
                finding.severity = ReviewSeverity::CRITICAL;
                finding.message = message;
                finding.code = line;
                finding.rule = "SECURITY";
                findings.push_back(finding);
            }
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::CheckPerformance(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    
    std::vector<std::pair<std::regex, std::string>> perfPatterns = {
        {std::regex("std::vector<[^>]+>\\s+v;\\s*\\n\\s*for"), "Vector declared outside loop - consider reserve()"},
        {std::regex("std::map<"), "std::map - consider std::unordered_map for lookups"},
        {std::regex("std::set<"), "std::set - consider std::unordered_set for lookups"},
        {std::regex("\.find\([^)]+\)\s*!=\s*\w+\.end\(\)"), "Repeated .end() call - cache it"},
        {std::regex("push_back\([^)]+\)"), "push_back - consider emplace_back for efficiency"},
        {std::regex("std::stringstream"), "stringstream - consider fmt::format or std::format"},
    };
    
    while (std::getline(stream, line)) {
        lineNum++;
        for (const auto& [pattern, message] : perfPatterns) {
            if (std::regex_search(line, pattern)) {
                ReviewFinding finding;
                finding.file = file;
                finding.line = lineNum;
                finding.severity = ReviewSeverity::WARNING;
                finding.message = message;
                finding.code = line;
                finding.rule = "PERFORMANCE";
                findings.push_back(finding);
            }
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::CheckStyle(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    auto lineFindings = AnalyzeLineLength(code, file);
    findings.insert(findings.end(), lineFindings.begin(), lineFindings.end());
    
    auto namingFindings = AnalyzeNaming(code, file);
    findings.insert(findings.end(), namingFindings.begin(), namingFindings.end());
    
    auto todoFindings = AnalyzeTodo(code, file);
    findings.insert(findings.end(), todoFindings.begin(), todoFindings.end());
    
    auto magicFindings = AnalyzeMagicNumbers(code, file);
    findings.insert(findings.end(), magicFindings.begin(), magicFindings.end());
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::CheckComplexity(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    auto funcFindings = AnalyzeFunctionLength(code, file);
    findings.insert(findings.end(), funcFindings.begin(), funcFindings.end());
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::CheckDocumentation(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    bool inFunction = false;
    int funcStartLine = 0;
    bool hasDoc = false;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Detect function definition
        if (std::regex_search(line, std::regex("\\w+\\s+\\w+\\s*\\([^)]*\\)\\s*\\{"))) {
            inFunction = true;
            funcStartLine = lineNum;
            hasDoc = false;
        }
        
        // Check for documentation before function
        if (inFunction && lineNum == funcStartLine - 1) {
            if (line.find("//") != std::string::npos || line.find("/*") != std::string::npos) {
                hasDoc = true;
            }
        }
        
        // Check for closing brace
        if (inFunction && line.find("}") != std::string::npos) {
            if (!hasDoc && funcStartLine > 1) {
                ReviewFinding finding;
                finding.file = file;
                finding.line = funcStartLine;
                finding.severity = ReviewSeverity::INFO;
                finding.message = "Function lacks documentation comment";
                finding.rule = "DOCUMENTATION";
                findings.push_back(finding);
            }
            inFunction = false;
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::AnalyzeLineLength(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        if (line.length() > config_.maxLineLength) {
            ReviewFinding finding;
            finding.file = file;
            finding.line = lineNum;
            finding.severity = ReviewSeverity::STYLE;
            finding.message = "Line exceeds " + std::to_string(config_.maxLineLength) + " characters";
            finding.code = line;
            finding.rule = "LINE_LENGTH";
            findings.push_back(finding);
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::AnalyzeFunctionLength(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    int funcStart = 0;
    int braceCount = 0;
    bool inFunction = false;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        if (std::regex_search(line, std::regex("\\w+\\s+\\w+\\s*\\([^)]*\\)\\s*\\{"))) {
            if (inFunction) {
                int funcLen = lineNum - funcStart;
                if (funcLen > config_.maxFunctionLength) {
                    ReviewFinding finding;
                    finding.file = file;
                    finding.line = funcStart;
                    finding.severity = ReviewSeverity::WARNING;
                    finding.message = "Function is " + std::to_string(funcLen) + 
                                     " lines (max: " + std::to_string(config_.maxFunctionLength) + ")";
                    finding.rule = "FUNCTION_LENGTH";
                    findings.push_back(finding);
                }
            }
            funcStart = lineNum;
            inFunction = true;
            braceCount = 1;
        } else if (inFunction) {
            for (char c : line) {
                if (c == '{') braceCount++;
                if (c == '}') braceCount--;
            }
            if (braceCount <= 0) {
                int funcLen = lineNum - funcStart;
                if (funcLen > config_.maxFunctionLength) {
                    ReviewFinding finding;
                    finding.file = file;
                    finding.line = funcStart;
                    finding.severity = ReviewSeverity::WARNING;
                    finding.message = "Function is " + std::to_string(funcLen) + 
                                     " lines (max: " + std::to_string(config_.maxFunctionLength) + ")";
                    finding.rule = "FUNCTION_LENGTH";
                    findings.push_back(finding);
                }
                inFunction = false;
            }
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::AnalyzeNaming(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    
    std::regex snakeCase("^\\s*\\w+\\s+[a-z]+\\w*\\s*[=;]");
    std::regex camelCase("^\\s*\\w+\\s+[A-Z]\\w*\\s*[=;]");
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Check for global variables (should be rare)
        if (std::regex_search(line, std::regex("^\\s*int\\s+[a-z]\\w*\\s*=")) &&
            line.find("static") == std::string::npos &&
            line.find("const") == std::string::npos) {
            ReviewFinding finding;
            finding.file = file;
            finding.line = lineNum;
            finding.severity = ReviewSeverity::STYLE;
            finding.message = "Non-const global variable";
            finding.code = line;
            finding.rule = "NAMING";
            findings.push_back(finding);
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::AnalyzeTodo(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        if (line.find("TODO") != std::string::npos || 
            line.find("FIXME") != std::string::npos ||
            line.find("HACK") != std::string::npos ||
            line.find("XXX") != std::string::npos) {
            ReviewFinding finding;
            finding.file = file;
            finding.line = lineNum;
            finding.severity = ReviewSeverity::INFO;
            finding.message = "Unresolved TODO/FIXME/HACK";
            finding.code = line;
            finding.rule = "TODO";
            findings.push_back(finding);
        }
    }
    
    return findings;
}

std::vector<ReviewFinding> AgentReviewer::AnalyzeMagicNumbers(const std::string& code, const std::string& file) {
    std::vector<ReviewFinding> findings;
    std::istringstream stream(code);
    std::string line;
    int lineNum = 0;
    
    std::regex magicNumber("\\b[0-9]{4,}\\b");
    
    while (std::getline(stream, line)) {
        lineNum++;
        std::smatch match;
        if (std::regex_search(line, match, magicNumber)) {
            // Skip common numbers
            std::string num = match.str();
            if (num != "1024" && num != "2048" && num != "4096" && num != "8192") {
                ReviewFinding finding;
                finding.file = file;
                finding.line = lineNum;
                finding.severity = ReviewSeverity::STYLE;
                finding.message = "Magic number: " + num + " - consider named constant";
                finding.code = line;
                finding.rule = "MAGIC_NUMBERS";
                findings.push_back(finding);
            }
        }
    }
    
    return findings;
}

double AgentReviewer::CalculateScore(const ReviewResult& result) {
    double score = 100.0;
    score -= result.criticalIssues * 15.0;
    score -= result.warnings * 5.0;
    score -= result.styleIssues * 1.0;
    score -= result.infoItems * 0.5;
    return std::max(0.0, std::min(100.0, score));
}

std::string AgentReviewer::GenerateSummary(const ReviewResult& result) {
    std::stringstream ss;
    ss << "Review Score: " << std::fixed << std::setprecision(1) << result.score << "/100\n";
    ss << "Issues: " << result.totalIssues << " total, "
       << result.criticalIssues << " critical, "
       << result.warnings << " warnings, "
       << result.styleIssues << " style, "
       << result.infoItems << " info\n";
    return ss.str();
}

} // namespace Sovereign
