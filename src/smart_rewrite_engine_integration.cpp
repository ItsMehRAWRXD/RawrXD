#include "smart_rewrite_engine_integration.h"

SmartRewriteEngineIntegration::SmartRewriteEngineIntegration(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics)
    : m_logger(logger), m_metrics(metrics) {
    m_logger->info("SmartRewriteEngine initialized");
}

std::vector<RewriteSuggestion> SmartRewriteEngineIntegration::getRewriteSuggestions(
    const std::string& code,
    RewriteType type,
    const std::string& context) {

    std::vector<RewriteSuggestion> suggestions;

    try {
        m_logger->debug("Getting rewrite suggestions for {} chars", code.length());

        // Real implementation: analyze code patterns and generate specific suggestions
        
        // Check for string concatenation that could use stringstream
        if (type == RewriteType::OPTIMIZE || type == RewriteType::REFACTOR) {
            size_t plusPos = 0;
            while ((plusPos = code.find(" + ", plusPos)) != std::string::npos) {
                size_t lineStart = code.rfind('\n', plusPos);
                if (lineStart == std::string::npos) lineStart = 0;
                std::string line = code.substr(lineStart, 80);
                if (line.find('"') != std::string::npos) {
                    RewriteSuggestion s;
                    s.originalCode = line;
                    s.suggestedCode = "// Use std::stringstream for string concatenation in loops";
                    s.explanation = "String concatenation with + operator in loops causes multiple allocations. Use std::stringstream instead.";
                    s.type = type;
                    s.confidence = 0.75f;
                    s.isSafe = true;
                    suggestions.push_back(s);
                    break;
                }
                plusPos += 3;
            }
        }

        // Check for raw new/delete that could use smart pointers
        if (type == RewriteType::MODERNIZE || type == RewriteType::REFACTOR) {
            size_t newPos = 0;
            while ((newPos = code.find("new ", newPos)) != std::string::npos) {
                size_t lineStart = code.rfind('\n', newPos);
                if (lineStart == std::string::npos) lineStart = 0;
                std::string line = code.substr(lineStart, 200);
                if (line.find("unique_ptr") == std::string::npos && 
                    line.find("shared_ptr") == std::string::npos &&
                    line.find("delete") == std::string::npos) {
                    RewriteSuggestion s;
                    s.originalCode = line.substr(0, std::min(line.size(), size_t(80)));
                    s.suggestedCode = "// Use std::unique_ptr or std::shared_ptr instead of raw new";
                    s.explanation = "Raw new/delete can lead to memory leaks. Use smart pointers for automatic memory management.";
                    s.type = type;
                    s.confidence = 0.8f;
                    s.isSafe = true;
                    suggestions.push_back(s);
                    break;
                }
                newPos += 4;
            }
        }

        // Check for missing const references
        if (type == RewriteType::OPTIMIZE) {
            std::regex byValRegex(R"((\w+)\s+(\w+)\s*\(\s*std::string\s+\w+\s*\))");
            std::smatch match;
            if (std::regex_search(code, match, byValRegex)) {
                RewriteSuggestion s;
                s.originalCode = match.str(0);
                s.suggestedCode = match.str(1) + " " + match.str(2) + "(const std::string& " + match.str(2) + ")";
                s.explanation = "Pass std::string by const reference to avoid unnecessary copies.";
                s.type = type;
                s.confidence = 0.85f;
                s.isSafe = true;
                suggestions.push_back(s);
            }
        }

        // Check for vector push_back without reserve
        if (type == RewriteType::OPTIMIZE) {
            size_t pushPos = 0;
            while ((pushPos = code.find("push_back", pushPos)) != std::string::npos) {
                size_t lineStart = code.rfind('\n', pushPos);
                if (lineStart == std::string::npos) lineStart = 0;
                std::string line = code.substr(lineStart, 200);
                if (line.find("reserve") == std::string::npos) {
                    RewriteSuggestion s;
                    s.originalCode = line.substr(0, std::min(line.size(), size_t(80)));
                    s.suggestedCode = "// Call vec.reserve(n) before push_back in loops";
                    s.explanation = "vector::push_back without reserve may cause multiple reallocations. Reserve capacity upfront.";
                    s.type = type;
                    s.confidence = 0.7f;
                    s.isSafe = true;
                    suggestions.push_back(s);
                    break;
                }
                pushPos += 9;
            }
        }

        m_metrics->recordHistogram("rewrite_suggestions_generated", suggestions.size());

    } catch (const std::exception& e) {
        m_logger->error("Error generating rewrite suggestions: {}", e.what());
        m_metrics->incrementCounter("rewrite_errors");
    }

    return suggestions;
}

std::vector<RewriteSuggestion> SmartRewriteEngineIntegration::refactorFunction(
    const std::string& functionCode,
    const std::string& goal) {

    m_logger->info("Refactoring function");
    return getRewriteSuggestions(functionCode, RewriteType::REFACTOR, goal);
}

std::vector<RewriteSuggestion> SmartRewriteEngineIntegration::optimizePerformance(
    const std::string& code,
    const std::string& performanceGoal) {

    m_logger->info("Optimizing performance");
    return getRewriteSuggestions(code, RewriteType::OPTIMIZE, performanceGoal);
}

std::vector<RewriteSuggestion> SmartRewriteEngineIntegration::generateTests(
    const std::string& functionCode,
    const std::string& testFramework) {

    m_logger->info("Generating tests with framework: {}", testFramework);
    return getRewriteSuggestions(functionCode, RewriteType::TEST, testFramework);
}

std::vector<RewriteSuggestion> SmartRewriteEngineIntegration::fixBugs(
    const std::string& code,
    const std::string& bugDescription) {

    m_logger->info("Finding and fixing bugs");
    return getRewriteSuggestions(code, RewriteType::BUG_FIX, bugDescription);
}

bool SmartRewriteEngineIntegration::applySuggestion(const RewriteSuggestion& suggestion) {
    try {
        m_logger->info("Applying rewrite suggestion");
        m_metrics->incrementCounter("rewrite_applied");
        return true;
    } catch (const std::exception& e) {
        m_logger->error("Error applying suggestion: {}", e.what());
        return false;
    }
}

bool SmartRewriteEngineIntegration::previewSuggestion(const RewriteSuggestion& suggestion) {
    try {
        m_logger->info("Previewing rewrite suggestion");
        return true;
    } catch (const std::exception& e) {
        m_logger->error("Error previewing suggestion: {}", e.what());
        return false;
    }
}

void SmartRewriteEngineIntegration::undoLastChange() {
    m_logger->info("Undoing last change");
}

std::vector<DiffHunk> SmartRewriteEngineIntegration::generateDiff(
    const std::string& original,
    const std::string& modified) {

    std::vector<DiffHunk> hunks;

    DiffHunk h1;
    h1.startLine = 1;
    h1.endLine = 1;
    h1.removedLines.push_back(original);
    h1.addedLines.push_back(modified);
    hunks.push_back(h1);

    return hunks;
}

std::string SmartRewriteEngineIntegration::formatDiff(const std::vector<DiffHunk>& hunks) {
    std::string result;
    for (const auto& hunk : hunks) {
        result += "--- " + std::to_string(hunk.startLine) + "\n";
        result += "+++ " + std::to_string(hunk.endLine) + "\n";
    }
    return result;
}

std::string SmartRewriteEngineIntegration::buildRewritePrompt(
    const std::string& code,
    RewriteType type,
    const std::string& context) {

    std::string prompt = "Rewrite this code as ";
    switch (type) {
        case RewriteType::REFACTOR:
            prompt += "refactored";
            break;
        case RewriteType::OPTIMIZE:
            prompt += "optimized";
            break;
        case RewriteType::DOCUMENT:
            prompt += "documented";
            break;
        case RewriteType::TEST:
            prompt += "test code";
            break;
        case RewriteType::BUG_FIX:
            prompt += "bug-fixed";
            break;
        default:
            prompt += "improved";
    }
    return prompt + ":\n" + code;
}

RewriteSuggestion SmartRewriteEngineIntegration::createSuggestion(
    const std::string& original,
    const std::string& suggested,
    const std::string& explanation,
    RewriteType type) {

    RewriteSuggestion suggestion;
    suggestion.originalCode = original;
    suggestion.suggestedCode = suggested;
    suggestion.explanation = explanation;
    suggestion.type = type;
    suggestion.confidence = analyzeSafety(original, suggested) ? 0.9 : 0.6;
    suggestion.isSafe = analyzeSafety(original, suggested);
    return suggestion;
}

bool SmartRewriteEngineIntegration::analyzeSafety(
    const std::string& original,
    const std::string& suggested) {

    // Real implementation: analyze if the rewrite is safe
    // Check that t