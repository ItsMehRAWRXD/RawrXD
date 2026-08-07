#include "advanced_coding_agent.h"

AdvancedCodingAgentIntegration::AdvancedCodingAgentIntegration(
    std::shared_ptr<Logger> logger,
    std::shared_ptr<Metrics> metrics)
    : m_logger(logger), m_metrics(metrics) {

}

GeneratedFeature AdvancedCodingAgentIntegration::implementFeature(
    const FeatureRequest& request) {


    GeneratedFeature feature;
    feature.code = "// Generated implementation\n";
    feature.explanation = "Feature implementation generated from request";
    feature.confidence = 0.85;
    
    m_metrics->incrementCounter("features_generated");
    return feature;
}

std::vector<GeneratedFeature> AdvancedCodingAgentIntegration::generateImplementationOptions(
    const std::string& description,
    const std::string& context) {


    std::vector<GeneratedFeature> options;
    
    GeneratedFeature opt1;
    opt1.code = "// Option 1";
    opt1.explanation = "First implementation option";
    opt1.confidence = 0.80;
    options.push_back(opt1);
    
    GeneratedFeature opt2;
    opt2.code = "// Option 2";
    opt2.explanation = "Second implementation option";
    opt2.confidence = 0.75;
    options.push_back(opt2);

    return options;
}

std::string AdvancedCodingAgentIntegration::generateDocumentation(
    const std::string& code) {


    std::string doc = "/**\n";
    doc += " * Auto-generated documentation\n";
    doc += " * Function purpose and usage\n";
    doc += " */\n";

    m_metrics->incrementCounter("documentation_generated");
    return doc;
}

std::string AdvancedCodingAgentIntegration::generateFunctionDocumentation(
    const std::string& functionCode,
    const std::string& style) {

    return "/// Auto-generated documentation";
}

std::vector<std::string> AdvancedCodingAgentIntegration::generateTests(
    const std::string& functionCode) {


    std::vector<std::string> tests;
    
    tests.push_back("TEST_CASE(\"Basic functionality\") { /* test */ }");
    tests.push_back("TEST_CASE(\"Edge cases\") { /* test */ }");
    tests.push_back("TEST_CASE(\"Error handling\") { /* test */ }");

    m_metrics->incrementCounter("tests_generated");
    return tests;
}

std::vector<std::string> AdvancedCodingAgentIntegration::findBugs(
    const std::string& code) {


    std::vector<std::string> bugs;
    
    // Real static analysis: detect common bug patterns
    
    // 1. Null pointer dereference risk: dereference without null check
    size_t arrowPos = 0;
    while ((arrowPos = code.find("->", arrowPos)) != std::string::npos) {
        // Check if preceded by a null check within 200 chars
        size_t checkStart = (arrowPos > 200) ? arrowPos - 200 : 0;
        std::string context = code.substr(checkStart, arrowPos - checkStart);
        if (context.find("!= nullptr") == std::string::npos &&
            context.find("!=" + std::string(" NULL")) == std::string::npos &&
            context.find("if (") == std::string::npos) {
            // Extract variable name before ->
            size_t varEnd = arrowPos;
            size_t varStart = varEnd;
            while (varStart > 0 && (isalnum((unsigned char)code[varStart-1]) || code[varStart-1] == '_'))
                varStart--;
            std::string varName = code.substr(varStart, varEnd - varStart);
            if (!varName.empty() && varName != "this" && varName != "self") {
                bugs.push_back("Potential null dereference: " + varName + " not checked before -> access");
            }
        }
        arrowPos += 2;
    }
    
    // 2. Uninitialized variable: type declaration without assignment
    std::vector<std::string> typeKeywords = {"int ", "float ", "double ", "bool ", "char*", "void*"};
    for (const auto& kw : typeKeywords) {
        size_t pos = 0;
        while ((pos = code.find(kw, pos)) != std::string::npos) {
            size_t varStart = pos + kw.length();
            size_t varEnd = varStart;
            while (varEnd < code.length() && (isalnum((unsigned char)code[varEnd]) || code[varEnd] == '_'))
                varEnd++;
            std::string varName = code.substr(varStart, varEnd - varStart);
            // Check if followed by = or ;
            size_t nextNonSpace = code.find_first_not_of(" \t", varEnd);
            if (nextNonSpace != std::string::npos && code[nextNonSpace] == ';') {
                if (!varName.empty() && varName != "i" && varName != "j" && varName != "k") {
                    bugs.push_back("Uninitialized variable: " + varName + " declared without assignment");
                }
            }
            pos = varEnd;
        }
    }
    
    // 3. Buffer overflow risk: memcpy/strcpy without size check
    size_t memcpyPos = 0;
    while ((memcpyPos = code.find("memcpy(", memcpyPos)) != std::string::npos) {
        size_t parenEnd = code.find(')', memcpyPos);
        if (parenEnd != std::string::npos) {
            std::string args = code.substr(memcpyPos + 7, parenEnd - memcpyPos - 7);
            if (args.find("sizeof") == std::string::npos) {
                bugs.push_back("Potential buffer overflow: memcpy without sizeof");
            }
        }
        memcpyPos += 7;
    }
    
    // 4. Resource leak: open without close
    if (code.find("fopen(") != std::string::npos || code.find("open(") != std::string::npos) {
        if (code.find("fclose") == std::string::npos && code.find("close(") == std::string::npos) {
            bugs.push_back("Resource leak: file opened but never closed");
        }
    }
    
    // 5. Integer overflow: arithmetic without bounds check
    if (code.find("* ") != std::string::npos && code.find("INT_MAX") == std::string::npos) {
        size_t mulPos = code.find("* ");
        if (mulPos != std::string::npos && mulPos > 0) {
            // Check if it's in an arithmetic context (not pointer)
            if (code[mulPos-1] != '*' && code[mulPos-1] != '(' && code[mulPos-1] != '=') {
                bugs.push_back("Potential integer overflow: multiplication without bounds check");
            }
        }
    }
    
    // 6. Use-after-free: delete followed by use
    size_t deletePos = 0;
    while ((deletePos = code.find("delete ", deletePos)) != std::string::npos) {
        size_t varStart = deletePos + 7;
        size_t varEnd = varStart;
        while (varEnd < code.length() && (isalnum((unsigned char)code[varEnd]) || code[varEnd] == '_'))
            varEnd++;
        std::string varName = code.substr(varStart, varEnd - varStart);
        // Check if variable is used after delete
        size_t nextUse = code.find(varName, varEnd);
        if (nextUse != std::string::npos && nextUse < varEnd + 500) {
            bugs.push_back("Use-after-free risk: " + varName + " used after delete");
        }
        deletePos = varEnd;
    }

    m_metrics->incrementCounter("bug_analysis_runs");
    return bugs;
}

std::vector<std::string> AdvancedCodingAgentIntegration::optimizeCode(
    const std::string& code) {


    std::vector<std::string> optimizations;
    
    optimizations.push_back("Use const references for large objects");
    optimizations.push_back("Cache repeated computations");
    optimizations.push_back("Use move semantics for large returns");

    m_metrics->incrementCounter("optimization_suggestions");
    return optimizations;
}

std::vector<SecurityIssue> AdvancedCodingAgentIntegration::scanSecurity(
    const std::string& code,
    const std::string& language) {


    std::vector<SecurityIssue> issues;
    
    // Real security analysis: detect common vulnerability patterns
    std::string lowerCode = code;
    std::transform(lowerCode.begin(), lowerCode.end(), lowerCode.begin(), ::tolower);
    
    // 1. Buffer overflow patterns
    if (lowerCode.find("strcpy(") != std::string::npos ||
        lowerCode.find("strcat(") != std::string::npos ||
        lowerCode.find("gets(") != std::string::npos) {
        SecurityIssue issue;
        issue.severity = "High";
        issue.category = "Buffer Overflow";
        issue.description = "Use of unsafe string functions (strcpy, strcat, gets) detected. Use strncpy, strncat, or fgets instead.";
        issue.location = "Global";
        issue.remediationSteps = {"Replace strcpy with strncpy", "Replace strcat with strncat", "Replace gets with fgets"};
        issues.push_back(issue);
    }
    
    // 2. SQL injection patterns
    if (lowerCode.find("sql") != std::string::npos &&
        (lowerCode.find("sprintf") != std::string::npos || lowerCode.find("+") != std::string::npos)) {
        SecurityIssue issue;
        issue.severity = "Critical";
        issue.category = "SQL Injection";
        issue.description = "Potential SQL injection: string concatenation in SQL query detected.";
        issue.location = "Global";
        issue.remediationSteps = {"Use parameterized queries", "Use prepared statements", "Validate all inputs"};
        issues.push_back(issue);
    }
    
    // 3. Command injection patterns
    if (lowerCode.find("system(") != std::string::npos ||
        lowerCode.find("popen(") != std::string::npos ||
        lowerCode.find("exec(") != std::string::npos) {
        SecurityIssue issue;
        issue.severity = "Critical";
        issue.category = "Command Injection";
        issue.description = "Use of system/popen/exec with potential user input detected.";
        issue.location = "Global";
        issue.remediationSteps = {"Avoid system calls with user input", "Use allowlists for commands", "Sanitize inputs"};
        issues.push_back(issue);
    }
    
    // 4. Memory leak patterns
    if (lowerCode.find("new ") != std::string::npos && lowerCode.find("delete") == std::string::npos) {
        SecurityIssue issue;
        issue.severity = "Medium";
        issue.category = "Memory Leak";
        issue.description = "Dynamic allocation without corresponding delete detected.";
        issue.location = "Global";
        issue.remediationSteps = {"Use smart pointers (std::unique_ptr, std::shared_ptr)", "Ensure delete matches every new"};
        issues.push_back(issue);
    }
    
    // 5. Integer overflow patterns
    if (lowerCode.find("malloc(") != std::string::npos || lowerCode.find("calloc(") != std::string::npos) {
        size_t pos = 0;
        while ((pos = lowerCode.find("malloc(", pos)) != std::string::npos) {
            size_t end = lowerCode.find(")", pos);
            if (end != std::string::npos) {
                std::string args = lowerCode.substr(pos + 7, end - pos - 7);
                if (args.find("*") != std::string::npos && args.find("sizeof") == std::string::npos) {
                    SecurityIssue issue;
                    issue.severity = "High";
                    issue.category = "Integer Overflow";
                    issue.description = "Potential integer overflow in malloc: multiplication without sizeof check.";
                    issue.location = "Line containing malloc";
                    issue.remediationSteps = {"Use calloc instead of malloc*", "Check for overflow before multiplication"};
                    issues.push_back(issue);
                    break;
                }
            }
            ++pos;
        }
    }
    
    // 6. Format string vulnerabilities
    if (lowerCode.find("printf(") != std::string::npos || lowerCode.find("fprintf(") != std::string::npos) {
        size_t pos = 0;
        while ((pos = lowerCode.find("printf(", pos)) != std::string::npos) {
            size_t end = lowerCode.find(")", pos);
            if (end != std::string::npos) {
                std::string args = lowerCode.substr(pos + 7, end - pos - 7);
                if (args.find("\"") == std::string::npos) {
                    SecurityIssue issue;
                    issue.severity = "Critical";
                    issue.category = "Format String Vulnerability";
                    issue.description = "Potential format string vulnerability: printf with variable format string.";
                    issue.location = "Line containing printf";
                    issue.remediationSteps = {"Use constant format strings", "Validate format string before use"};
                    issues.push_back(issue);
                    break;
                }
            }
            ++pos;
        }
    }

    m_metrics->incrementCounter("security_scans");
    return issues;
}

std::string AdvancedCodingAgentIntegration::buildFeaturePrompt(
    const FeatureRequest& request) {

    std::string prompt = "Generate " + request.language + " code for: ";
    prompt += request.description;
    return prompt;
}

bool AdvancedCodingAgentIntegration::validateGeneratedCode(const std::string& code) {
    // Basic syntax validation: check for balanced delimiters and non-empty content
    if (code.empty()) return false;

    int braces = 0, parens = 0, brackets = 0;
    bool inString = false;
    bool inLineComment = false;
    bool inBlockComment = false;
    char prev = 0;

    for (size_t i = 0; i < code.size(); ++i) {
        char c = code[i];

        if (inLineComment) {
            if (c == '\n') inLineComment = false;
            prev = c;
            continue;
        }
        if (inBlockComment) {
            if (c == '/' && prev == '*') inBlockComment = false;
            prev = c;
            continue;
        }
        if (inString) {
            if (c == '"' && prev != '\\') inString = false;
            prev = c;
            continue;
        }

        if (c == '/' && i + 1 < code.size()) {
            if (code[i + 1] == '/') { inLineComment = true; prev = c; continue; }
            if (code[i + 1] == '*') { inBlockComment = true; prev = c; continue; }
        }
        if (c == '"' && prev != '\\') { inString = true; prev = c; continue; }

        switch (c) {
            case '{': braces++; break;
            case '}': braces--; break;
            case '(': parens++; break;
            case ')': parens--; break;
            case '[': brackets++; break;
            case ']': brackets--; break;
        }

        // Negative count means closing without opening
        if (braces < 0 || parens < 0 || brackets < 0) return false;
        prev = c;
    }

    return braces == 0 && parens == 0 && brackets == 0;
}
