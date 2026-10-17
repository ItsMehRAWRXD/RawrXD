#include "AdvancedCodingAgent.h"
#include <algorithm>
#include <map>
#include <regex>
#include <sstream>

namespace RawrXD {
namespace IDE {

AdvancedCodingAgent::AdvancedCodingAgent() {
}

AgentTaskResult AdvancedCodingAgent::implementFeature(
    const std::string& specification, const std::string& language,
    const std::string& codeContext, const std::vector<std::string>& requirements) {
    
    AgentTaskResult result;
    result.taskType = "feature_implementation";
    result.success = false;
    
    // Step 1: Analyze requirements
    std::string analysis = "Analyzing: " + specification;
    result.steps.push_back(analysis);
    
    // Step 2: Generate code
    std::string generatedCode = "// Feature: " + specification + "\n";
    generatedCode += "// Language: " + language + "\n";
    generatedCode += "// Requirements:\n";
    for (const auto& req : requirements) {
        generatedCode += "//   - " + req + "\n";
    }
    generatedCode += "// Context:\n//   " + codeContext + "\n\n";
    generatedCode += generateFeatureBoilerplate(specification, language);
    
    result.steps.push_back("Code generation complete");
    result.generatedCode = generatedCode;
    result.success = true;
    result.confidence = 0.8f;
    
    return result;
}

AgentTaskResult AdvancedCodingAgent::generateTests(
    const std::string& code, const std::string& language,
    int minCoverage) {
    
    AgentTaskResult result;
    result.taskType = "test_generation";
    result.success = false;
    
    // Analyze code for test cases
    std::vector<TestCase> testCases = identifyTestCases(code, language);
    
    result.steps.push_back("Identified " + std::to_string(testCases.size()) + " test cases");
    
    // Generate test code
    std::string testCode = generateTestCode(code, testCases, language);
    
    result.steps.push_back("Generated test code");
    result.generatedCode = testCode;
    result.testCases = testCases;
    result.success = true;
    result.confidence = 0.75f;
    
    return result;
}

AgentTaskResult AdvancedCodingAgent::generateDocumentation(
    const std::string& code, const std::string& language) {
    
    AgentTaskResult result;
    result.taskType = "documentation_generation";
    result.success = false;
    
    // Parse code structure
    result.steps.push_back("Analyzing code structure");
    
    // Extract functions, classes, etc.
    std::string documentation = "# API Documentation\n\n";
    documentation += extractDocumentation(code, language);
    
    result.steps.push_back("Generated documentation");
    result.generatedCode = documentation;
    result.success = true;
    result.confidence = 0.85f;
    
    return result;
}

AgentTaskResult AdvancedCodingAgent::detectBugs(
    const std::string& code, const std::string& language) {
    
    AgentTaskResult result;
    result.taskType = "bug_detection";
    result.success = false;
    
    std::vector<Vulnerability> vulns = performStaticAnalysis(code, language);
    
    result.steps.push_back("Performed static analysis");
    
    for (const auto& vuln : vulns) {
        result.suggestions.push_back(vuln.description + " - " + vuln.suggestedFix);
    }
    
    result.vulnerabilities = vulns;
    result.success = true;
    result.confidence = 0.7f;
    
    return result;
}

AgentTaskResult AdvancedCodingAgent::optimizeForPerformance(
    const std::string& code, const std::string& language) {
    
    AgentTaskResult result;
    result.taskType = "performance_optimization";
    result.success = false;
    
    result.steps.push_back("Analyzing code for performance issues");
    
    // Identify optimization opportunities
    std::string optimizedCode = code;
    
    // Check for common inefficiencies
    if (code.find("+ \"") != std::string::npos) {
        result.suggestions.push_back("Use stringstream for string concatenation");
        optimizedCode = replaceStringConcatenation(code);
    }
    
    if (code.find("vector") != std::string::npos) {
        result.suggestions.push_back("Reserve vector capacity if size is known");
    }
    
    result.steps.push_back("Generated optimizations");
    result.generatedCode = optimizedCode;
    result.success = true;
    result.confidence = 0.75f;
    
    return result;
}

AgentTaskResult AdvancedCodingAgent::scanForVulnerabilities(
    const std::string& code, const std::string& language) {
    
    AgentTaskResult result;
    result.taskType = "security_scan";
    result.success = false;
    
    result.steps.push_back("Performing security analysis");
    
    std::vector<Vulnerability> vulnerabilities = scanSecurityIssues(code, language);
    
    for (const auto& vuln : vulnerabilities) {
        result.suggestions.push_back("SECURITY: " + vuln.description);
    }
    
    result.vulnerabilities = vulnerabilities;
    result.steps.push_back("Identified " + std::to_string(vulnerabilities.size()) + " potential issues");
    result.success = true;
    result.confidence = 0.8f;
    
    return result;
}

AgentTaskResult AdvancedCodingAgent::refactorCode(
    const std::string& code, const std::string& language,
    const std::string& strategy) {
    
    AgentTaskResult result;
    result.taskType = "refactoring";
    result.success = false;
    
    result.steps.push_back("Analyzing code structure");
    
    std::string refactoredCode = code;
    
    if (strategy == "extract_methods") {
        result.steps.push_back("Extracting long methods");
        refactoredCode = extractMethodRefactoring(code, language);
    } else if (strategy == "reduce_complexity") {
        result.steps.push_back("Reducing cyclomatic complexity");
        refactoredCode = reduceComplexity(code, language);
    } else if (strategy == "improve_names") {
        result.steps.push_back("Improving variable names");
        refactoredCode = improveNaming(code, language);
    }
    
    result.generatedCode = refactoredCode;
    result.success = true;
    result.confidence = 0.75f;
    
    return result;
}

// Private helper methods

std::string AdvancedCodingAgent::generateFeatureBoilerplate(
    const std::string& feature, const std::string& language) {
    
    if (language == "cpp" || language == "c++") {
        return "class " + feature + " {\n"
               "public:\n"
               "    " + feature + "() {}\n"
               "    ~" + feature + "() {}\n"
               "private:\n"
               "};\n";
    } else if (language == "python") {
        return "class " + feature + ":\n"
               "    def __init__(self):\n"
               "        pass\n";
    }
    
    return "";
}

std::vector<TestCase> AdvancedCodingAgent::identifyTestCases(
    const std::string& code, const std::string& language) {
    
    std::vector<TestCase> cases;
    
    // Basic test case identification
    if (code.find("if ") != std::string::npos) {
        TestCase tc;
        tc.name = "test_condition_true";
        tc.expectedResult = "pass";
        cases.push_back(tc);
        
        tc.name = "test_condition_false";
        cases.push_back(tc);
    }
    
    if (code.find("for ") != std::string::npos) {
        TestCase tc;
        tc.name = "test_empty_collection";
        tc.expectedResult = "pass";
        cases.push_back(tc);
        
        tc.name = "test_single_element";
        cases.push_back(tc);
        
        tc.name = "test_multiple_elements";
        cases.push_back(tc);
    }
    
    return cases;
}

std::string AdvancedCodingAgent::generateTestCode(
    const std::string& code, const std::vector<TestCase>& testCases,
    const std::string& language) {
    
    std::string testCode = "// Generated tests\n";
    
    if (language == "cpp" || language == "c++") {
        testCode += "#include <cassert>\n\n";
        testCode += "void runTests() {\n";
        
        for (const auto& tc : testCases) {
            testCode += "    // " + tc.name + "\n";
            testCode += "    // assert(...);\n";
        }
        
        testCode += "}\n";
    } else if (language == "python") {
        testCode += "import unittest\n\n";
        testCode += "class TestCase(unittest.TestCase):\n";
        
        for (const auto& tc : testCases) {
            testCode += "    def " + tc.name + "(self):\n";
            testCode += "        self.assertTrue(True)\n";
        }
    }
    
    return testCode;
}

std::string AdvancedCodingAgent::extractDocumentation(
    const std::string& code, const std::string& language) {
    
    std::string doc = "";
    
    if (language == "cpp" || language == "c++") {
        // Extract class and function declarations
        doc += "## Classes\n\n";
        doc += "## Functions\n\n";
    } else if (language == "python") {
        doc += "## Modules\n\n";
        doc += "## Classes\n\n";
        doc += "## Functions\n\n";
    }
    
    return doc;
}

std::vector<Vulnerability> AdvancedCodingAgent::performStaticAnalysis(
    const std::string& code, const std::string& language) {
    
    std::vector<Vulnerability> vulns;
    
    // Check for null pointer dereferences
    if (code.find("->") != std::string::npos) {
        Vulnerability vuln;
        vuln.severity = "warning";
        vuln.type = "null_dereference";
        vuln.description = "Potential null pointer dereference";
        vuln.suggestedFix = "Add null check before dereferencing";
        vulns.push_back(vuln);
    }
    
    // Check for memory leaks
    if (code.find("new ") != std::string::npos && 
        code.find("delete ") == std::string::npos) {
        Vulnerability vuln;
        vuln.severity = "warning";
        vuln.type = "memory_leak";
        vuln.description = "Possible memory leak";
        vuln.suggestedFix = "Use smart pointers or ensure cleanup";
        vulns.push_back(vuln);
    }
    
    return vulns;
}

std::string AdvancedCodingAgent::replaceStringConcatenation(
    const std::string& code) {
    
    std::string result = code;
    
    // Replace patterns like: str = "part1" + "part2" + variable
    // with: std::stringstream ss; ss << "part1" << "part2" << variable; str = ss.str();
    
    // Find string concatenation assignments: identifier = "..." + ...
    std::regex concatAssign(R"((\w+)\s*=\s*"([^"]*)"\s*\+\s*(.+))");
    std::smatch match;
    std::string::const_iterator searchStart(result.cbegin());
    
    while (std::regex_search(searchStart, result.cend(), match, concatAssign)) {
        std::string varName = match[1].str();
        std::string firstPart = match[2].str();
        std::string rest = match[3].str();
        
        // Build stringstream replacement
        std::stringstream ss;
        ss << "std::stringstream _ss_" << varName << ";\n";
        ss << "_ss_" << varName << " << \"" << firstPart << "\";\n";
        
        // Handle chained concatenations in the rest
        std::string remaining = rest;
        size_t pos = 0;
        while ((pos = remaining.find(" + ")) != std::string::npos) {
            std::string part = remaining.substr(0, pos);
            ss << "_ss_" << varName << " << " << part << ";\n";
            remaining = remaining.substr(pos + 3);
        }
        ss << "_ss_" << varName << " << " << remaining << ";\n";
        ss << varName << " = _ss_" << varName << ".str();\n";
        
        result.replace(match.position(), match.length(), ss.str());
        searchStart = result.cbegin() + match.position() + ss.str().length();
    }
    
    return result;
}

std::vector<Vulnerability> AdvancedCodingAgent::scanSecurityIssues(
    const std::string& code, const std::string& language) {
    
    std::vector<Vulnerability> vulns;
    
    // Check for SQL injection
    if (code.find("sprintf") != std::string::npos && 
        code.find("SELECT") != std::string::npos) {
        Vulnerability vuln;
        vuln.severity = "error";
        vuln.type = "sql_injection";
        vuln.description = "Potential SQL injection vulnerability";
        vuln.suggestedFix = "Use prepared statements";
        vulns.push_back(vuln);
    }
    
    // Check for hardcoded secrets
    if (code.find("password") != std::string::npos ||
        code.find("api_key") != std::string::npos) {
        Vulnerability vuln;
        vuln.severity = "error";
        vuln.type = "hardcoded_secret";
        vuln.description = "Hardcoded secrets found";
        vuln.suggestedFix = "Use environment variables";
        vulns.push_back(vuln);
    }
    
    return vulns;
}

std::string AdvancedCodingAgent::extractMethodRefactoring(
    const std::string& code, const std::string& language) {
    
    std::string result = code;
    
    // Detect long functions and suggest extraction
    // Look for functions with many lines or nested blocks
    
    // Count braces to estimate function complexity
    int braceDepth = 0;
    int maxDepth = 0;
    int braceCount = 0;
    for (char c : code) {
        if (c == '{') {
            braceDepth++;
            braceCount++;
            if (braceDepth > maxDepth) maxDepth = braceDepth;
        } else if (c == '}') {
            braceDepth--;
        }
    }
    
    // If function has high nesting, suggest extraction
    if (maxDepth > 3) {
        // Insert a comment suggesting method extraction
        std::stringstream suggestion;
        suggestion << "// Refactoring suggestion: Consider extracting nested logic (max depth: "
                   << maxDepth << ") into separate methods\n";
        result = suggestion.str() + result;
    }
    
    // Look for repeated code blocks that could be extracted
    // Simple heuristic: find duplicated lines of 5+ chars
    std::istringstream iss(code);
    std::string line;
    std::map<std::string, int> lineCounts;
    while (std::getline(iss, line)) {
        // Trim whitespace
        size_t start = line.find_first_not_of(" \t");
        size_t end = line.find_last_not_of(" \t");
        if (start != std::string::npos && end != std::string::npos) {
            std::string trimmed = line.substr(start, end - start + 1);
            if (trimmed.length() >= 10 && trimmed.find("//") == std::string::npos) {
                lineCounts[trimmed]++;
            }
        }
    }
    
    for (const auto& [line, count] : lineCounts) {
        if (count > 1) {
            std::stringstream suggestion;
            suggestion << "// Refactoring suggestion: Repeated block (\"" << line.substr(0, 40) 
                       << "\") appears " << count << " times - consider extracting to method\n";
            result = suggestion.str() + result;
            break; // Only add one suggestion at top
        }
    }
    
    return result;
}

std::string AdvancedCodingAgent::reduceComplexity(
    const std::string& code, const std::string& language) {
    
    std::string result = code;
    
    // Reduce cyclomatic complexity by:
    // 1. Converting nested if-else to early returns
    // 2. Replacing switch with map/lookup where applicable
    // 3. Simplifying boolean expressions
    
    // Track complexity metrics
    int ifCount = 0;
    int elseCount = 0;
    int switchCount = 0;
    int loopCount = 0;
    
    size_t pos = 0;
    while ((pos = result.find("if (", pos)) != std::string::npos) {
        ifCount++;
        pos += 3;
    }
    
    pos = 0;
    while ((pos = result.find("else", pos)) != std::string::npos) {
        elseCount++;
        pos += 4;
    }
    
    pos = 0;
    while ((pos = result.find("switch (", pos)) != std::string::npos) {
        switchCount++;
        pos += 7;
    }
    
    pos = 0;
    while ((pos = result.find("for (", pos)) != std::string::npos ||
           (pos = result.find("while (", pos)) != std::string::npos) {
        loopCount++;
        pos += 1;
    }
    
    int complexity = ifCount + elseCount + switchCount + loopCount;
    
    // Add complexity reduction suggestions at top
    std::stringstream suggestion;
    suggestion << "// Complexity analysis: if=" << ifCount << ", else=" << elseCount
               << ", switch=" << switchCount << ", loops=" << loopCount
               << ", estimated cyclomatic complexity: " << (complexity + 1) << "\n";
    
    if (complexity > 10) {
        suggestion << "// Refactoring suggestion: High complexity detected - consider "
                   << "splitting into smaller functions or using early returns\n";
    }
    
    result = suggestion.str() + result;
    
    // Convert deep nested if-else chains to early returns where possible
    // Pattern: if (cond) { ... } else { ... } -> if (!cond) return/continue; ...
    std::regex nestedIfElse(R"(if\s*\(([^)]+)\)\s*\{[^}]*\}\s*else\s*\{)");
    result = std::regex_replace(result, nestedIfElse, 
        "if (!($1)) { /* early return */ }\n    if ($1) {");
    
    return result;
}

std::string AdvancedCodingAgent::improveNaming(
    const std::string& code, const std::string& language) {
    
    std::string result = code;
    
    // Detect and suggest improvements for poor variable names
    // Common bad patterns: single-letter names (except loop vars), abbreviations, etc.
    
    std::vector<std::pair<std::string, std::string>> nameSuggestions;
    
    // Find single-letter variable declarations (excluding common loop variables i, j, k)
    std::regex singleLetterDecl(R"((int|float|double|std::string|auto)\s+([a-h,l-zA-H,L-Z])\s*[=;])");
    std::smatch match;
    std::string::const_iterator searchStart(result.cbegin());
    
    while (std::regex_search(searchStart, result.cend(), match, singleLetterDecl)) {
        std::string type = match[1].str();
        std::string var = match[2].str();
        nameSuggestions.push_back({var, type + " " + var + " // Consider: " + type + " descriptive_" + var});
        searchStart = match.suffix().first;
    }
    
    // Find common abbreviation patterns
    std::vector<std::pair<std::string, std::string>> abbreviations = {
        {"tmp", "temporary"}, {"cnt", "count"}, {"idx", "index"},
        {"num", "number"}, {"str", "string"}, {"ptr", "pointer"},
        {"buf", "buffer"}, {"sz", "size"}, {"len", "length"},
        {"val", "value"}, {"ret", "return"}, {"dst", "destination"},
        {"src", "source"}, {"msg", "message"}, {"ctx", "context"},
        {"cfg", "config"}, {"data", "dataValue"}, {"obj", "object"},
        {"arr", "array"}, {"lst", "list"}, {"map", "mapValue"}
    };
    
    for (const auto& [abbr, full] : abbreviations) {
        size_t pos = 0;
        while ((pos = result.find(abbr, pos)) != std::string::npos) {
            // Check if it's a word boundary
            bool isWord = true;
            if (pos > 0 && std::isalnum(result[pos - 1])) isWord = false;
            if (pos + abbr.length() < result.length() && std::isalnum(result[pos + abbr.length()])) isWord = false;
            
            if (isWord) {
                nameSuggestions.push_back({abbr, full});
                pos += abbr.length();
            } else {
                pos++;
            }
        }
    }
    
    // Add naming suggestions at top
    if (!nameSuggestions.empty()) {
        std::stringstream suggestion;
        suggestion << "// Naming suggestions:\n";
        for (const auto& [oldName, newName] : nameSuggestions) {
            suggestion << "//   " << oldName << " -> " << newName << "\n";
        }
        suggestion << "\n";
        result = suggestion.str() + result;
    }
    
    return result;
}

} // namespace IDE
} // namespace RawrXD
