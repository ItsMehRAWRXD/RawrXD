// ============================================================================
// SpecializedAgents.cpp - Specialized Agent Implementations
// ============================================================================

#include "SpecializedAgents.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iostream>

namespace Sovereign {

// ============================================================
// CodeCompletionAgent
// ============================================================

CodeCompletionAgent::CodeCompletionAgent() = default;
CodeCompletionAgent::~CodeCompletionAgent() { Shutdown(); }

bool CodeCompletionAgent::Initialize(const std::string& modelPath) {
    initialized_ = true;
    return true;
}

void CodeCompletionAgent::Shutdown() { initialized_ = false; }

std::vector<std::string> CodeCompletionAgent::Complete(const std::string& context, const std::string& prefix, size_t maxSuggestions) {
    std::vector<std::string> suggestions;
    stats_.totalCompletions++;
    
    // Simple completion: find matching symbols in context
    std::regex symbolRegex(R"(\b\w*" + prefix + R"(\w*\b)");
    std::smatch match;
    std::string::const_iterator searchStart(context.cbegin());
    
    while (std::regex_search(searchStart, context.cend(), match, symbolRegex) && suggestions.size() < maxSuggestions) {
        suggestions.push_back(match.str());
        searchStart = match.suffix().first;
    }
    
    // Remove duplicates
    std::sort(suggestions.begin(), suggestions.end());
    suggestions.erase(std::unique(suggestions.begin(), suggestions.end()), suggestions.end());
    
    return suggestions;
}

std::vector<std::string> CodeCompletionAgent::CompleteLine(const std::string& line, const std::string& fileExtension) {
    std::vector<std::string> suggestions;
    
    // Language-specific completions
    if (fileExtension == ".cpp" || fileExtension == ".hpp") {
        if (line.find("#include") != std::string::npos) {
            suggestions = {"<iostream>", "<vector>", "<string>", "<memory>", "<fstream>", "<algorithm>", "<map>", "<set>"};
        } else if (line.find("for") != std::string::npos) {
            suggestions = {"for (int i = 0; i < n; ++i) {", "for (auto& item : items) {", "for (size_t i = 0; i < size(); ++i) {"};
        } else if (line.find("class") != std::string::npos) {
            suggestions = {"class Name { public: Name(); ~Name(); private: };", "class Name : public Base { public: };", "class Name final { public: explicit Name(); };"};
        }
    } else if (fileExtension == ".py") {
        if (line.find("import") != std::string::npos) {
            suggestions = {"import os", "import sys", "import json", "import numpy as np", "import torch", "from typing import "};
        } else if (line.find("def ") != std::string::npos) {
            suggestions = {"def function_name(args):", "def __init__(self):", "def __str__(self): return \"\""};
        } else if (line.find("class ") != std::string::npos) {
            suggestions = {"class ClassName:", "class ClassName(BaseClass):", "class ClassName(ABC):"};
        }
    }
    
    return suggestions;
}

std::vector<std::string> CodeCompletionAgent::CompleteSymbol(const std::string& symbolName, const std::vector<std::string>& availableSymbols) {
    std::vector<std::string> matches;
    std::string lower = symbolName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& sym : availableSymbols) {
        std::string symLower = sym;
        std::transform(symLower.begin(), symLower.end(), symLower.begin(), ::tolower);
        if (symLower.find(lower) != std::string::npos) {
            matches.push_back(sym);
        }
    }
    
    return matches;
}

// ============================================================
// DocumentationAgent
// ============================================================

DocumentationAgent::DocumentationAgent() = default;
DocumentationAgent::~DocumentationAgent() = default;

bool DocumentationAgent::Initialize() { return true; }
void DocumentationAgent::Shutdown() {}

std::string DocumentationAgent::GenerateDoc(const std::string& code, const std::string& language) {
    stats_.totalDocs++;
    std::stringstream doc;
    
    if (language == "cpp") {
        doc << "/**\n * @brief " << (code.size() > 50 ? code.substr(0, 50) + "..." : code) << "\n";
        doc << " * \n";
        // Extract parameters
        std::regex paramRegex(R"((\w+)\s+(\w+)\s*[,)])");
        std::smatch match;
        std::string::const_iterator searchStart(code.cbegin());
        while (std::regex_search(searchStart, code.cend(), match, paramRegex)) {
            doc << " * @param " << match[2] << " Description of " << match[2] << "\n";
            searchStart = match.suffix().first;
        }
        doc << " * @return Description of return value\n */\n";
    } else if (language == "python") {
        doc << "\"\"\"\n" << (code.size() > 50 ? code.substr(0, 50) + "..." : code) << "\n\n";
        std::regex paramRegex(R"((\w+)\s*[:=])");
        std::smatch match;
        std::string::const_iterator searchStart(code.cbegin());
        while (std::regex_search(searchStart, code.cend(), match, paramRegex)) {
            doc << "Args:\n    " << match[1] << ": Description\n";
            searchStart = match.suffix().first;
        }
        doc << "Returns:\n    Description of return value\n\"\"\"\n";
    }
    
    stats_.totalTokens += doc.str().size() / 4;
    return doc.str();
}

std::string DocumentationAgent::GenerateFunctionDoc(const std::string& functionName, const std::vector<std::string>& params, const std::string& returnType) {
    std::stringstream doc;
    doc << "/**\n * @brief " << functionName << "\n * \n";
    for (const auto& p : params) doc << " * @param " << p << " Description\n";
    doc << " * @return " << (returnType.empty() ? "void" : returnType) << "\n */\n";
    return doc.str();
}

std::string DocumentationAgent::GenerateFileHeader(const std::string& fileName, const std::string& author, const std::string& description) {
    std::stringstream doc;
    doc << "// ============================================================================\n";
    doc << "// " << fileName << "\n";
    if (!description.empty()) doc << "// " << description << "\n";
    if (!author.empty()) doc << "// Author: " << author << "\n";
    doc << "// ============================================================================\n\n";
    return doc.str();
}

// ============================================================
// SecurityAuditAgent
// ============================================================

SecurityAuditAgent::SecurityAuditAgent() = default;
SecurityAuditAgent::~SecurityAuditAgent() = default;

bool SecurityAuditAgent::Initialize() { return true; }
void SecurityAuditAgent::Shutdown() {}

std::vector<std::string> SecurityAuditAgent::AuditFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file) return {"Cannot open file: " + filePath};
    std::stringstream ss;
    ss << file.rdbuf();
    return AuditCode(ss.str(), "cpp");
}

std::vector<std::string> SecurityAuditAgent::AuditCode(const std::string& code, const std::string& language) {
    std::vector<std::string> findings;
    stats_.totalAudits++;
    
    auto secrets = CheckForSecrets(code);
    findings.insert(findings.end(), secrets.begin(), secrets.end());
    
    auto injections = CheckForInjections(code);
    findings.insert(findings.end(), injections.begin(), injections.end());
    
    auto unsafe = CheckForUnsafeFunctions(code);
    findings.insert(findings.end(), unsafe.begin(), unsafe.end());
    
    stats_.totalFindings += findings.size();
    for (const auto& f : findings) {
        if (f.find("CRITICAL") != std::string::npos) stats_.criticalFindings++;
    }
    
    return findings;
}

std::vector<std::string> SecurityAuditAgent::CheckForSecrets(const std::string& code) {
    std::vector<std::string> findings;
    std::vector<std::pair<std::regex, std::string>> patterns = {
        {std::regex(R"((?:api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"])", std::regex::icase), "CRITICAL: Hardcoded API key detected"},
        {std::regex(R"(-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----)"), "CRITICAL: Private key detected in source"},
        {std::regex(R"(gh[pousr]_[A-Za-z0-9_]{36,})"), "CRITICAL: GitHub token detected"},
        {std::regex(R"(password\s*[:=]\s*['\"][^'\"]+['\"])", std::regex::icase), "HIGH: Hardcoded password detected"},
        {std::regex(R"(Bearer\s+[A-Za-z0-9\-._~+/]{20,})", std::regex::icase), "HIGH: Bearer token detected"},
    };
    
    for (const auto& [pattern, message] : patterns) {
        if (std::regex_search(code, pattern)) {
            findings.push_back(message);
        }
    }
    return findings;
}

std::vector<std::string> SecurityAuditAgent::CheckForInjections(const std::string& code) {
    std::vector<std::string> findings;
    if (std::regex_search(code, std::regex(R"(system\s*\([^)]*\))"))) {
        findings.push_back("HIGH: system() call - potential command injection");
    }
    if (std::regex_search(code, std::regex(R"(popen\s*\([^)]*\))"))) {
        findings.push_back("HIGH: popen() call - potential command injection");
    }
    if (std::regex_search(code, std::regex(R"(eval\s*\([^)]*\))"))) {
        findings.push_back("HIGH: eval() call - potential code injection");
    }
    if (std::regex_search(code, std::regex(R"(exec\s*\([^)]*\))"))) {
        findings.push_back("HIGH: exec() call - potential code injection");
    }
    return findings;
}

std::vector<std::string> SecurityAuditAgent::CheckForUnsafeFunctions(const std::string& code) {
    std::vector<std::string> findings;
    if (std::regex_search(code, std::regex(R"(\bstrcpy\s*\()"))) findings.push_back("MEDIUM: strcpy() - use strcpy_s or std::string");
    if (std::regex_search(code, std::regex(R"(\bstrcat\s*\()"))) findings.push_back("MEDIUM: strcat() - use strcat_s or std::string");
    if (std::regex_search(code, std::regex(R"(\bsprintf\s*\()"))) findings.push_back("MEDIUM: sprintf() - use snprintf or std::format");
    if (std::regex_search(code, std::regex(R"(\bgets\s*\()"))) findings.push_back("CRITICAL: gets() - use fgets");
    if (std::regex_search(code, std::regex(R"(\balloca\s*\()"))) findings.push_back("MEDIUM: alloca() - potential stack overflow");
    return findings;
}

// ============================================================
// DependencyUpdateAgent
// ============================================================

DependencyUpdateAgent::DependencyUpdateAgent() = default;
DependencyUpdateAgent::~DependencyUpdateAgent() = default;

bool DependencyUpdateAgent::Initialize() { return true; }
void DependencyUpdateAgent::Shutdown() {}

std::vector<std::pair<std::string, std::string>> DependencyUpdateAgent::CheckUpdates(const std::string& projectPath) {
    std::vector<std::pair<std::string, std::string>> updates;
    stats_.totalChecks++;
    return updates;
}

bool DependencyUpdateAgent::UpdateDependency(const std::string& name, const std::string& newVersion) {
    stats_.totalUpdates++;
    return true;
}

std::vector<std::string> DependencyUpdateAgent::GetOutdatedDependencies(const std::string& projectPath) {
    return {};
}

} // namespace Sovereign
