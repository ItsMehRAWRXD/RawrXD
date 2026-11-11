// ============================================================================
// IntelliSense.cpp - IntelliSense Engine Implementation
// ============================================================================

#include "IntelliSense.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <iostream>

namespace Sovereign {

IntelliSense::IntelliSense() = default;
IntelliSense::~IntelliSense() = default;

bool IntelliSense::Initialize() {
    InitializeDefaultSnippets();
    initialized_ = true;
    return true;
}

void IntelliSense::Shutdown() { snippets_.clear(); initialized_ = false; }

std::vector<CompletionItem> IntelliSense::AutoComplete(const std::string& context, const std::string& prefix, const std::string& language) {
    stats_.totalCompletions++;
    std::vector<CompletionItem> items;
    
    // Add language keywords
    auto keywords = GetLanguageKeywords(language);
    for (auto& kw : keywords) {
        if (kw.label.find(prefix) == 0 || prefix.empty()) {
            items.push_back(kw);
        }
    }
    
    // Add snippets
    auto snippets = GetLanguageSnippets(prefix, language);
    items.insert(items.end(), snippets.begin(), snippets.end());
    
    // Add symbols from context
    std::regex symbolRegex(R"(\b\w*" + prefix + R"(\w*\b)");
    std::smatch match;
    std::string::const_iterator searchStart(context.cbegin());
    while (std::regex_search(searchStart, context.cend(), match, symbolRegex)) {
        CompletionItem item;
        item.label = match.str();
        item.kind = "variable";
        item.score = 0.5f;
        items.push_back(item);
        searchStart = match.suffix().first;
    }
    
    // Sort by score
    std::sort(items.begin(), items.end(), [](const CompletionItem& a, const CompletionItem& b) {
        return a.score > b.score;
    });
    
    // Remove duplicates
    items.erase(std::unique(items.begin(), items.end(), [](const CompletionItem& a, const CompletionItem& b) {
        return a.label == b.label;
    }), items.end());
    
    return items;
}

std::vector<CompletionItem> IntelliSense::GetLanguageKeywords(const std::string& language) const {
    std::vector<CompletionItem> keywords;
    
    if (language == "cpp" || language == "c") {
        std::vector<std::string> cppKeywords = {
            "auto", "break", "case", "catch", "class", "const", "constexpr", "continue",
            "decltype", "default", "delete", "do", "else", "enum", "explicit", "export",
            "extern", "for", "friend", "goto", "if", "inline", "mutable", "namespace",
            "new", "noexcept", "operator", "override", "private", "protected", "public",
            "register", "return", "static", "struct", "switch", "template", "this",
            "throw", "try", "typedef", "typename", "union", "using", "virtual", "void", "while"
        };
        for (const auto& kw : cppKeywords) {
            CompletionItem item;
            item.label = kw;
            item.kind = "keyword";
            item.score = 0.8f;
            keywords.push_back(item);
        }
    } else if (language == "python") {
        std::vector<std::string> pyKeywords = {
            "False", "None", "True", "and", "as", "assert", "async", "await",
            "break", "class", "continue", "def", "del", "elif", "else", "except",
            "finally", "for", "from", "global", "if", "import", "in", "is",
            "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
            "try", "while", "with", "yield"
        };
        for (const auto& kw : pyKeywords) {
            CompletionItem item;
            item.label = kw;
            item.kind = "keyword";
            item.score = 0.8f;
            keywords.push_back(item);
        }
    }
    
    return keywords;
}

std::vector<CompletionItem> IntelliSense::GetLanguageSnippets(const std::string& prefix, const std::string& language) const {
    std::vector<CompletionItem> items;
    for (const auto& snip : snippets_) {
        if (snip.language == language && snip.prefix.find(prefix) == 0) {
            CompletionItem item;
            item.label = snip.name;
            item.detail = snip.prefix;
            item.insertText = snip.body;
            item.kind = "snippet";
            item.score = 0.9f;
            items.push_back(item);
        }
    }
    return items;
}

SignatureHelp IntelliSense::GetSignatureHelpForFunction(const std::string& function) {
    stats_.totalSignatures++;
    SignatureHelp help;
    help.signature = function + "(...)";
    help.documentation = "Documentation for " + function;
    
    ParameterHint p1;
    p1.label = "param1";
    p1.documentation = "First parameter";
    p1.isOptional = false;
    help.parameters.push_back(p1);
    
    ParameterHint p2;
    p2.label = "param2";
    p2.documentation = "Second parameter (optional)";
    p2.isOptional = true;
    help.parameters.push_back(p2);
    
    help.activeParameter = 0;
    help.activeSignature = 0;
    return help;
}

void IntelliSense::InitializeDefaultSnippets() {
    // C++ snippets
    snippets_.push_back({"for loop", "for", "for (int i = 0; i < n; ++i) {\n    \n}", "cpp"});
    snippets_.push_back({"for range", "forr", "for (auto& item : items) {\n    \n}", "cpp"});
    snippets_.push_back({"if", "if", "if (condition) {\n    \n}", "cpp"});
    snippets_.push_back({"else", "else", "} else {\n    \n}", "cpp"});
    snippets_.push_back({"class", "class", "class Name {\npublic:\n    Name();\n    ~Name();\nprivate:\n    \n};", "cpp"});
    snippets_.push_back({"function", "fn", "ReturnType functionName(Params) {\n    \n}", "cpp"});
    snippets_.push_back({"namespace", "ns", "namespace Name {\n    \n} // namespace Name", "cpp"});
    snippets_.push_back({"include", "inc", "#include <iostream>", "cpp"});
    snippets_.push_back({"main", "main", "int main(int argc, char* argv[]) {\n    \n    return 0;\n}", "cpp"});
    
    // Python snippets
    snippets_.push_back({"function", "def", "def function_name(args):\n    pass", "python"});
    snippets_.push_back({"class", "class", "class ClassName:\n    def __init__(self):\n        pass", "python"});
    snippets_.push_back({"for", "for", "for item in items:\n    ", "python"});
    snippets_.push_back({"if", "if", "if condition:\n    ", "python"});
    snippets_.push_back({"import", "import", "import module_name", "python"});
    snippets_.push_back({"main", "main", "if __name__ == \"__main__\":\n    ", "python"});
    
    stats_.totalSnippets = snippets_.size();
}

} // namespace Sovereign
