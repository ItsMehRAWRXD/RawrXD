// ============================================================================
// IDEEditor.cpp - Core IDE Editor Features Implementation
// ============================================================================

#include "IDEEditor.hpp"
#include <fstream>
#include <sstream>
#include <stack>
#include <regex>
#include <algorithm>
#include <iostream>

namespace Sovereign {

IDEEditor::IDEEditor() = default;
IDEEditor::~IDEEditor() = default;

bool IDEEditor::Initialize() { initialized_ = true; return true; }
void IDEEditor::Shutdown() { initialized_ = false; }

std::vector<FoldingRegion> IDEEditor::ComputeFoldingRegions(const std::string& code, const std::string& language) {
    std::vector<FoldingRegion> regions;
    std::stack<std::pair<uint32_t, int>> braceStack; // line, level
    
    std::istringstream stream(code);
    std::string line;
    uint32_t lineNum = 0;
    int level = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Count braces
        for (char c : line) {
            if (c == '{' || c == '(' || c == '[') {
                braceStack.push({lineNum, level});
                level++;
            } else if (c == '}' || c == ')' || c == ']') {
                if (!braceStack.empty()) {
                    auto [startLine, startLevel] = braceStack.top();
                    braceStack.pop();
                    level--;
                    
                    if (lineNum - startLine > 1) {
                        FoldingRegion region;
                        region.range.start = {startLine, 0};
                        region.range.end = {lineNum, 0};
                        region.isCollapsed = false;
                        region.level = startLevel;
                        region.placeholder = "...";
                        regions.push_back(region);
                    }
                }
            }
        }
        
        // Check for #region / #endregion
        if (line.find("#region") != std::string::npos) {
            braceStack.push({lineNum, level});
        } else if (line.find("#endregion") != std::string::npos) {
            if (!braceStack.empty()) {
                auto [startLine, startLevel] = braceStack.top();
                braceStack.pop();
                if (lineNum - startLine > 1) {
                    FoldingRegion region;
                    region.range.start = {startLine, 0};
                    region.range.end = {lineNum, 0};
                    region.isCollapsed = false;
                    region.level = startLevel;
                    regions.push_back(region);
                }
            }
        }
    }
    
    return regions;
}

std::vector<BracketMatch> IDEEditor::FindBrackets(const std::string& code) {
    std::vector<BracketMatch> matches;
    std::stack<std::pair<EditorPosition, char>> bracketStack;
    
    std::istringstream stream(code);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        for (uint32_t col = 0; col < line.size(); ++col) {
            char c = line[col];
            if (c == '(' || c == '[' || c == '{') {
                bracketStack.push({{lineNum, col}, c});
            } else if (c == ')' || c == ']' || c == '}') {
                if (!bracketStack.empty()) {
                    auto [openPos, openBracket] = bracketStack.top();
                    bracketStack.pop();
                    if (GetMatchingBracket(openBracket) == c) {
                        BracketMatch match;
                        match.open = openPos;
                        match.close = {lineNum, col};
                        match.bracket = openBracket;
                        matches.push_back(match);
                    }
                }
            }
        }
    }
    
    return matches;
}

BracketMatch IDEEditor::FindMatchingBracket(const std::string& code, EditorPosition pos) {
    auto brackets = FindBrackets(code);
    for (const auto& b : brackets) {
        if ((b.open.line == pos.line && b.open.column == pos.column) ||
            (b.close.line == pos.line && b.close.column == pos.column)) {
            return b;
        }
    }
    return {};
}

DefinitionLocation IDEEditor::GoToDefinition(const std::string& symbol, const std::string& workspace) {
    stats_.totalDefinitions++;
    DefinitionLocation loc;
    loc.symbolName = symbol;
    
    // Search for definition patterns
    std::vector<std::string> patterns = {
        "class " + symbol, "struct " + symbol, "enum " + symbol,
        symbol + "(", symbol + "::", "using " + symbol,
        "typedef.*" + symbol, symbol + "\\s*="
    };
    
    for (const auto& entry : std::filesystem::recursive_directory_iterator(workspace, std::filesystem::directory_options::skip_permission_denied)) {
        if (!entry.is_regular_file()) continue;
        std::ifstream file(entry.path());
        std::string line;
        int lineNum = 0;
        while (std::getline(file, line)) {
            lineNum++;
            for (const auto& pattern : patterns) {
                if (line.find(pattern) != std::string::npos) {
                    loc.file = entry.path().string();
                    loc.position = {(uint32_t)lineNum, 0};
                    return loc;
                }
            }
        }
    }
    
    return loc;
}

HoverInfo IDEEditor::GetHoverInfo(const std::string& file, EditorPosition pos) {
    stats_.totalHovers++;
    HoverInfo info;
    
    std::ifstream f(file);
    if (!f) return info;
    
    std::string line;
    int lineNum = 0;
    while (std::getline(f, line)) {
        lineNum++;
        if (lineNum == pos.line) {
            // Extract symbol at position
            std::regex wordRegex(R"(\b\w+\b)");
            std::smatch match;
            std::string::const_iterator searchStart(line.cbegin() + std::min((size_t)pos.column, line.size()));
            
            if (std::regex_search(searchStart, line.cend(), match, wordRegex)) {
                info.signature = match.str() + "(...)";
                info.documentation = "Documentation for " + match.str();
                info.returnType = "auto";
            }
            break;
        }
    }
    
    return info;
}

std::vector<CodeAction> IDEEditor::GetCodeActions(const std::string& file, EditorRange range, const std::vector<Diagnostic>& diagnostics) {
    stats_.totalActions++;
    std::vector<CodeAction> actions;
    
    for (const auto& diag : diagnostics) {
        auto fixes = GetQuickFixes(diag);
        actions.insert(actions.end(), fixes.begin(), fixes.end());
    }
    
    // Add common refactorings
    CodeAction extractFunction;
    extractFunction.title = "Extract function";
    extractFunction.kind = "refactor.extract.function";
    extractFunction.isPreferred = false;
    actions.push_back(extractFunction);
    
    CodeAction renameSymbol;
    renameSymbol.title = "Rename symbol";
    renameSymbol.kind = "refactor.rename";
    renameSymbol.isPreferred = true;
    actions.push_back(renameSymbol);
    
    return actions;
}

std::vector<Diagnostic> IDEEditor::ComputeDiagnostics(const std::string& code, const std::string& file, const std::string& language) {
    std::vector<Diagnostic> diagnostics;
    std::istringstream stream(code);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Check for common errors
        if (line.find("TODO") != std::string::npos) {
            Diagnostic diag;
            diag.range.start = {lineNum, (uint32_t)line.find("TODO")};
            diag.range.end = {lineNum, (uint32_t)line.find("TODO") + 4};
            diag.severity = 3; // info
            diag.message = "Unresolved TODO";
            diag.code = "todo";
            diag.source = "sovereign";
            diagnostics.push_back(diag);
        }
        
        if (line.find("FIXME") != std::string::npos) {
            Diagnostic diag;
            diag.range.start = {lineNum, (uint32_t)line.find("FIXME")};
            diag.range.end = {lineNum, (uint32_t)line.find("FIXME") + 5};
            diag.severity = 2; // warning
            diag.message = "Unresolved FIXME";
            diag.code = "fixme";
            diag.source = "sovereign";
            diagnostics.push_back(diag);
        }
        
        // Check line length
        if (line.size() > 120) {
            Diagnostic diag;
            diag.range.start = {lineNum, 120};
            diag.range.end = {lineNum, (uint32_t)line.size()};
            diag.severity = 4; // hint
            diag.message = "Line exceeds 120 characters";
            diag.code = "line_length";
            diag.source = "sovereign";
            diagnostics.push_back(diag);
        }
    }
    
    return diagnostics;
}

std::vector<CodeAction> IDEEditor::GetQuickFixes(const Diagnostic& diagnostic) {
    std::vector<CodeAction> fixes;
    
    if (diagnostic.code == "todo") {
        CodeAction action;
        action.title = "Remove TODO comment";
        action.kind = "quickfix";
        action.isPreferred = false;
        fixes.push_back(action);
    }
    
    if (diagnostic.code == "line_length") {
        CodeAction action;
        action.title = "Reformat line";
        action.kind = "quickfix.format";
        action.isPreferred = true;
        fixes.push_back(action);
    }
    
    return fixes;
}

std::vector<EditorRange> IDEEditor::ComputeErrorRanges(const std::vector<Diagnostic>& diagnostics) {
    std::vector<EditorRange> ranges;
    for (const auto& diag : diagnostics) {
        if (diag.severity <= 2) { // error or warning
            ranges.push_back(diag.range);
        }
    }
    return ranges;
}

bool IDEEditor::IsBracket(char c) const {
    return c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}';
}

char IDEEditor::GetMatchingBracket(char c) const {
    switch (c) {
        case '(': return ')'; case ')': return '(';
        case '[': return ']'; case ']': return '[';
        case '{': return '}'; case '}': return '{';
        default: return c;
    }
}

} // namespace Sovereign
