#include "LanguageServerIntegration.h"
#include <algorithm>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace IDE {

LanguageServerIntegration::LanguageServerIntegration()
    : m_isInitialized(false), m_serverCapabilities(0) {
}

HoverInfo LanguageServerIntegration::provideHoverInfo(
    const std::string& filePath, int line, int column,
    const std::string& language, const std::string& codeContext) {
    
    HoverInfo info;
    info.isAvailable = true;
    info.line = line;
    info.column = column;
    
    // Extract token at cursor position
    std::string token = extractTokenAtPosition(codeContext, line, column);
    
    if (token.empty()) {
        info.isAvailable = false;
        return info;
    }
    
    // Generate hover content based on language and token
    if (language == "cpp" || language == "c++") {
        info.contents = generateCppHoverInfo(token, filePath);
    } else if (language == "python") {
        info.contents = generatePythonHoverInfo(token, filePath);
    } else if (language == "javascript" || language == "typescript") {
        info.contents = generateJsHoverInfo(token, filePath);
    } else {
        info.contents = "Token: " + token;
    }
    
    return info;
}

Location LanguageServerIntegration::goToDefinition(
    const std::string& filePath, int line, int column,
    const std::string& language) {
    
    Location location;
    location.filePath = filePath;
    location.line = line;
    location.column = column;
    location.found = false;
    
    // Real implementation: parse the source file to find symbol definitions
    // Look for function/class/struct definitions near the cursor position
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return location;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    // Extract token at cursor position
    std::string token = extractTokenAtPosition(content, line, column);
    if (token.empty()) {
        return location;
    }
    
    // Search for definition patterns: "type tokenName(" or "class tokenName" or "struct tokenName"
    std::vector<std::string> patterns = {
        R"((?:(?:void|int|float|double|char|bool|auto|std::string|class|struct|enum)\s+)" + token + R"(\s*\())",
        R"((?:class|struct|enum)\s+)" + token + R"(\b)",
        R"((?:void|int|float|double|char|bool|auto)\s+)" + token + R"(\s*[\(;])"
    };
    
    for (const auto& pattern : patterns) {
        std::regex re(pattern);
        std::smatch match;
        std::string::const_iterator searchStart(content.cbegin());
        
        while (std::regex_search(searchStart, content.cend(), match, re)) {
            // Calculate line number of the match
            size_t matchPos = match.position() + (searchStart - content.cbegin());
            size_t lineNum = 1;
            for (size_t i = 0; i < matchPos && i < content.size(); ++i) {
                if (content[i] == '\n') lineNum++;
            }
            
            location.found = true;
            location.line = static_cast<int>(lineNum);
            location.column = static_cast<int>(matchPos - content.rfind('\n', matchPos - 1) - 1);
            if (location.column < 0) location.column = 0;
            
            return location;
        }
    }
    
    return location;
}

std::vector<Location> LanguageServerIntegration::findReferences(
    const std::string& filePath, int line, int column,
    const std::string& language) {
    
    std::vector<Location> references;
    
    // Real implementation: search the source file for all references to the token at cursor
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return references;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    // Extract token at cursor position
    std::string token = extractTokenAtPosition(content, line, column);
    if (token.empty() || token.length() < 2) {
        return references;
    }
    
    // Search for all occurrences of the token (as whole word)
    std::regex re("\\b" + token + "\\b");
    std::sregex_iterator it(content.begin(), content.end(), re);
    std::sregex_iterator end;
    
    size_t cursorPos = 0;
    // Calculate cursor position in the content
    size_t pos = 0;
    for (int l = 1; l < line && pos < content.size(); ++l) {
        pos = content.find('\n', pos);
        if (pos == std::string::npos) break;
        pos++;
    }
    cursorPos = pos + column;
    
    while (it != end) {
        size_t matchPos = it->position();
        // Skip the cursor position itself
        if (matchPos != cursorPos) {
            Location loc;
            loc.filePath = filePath;
            
            // Calculate line number
            size_t lineNum = 1;
            for (size_t i = 0; i < matchPos && i < content.size(); ++i) {
                if (content[i] == '\n') lineNum++;
            }
            loc.line = static_cast<int>(lineNum);
            
            // Calculate column
            size_t lastNewline = content.rfind('\n', matchPos);
            loc.column = static_cast<int>(matchPos - (lastNewline == std::string::npos ? 0 : lastNewline + 1));
            
            references.push_back(loc);
        }
        ++it;
    }
    
    return references;
}

std::vector<Diagnostic> LanguageServerIntegration::getDiagnostics(
    const std::string& filePath, const std::string& code,
    const std::string& language) {
    
    std::vector<Diagnostic> diagnostics;
    
    // Syntax checking
    auto syntaxDiags = checkSyntax(code, language);
    diagnostics.insert(diagnostics.end(), syntaxDiags.begin(), syntaxDiags.end());
    
    // Semantic checking
    auto semanticDiags = checkSemantics(code, language);
    diagnostics.insert(diagnostics.end(), semanticDiags.begin(), semanticDiags.end());
    
    // Style checking
    auto styleDiags = checkStyle(code, language);
    diagnostics.insert(diagnostics.end(), styleDiags.begin(), styleDiags.end());
    
    return diagnostics;
}

PrepareRenameResult LanguageServerIntegration::prepareRename(
    const std::string& filePath, int line, int column,
    const std::string& language) {
    
    PrepareRenameResult result;
    result.canRename = true;
    result.placeholder = extractTokenAtPosition("", line, column);
    
    return result;
}

std::vector<TextEdit> LanguageServerIntegration::rename(
    const std::string& filePath, int line, int column,
    const std::string& newName, const std::string& language) {
    
    std::vector<TextEdit> edits;
    
    // Real implementation: find all references to the old token and create text edits
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return edits;
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    file.close();
    
    // Extract old token at cursor position
    std::string oldToken = extractTokenAtPosition(content, line, column);
    if (oldToken.empty() || oldToken == newName) {
        return edits;
    }
    
    // Search for all whole-word occurrences of oldToken
    std::regex re("\\b" + oldToken + "\\b");
    std::sregex_iterator it(content.begin(), content.end(), re);
    std::sregex_iterator end;
    
    while (it != end) {
        size_t matchPos = it->position();
        
        // Calculate line and column
        size_t lineNum = 1;
        size_t lastNewline = 0;
        for (size_t i = 0; i < matchPos && i < content.size(); ++i) {
            if (content[i] == '\n') {
                lineNum++;
                lastNewline = i;
            }
        }
        int col = static_cast<int>(matchPos - lastNewline - 1);
        
        TextEdit edit;
        edit.filePath = filePath;
        edit.startLine = static_cast<int>(lineNum);
        edit.startColumn = col;
        edit.endLine = static_cast<int>(lineNum);
        edit.endColumn = col + static_cast<int>(oldToken.length());
        edit.newText = newName;
        
        edits.push_back(edit);
        ++it;
    }
    
    return edits;
}

std::vector<std::string> LanguageServerIntegration::getCompletionItems(
    const std::string& filePath, int line, int column,
    const std::string& language, const std::string& codeContext) {
    
    std::vector<std::string> items;
    
    // Language-specific completions
    if (language == "cpp" || language == "c++") {
        auto cppItems = getCppCompletions(codeContext);
        items.insert(items.end(), cppItems.begin(), cppItems.end());
    } else if (language == "python") {
        auto pyItems = getPythonCompletions(codeContext);
        items.insert(items.end(), pyItems.begin(), pyItems.end());
    } else if (language == "javascript" || language == "typescript") {
        auto jsItems = getJsCompletions(codeContext);
        items.insert(items.end(), jsItems.begin(), jsItems.end());
    }
    
    return items;
}

std::vector<TextEdit> LanguageServerIntegration::formatDocument(
    const std::string& code, const std::string& language) {
    
    std::vector<TextEdit> edits;
    
    // Language-specific formatting
    std::string formatted = code;
    
    if (language == "cpp" || language == "c++") {
        formatted = formatCppCode(code);
    } else if (language == "python") {
        formatted = formatPythonCode(code);
    } else if (language == "javascript" || language == "typescript") {
        formatted = formatJsCode(code);
    }
    
    if (formatted != code) {
        TextEdit edit;
        edit.newText = formatted;
        edits.push_back(edit);
    }
    
    return edits;
}

std::vector<TextEdit> LanguageServerIntegration::formatRange(
    const std::string& code, int startLine, int startColumn,
    int endLine, int endColumn, const std::string& language) {
    
    std::vector<TextEdit> edits;
    
    // Extract range and format it
    std::string rangeCode = extractCodeRange(code, startLine, startColumn, endLine, endColumn);
    
    std::string formatted = rangeCode;
    if (language == "cpp" || language == "c++") {
        formatted = formatCppCode(rangeCode);
    } else if (language == "python") {
        formatted = formatPythonCode(rangeCode);
    } else if (language == "javascript" || language == "typescript") {
        formatted = formatJsCode(rangeCode);
    }
    
    if (formatted != rangeCode) {
        TextEdit edit;
        edit.startLine = startLine;
        edit.startColumn = startColumn;
        edit.endLine = endLine;
        edit.endColumn = endColumn;
        edit.newText = formatted;
        edits.push_back(edit);
    }
    
    return edits;
}

bool LanguageServerIntegration::initialize() {
    m_isInitialized = true;
    m_serverCapabilities |= static_cast<int>(ServerCapability::HoverProvider);
    m_serverCapabilities |= static_cast<int>(ServerCapability::DefinitionProvider);
    m_serverCapabilities |= static_cast<int>(ServerCapability::ReferencesProvider);
    m_serverCapabilities |= static_cast<int>(ServerCapability::RenameProvider);
    m_serverCapabilities |= static_cast<int>(ServerCapability::CompletionProvider);
    m_serverCapabilities |= static_cast<int>(ServerCapability::DiagnosticProvider);
    m_serverCapabilities |= static_cast<int>(ServerCapability::FormattingProvider);
    
    return true;
}

bool LanguageServerIntegration::shutdown() {
    m_isInitialized = false;
    return true;
}

bool LanguageServerIntegration::supportsLanguage(const std::string& language) {
    return language == "cpp" || language == "c++" || 
           language == "python" || language == "js" ||
           language == "javascript" || language == "typescript" ||
           language == "ts";
}

void LanguageServerIntegration::registerLanguageHandler(
    const std::string& language,
    const std::function<std::string(const std::string&)>& handler) {
    
    m_languageHandlers[language] = handler;
}

// Private helper methods

std::string LanguageServerIntegration::extractTokenAtPosition(
    const std::string& code, int line, int column) {
    
    if (code.empty()) return "";
    
    std::istringstream iss(code);
    std::string currentLine;
    int currentLineNum = 0;
    
    while (std::getline(iss, currentLine) && currentLineNum < line) {
        currentLineNum++;
    }
    
    if (currentLineNum != line || column >= static_cast<int>(currentLine.length())) {
        return "";
    }
    
    // Extract word at column
    int start = column;
    int end = column;
    
    // Move start backwards to word boundary
    while (start > 0 && (isalnum(currentLine[start - 1]) || currentLine[start - 1] == '_')) {
        start--;
    }
    
    // Move end forwards to word boundary
    while (end < static_cast<int>(currentLine.length()) && 
           (isalnum(currentLine[end]) || currentLine[end] == '_')) {
        end++;
    }
    
    return currentLine.substr(start, end - start);
}

std::string LanguageServerIntegration::generateCppHoverInfo(
    const std::string& token, const std::string& filePath) {
    
    std::string info = "**" + token + "**\n\n";
    
    // Check for common C++ keywords
    if (token == "int" || token == "void" || token == "float" || token == "double") {
        info += "C++ primitive type\n";
    } else if (token == "std") {
        info += "C++ Standard Library namespace\n";
    } else {
        info += "Symbol: " + token + "\n";
    }
    
    return info;
}

std::string LanguageServerIntegration::generatePythonHoverInfo(
    const std::string& token, const std::string& filePath) {
    
    std::string info = "**" + token + "**\n\n";
    
    if (token == "print" || token == "len" || token == "range") {
        info += "Python built-in function\n";
    } else {
        info += "Symbol: " + token + "\n";
    }
    
    return info;
}

std::string LanguageServerIntegration::generateJsHoverInfo(
    const std::string& token, const std::string& filePath) {
    
    std::string info = "**" + token + "**\n\n";
    
    if (token == "console" || token == "window" || token == "document") {
        info += "JavaScript global object\n";
    } else {
        info += "Symbol: " + token + "\n";
    }
    
    return info;
}

std::vector<Diagnostic> LanguageServerIntegration::checkSyntax(
    const std::string& code, const std::string& language) {
    
    std::vector<Diagnostic> diags;
    
    // Basic syntax checks
    int braces = 0, parens = 0, brackets = 0;
    int line = 1;
    
    for (size_t i = 0; i < code.length(); i++) {
        if (code[i] == '\n') line++;
        if (code[i] == '{') braces++;
        else if (code[i] == '}') {
            braces--;
            if (braces < 0) {
                Diagnostic diag;
                diag.line = line;
                diag.severity = "error";
                diag.message = "Unmatched closing brace";
                diags.push_back(diag);
            }
        } else if (code[i] == '(') parens++;
        else if (code[i] == ')') {
            parens--;
            if (parens < 0) {
                Diagnostic diag;
                diag.line = line;
                diag.severity = "error";
                diag.message = "Unmatched closing parenthesis";
                diags.push_back(diag);
            }
        } else if (code[i] == '[') brackets++;
        else if (code[i] == ']') {
            brackets--;
            if (brackets < 0) {
                Diagnostic diag;
                diag.line = line;
                diag.severity = "error";
                diag.message = "Unmatched closing bracket";
                diags.push_back(diag);
            }
        }
    }
    
    return diags;
}

std::vector<Diagnostic> LanguageServerIntegration::checkSemantics(
    const std::string& code, const std::string& language) {
    
    std::vector<Diagnostic> diags;
    // Placeholder for semantic analysis
    return diags;
}

std::vector<Diagnostic> LanguageServerIntegration::checkStyle(
    const std::string& code, const std::string& language) {
    
    std::vector<Diagnostic> diags;
    
    std::istringstream iss(code);
    std::string line;
    int lineNum = 0;
    
    while (std::getline(iss, line)) {
        lineNum++;
        
        if (line.length() > 120) {
            Diagnostic diag;
            diag.line = lineNum;
            diag.severity = "warning";
            diag.message = "Line too long";
            diags.push_back(diag);
        }
        
        // Check for trailing whitespace
        if (!line.empty() && (line.back() == ' ' || line.back() == '\t')) {
            Diagnostic diag;
            diag.line = lineNum;
            diag.severity = "info";
            diag.message = "Trailing whitespace";
            diags.push_back(diag);
        }
    }
    
    return diags;
}

std::vector<std::string> LanguageServerIntegration::getCppCompletions(
    const std::string& context) {
    
    return {"void", "int", "float", "double", "class", "struct", "void", "return", "for", "while", "if", "else"};
}

std::vector<std::string> LanguageServerIntegration::getPythonCompletions(
    const std::string& context) {
    
    return {"def", "class", "import", "from", "for", "while", "if", "else", "return", "print", "len", "range"};
}

std::vector<std::string> LanguageServerIntegration::getJsCompletions(
    const std::string& context) {
    
    return {"function", "const", "let", "var", "return", "if", "else", "for", "while", "console", "window", "document"};
}

std::string LanguageServerIntegration::formatCppCode(const std::string& code) {
    // Real C++ formatting: normalize indentation to 4 spaces, fix brace placement
    std::string result;
    int indentLevel = 0;
    bool inString = false;
    bool inChar = false;
    bool inLineComment = false;
    bool inBlockComment = false;
    
    for (size_t i = 0; i < code.size(); ++i) {
        char c = code[i];
        char next = (i + 1 < code.size()) ? code[i + 1] : '\0';
        
        // Handle comments
        if (!inString && !inChar && !inBlockComment) {
            if (!inLineComment && c == '/' && next == '/') {
                inLineComment = true;
            }
            if (!inLineComment && c == '/' && next == '*') {
                inBlockComment = true;
                i++;
                continue;
            }
        }
        
        if (inLineComment && c == '\n') {
            inLineComment = false;
        }
        
        if (inBlockComment && c == '*' && next == '/') {
            inBlockComment = false;
            i++;
            continue;
        }
        
        if (inLineComment || inBlockComment) {
            result += c;
            continue;
        }
        
        // Handle strings
        if (!inChar && c == '"') {
            inString = !inString;
            result += c;
            continue;
        }
        if (!inString && c == '\'') {
            inChar = !inChar;
            result += c;
            continue;
        }
        
        if (inString || inChar) {
            result += c;
            continue;
        }
        
        // Handle whitespace and indentation
        if (c == '{') {
            result += c;
            result += '\n';
            indentLevel++;
            for (int j = 0; j < indentLevel * 4; ++j) result += ' ';
        } else if (c == '}') {
            result += '\n';
            if (indentLevel > 0) indentLevel--;
            for (int j = 0; j < indentLevel * 4; ++j) result += ' ';
            result += c;
        } else if (c == ';' || c == ':' || c == ',') {
            result += c;
            // If next char is not whitespace, add space after
            if (next != '\0' && next != ' ' && next != '\n' && next != '\t' && next != ';' && next != '}' && next != ')') {
                result += ' ';
            }
        } else if (c == '\n') {
            result += c;
            // Write indentation for next line
            for (int j = 0; j < indentLevel * 4; ++j) result += ' ';
        } else if (c == ' ' || c == '\t') {
            // Normalize whitespace: skip multiple spaces
            bool needSpace = false;
            if (!result.empty() && result.back() != ' ' && result.back() != '\n' && result.back() != '{') {
                needSpace = true;
            }
            if (next != '\0' && next != ' ' && next != '\n' && next != '\t' && next != '}' && next != ';' && next != ',' && next != ':' && next != ')') {
                needSpace = true;
            }
            if (needSpace) result += ' ';
        } else {
            result += c;
        }
    }
    
    return result;
}

std::string LanguageServerIntegration::formatPythonCode(const std::string& code) {
    // Real Python formatting: normalize indentation to 4 spaces
    std::string result;
    int indentLevel = 0;
    bool inString = false;
    bool inTripleString = false;
    
    for (size_t i = 0; i < code.size(); ++i) {
        char c = code[i];
        
        // Handle triple-quoted strings
        if (i + 2 < code.size() && code[i] == '"' && code[i+1] == '"' && code[i+2] == '"') {
            inTripleString = !inTripleString;
            result += "'''";
            i += 2;
            continue;
        }
        
        if (!inTripleString && c == '"') {
            inString = !inString;
            result += c;
            continue;
        }
        
        if (inString || inTripleString) {
            result += c;
            continue;
        }
        
        if (c == ':') {
            result += c;
            // Check if next non-space is newline (block starter)
            size_t j = i + 1;
            while (j < code.size() && (code[j] == ' ' || code[j] == '\t')) j++;
            if (j < code.size() && code[j] == '\n') {
                indentLevel++;
            }
        } else if (c == '\n') {
            result += c;
            for (int j = 0; j < indentLevel * 4; ++j) result += ' ';
        } else if (c == ' ' || c == '\t') {
            bool needSpace = false;
            if (!result.empty() && result.back() != ' ' && result.back() != '\n') {
                needSpace = true;
            }
            if (needSpace) result += ' ';
        } else {
            result += c;
        }
    }
    
    return result;
}

std::string LanguageServerIntegration::formatJsCode(const std::string& code) {
    // Real JavaScript formatting: normalize indentation to 2 spaces, fix braces
    std::string result;
    int indentLevel = 0;
    bool inString = false;
    bool inTemplateLiteral = false;
    bool inLineComment = false;
    bool inBlockComment = false;
    
    for (size_t i = 0; i < code.size(); ++i) {
        char c = code[i];
        char next = (i + 1 < code.size()) ? code[i + 1] : '\0';
        
        if (!inString && !inTemplateLiteral && !inBlockComment) {
            if (!inLineComment && c == '/' && next == '/') {
                inLineComment = true;
            }
            if (!inLineComment && c == '/' && next == '*') {
                inBlockComment = true;
                i++;
                continue;
            }
        }
        
        if (inLineComment && c == '\n') inLineComment = false;
        if (inBlockComment && c == '*' && next == '/') { inBlockComment = false; i++; continue; }
        
        if (inLineComment || inBlockComment) { result += c; continue; }
        
        if (!inTemplateLiteral && c == '"') { inString = !inString; result += c; continue; }
        if (!inString && c == '`') { inTemplateLiteral = !inTemplateLiteral; result += c; continue; }
        
        if (inString || inTemplateLiteral) { result += c; continue; }
        
        if (c == '{') {
            result += c;
            result += '\n';
            indentLevel++;
            for (int j = 0; j < indentLevel * 2; ++j) result += ' ';
        } else if (c == '}') {
            result += '\n';
            if (indentLevel > 0) indentLevel--;
            for (int j = 0; j < indentLevel * 2; ++j) result += ' ';
            result += c;
        } else if (c == ';' || c == ',') {
            result += c;
        } else if (c == '\n') {
            result += c;
            for (int j = 0; j < indentLevel * 2; ++j) result += ' ';
        } else if (c == ' ' || c == '\t') {
            bool needSpace = false;
            if (!result.empty() && result.back() != ' ' && result.back() != '\n' && result.back() != '{') {
                needSpace = true;
            }
            if (needSpace) result += ' ';
        } else {
            result += c;
        }
    }
    
    return result;
}

std::string LanguageServerIntegration::extractCodeRange(
    const std::string& code, int startLine, int startColumn,
    int endLine, int endColumn) {
    
    std::istringstream iss(code);
    std::string line;
    std::string result;
    int currentLine = 0;
    
    while (std::getline(iss, line)) {
        if (currentLine >= startLine && currentLine <= endLine) {
            if (currentLine == startLine && currentLine == endLine) {
                result = line.substr(startColumn, endColumn - startColumn);
            } else if (currentLine == startLine) {
                result = line.substr(startColumn) + "\n";
            } else if (currentLine == endLine) {
                result += line.substr(0, endColumn);
            } else {
                result += line + "\n";
            }
        }
        currentLine++;
    }
    
    return result;
}

} // namespace IDE
} // namespace RawrXD
