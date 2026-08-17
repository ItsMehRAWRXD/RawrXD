#include "ContextEngine.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>

namespace RawrXD {

ContextEngine::ContextEngine() = default;

void ContextEngine::IndexProject(const std::string& rootPath) {
    context_.rootPath = rootPath;
    context_.files.clear();
    context_.symbols.clear();

    namespace fs = std::filesystem;
    for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
        if (entry.is_regular_file()) {
            std::string ext = entry.path().extension().string();
            if (ext == ".cpp" || ext == ".h" || ext == ".hpp" || 
                ext == ".c" || ext == ".asm" || ext == ".py") {
                context_.files.push_back(entry.path().string());
                
                std::ifstream file(entry.path());
                std::string content((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
                fileContents_[entry.path().string()] = content;
                ParseSymbols(entry.path().string(), content);
            }
        }
    }
}

void ContextEngine::UpdateFile(const std::string& filePath, const std::string& content) {
    fileContents_[filePath] = content;
    // Remove old symbols from this file
    context_.symbols.erase(
        std::remove_if(context_.symbols.begin(), context_.symbols.end(),
            [&](const Symbol& s) { return s.file == filePath; }),
        context_.symbols.end());
    ParseSymbols(filePath, content);
}

void ContextEngine::SetCursor(const std::string& file, size_t line) {
    context_.currentFile = file;
    context_.cursorLine = line;
    // Find enclosing function
    for (const auto& sym : context_.symbols) {
        if (sym.file == file && sym.kind == "function" && 
            sym.line <= line && 
            (context_.currentFunction.empty() || sym.line > context_.cursorLine)) {
            // Logic to find nearest function above cursor...
            context_.currentFunction = sym.name;
        }
    }
}

void ContextEngine::SetCompilerErrors(const std::string& errors) {
    context_.compilerErrors = errors;
}

std::string ContextEngine::BuildContextPrompt(size_t maxTokens) const {
    std::ostringstream oss;
    
    oss << "Project: " << context_.rootPath << "\n\n";
    
    // Current file
    oss << "Current file: " << context_.currentFile << "\n";
    if (!context_.currentFunction.empty())
        oss << "Current function: " << context_.currentFunction << "\n";
    if (context_.cursorLine > 0)
        oss << "Cursor at line: " << context_.cursorLine << "\n";
    
    // Related symbols
    auto related = FindRelatedSymbols(context_.currentFunction);
    if (!related.empty()) {
        oss << "\nRelated symbols:\n";
        for (const auto& sym : related) {
            oss << "  " << sym.signature << " [" << sym.file << ":" << sym.line << "]\n";
        }
    }
    
    // Compiler errors
    if (!context_.compilerErrors.empty()) {
        oss << "\nCompiler errors:\n" << context_.compilerErrors << "\n";
    }
    
    // File content (truncated)
    if (context_.currentFile.size() && fileContents_.count(context_.currentFile)) {
        oss << "\nFile content:\n```\n" << fileContents_.at(context_.currentFile) << "\n```\n";
    }
    
    return oss.str();
}

std::vector<Symbol> ContextEngine::FindRelatedSymbols(const std::string& name) const {
    std::vector<Symbol> related;
    for (const auto& sym : context_.symbols) {
        if (sym.name.find(name) != std::string::npos || 
            sym.signature.find(name) != std::string::npos) {
            related.push_back(sym);
        }
    }
    return related;
}

void ContextEngine::ParseSymbols(const std::string& filePath, const std::string& content) {
    // Simple regex-based symbol parser
    std::regex funcRegex(R"((\w[\w\s*&:<>,]*)\s+(\w+)\(([^)]*)\))");
    std::regex classRegex(R"(class\s+(\w+))");
    
    std::istringstream stream(content);
    std::string line;
    size_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        std::smatch match;
        if (std::regex_search(line, match, funcRegex) && 
            line.find(';') == std::string::npos) {
            Symbol sym;
            sym.name = match[2];
            sym.kind = "function";
            sym.file = filePath;
            sym.line = lineNum;
            sym.signature = match[0];
            context_.symbols.push_back(sym);
        }
        if (std::regex_search(line, match, classRegex)) {
            Symbol sym;
            sym.name = match[1];
            sym.kind = "class";
            sym.file = filePath;
            sym.line = lineNum;
            sym.signature = "class " + sym.name;
            context_.symbols.push_back(sym);
        }
    }
}

} // namespace RawrXD
