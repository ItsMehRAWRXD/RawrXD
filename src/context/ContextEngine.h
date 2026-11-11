#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <mutex>
#include <filesystem>
#include <regex>
#include <fstream>
#include <sstream>

namespace RawrXD {

struct CodeSymbol {
    std::string name;
    std::string qualifiedName;
    std::string type;       // "function", "class", "variable", "method"
    std::string filePath;
    uint32_t lineStart = 0;
    uint32_t lineEnd = 0;
    std::string signature;
    std::string parentScope;
    std::vector<std::string> references;
    float relevanceScore = 0.0f;
};

struct ContextResult {
    std::string contextText;
    std::vector<CodeSymbol> symbols;
    uint32_t tokenCount = 0;
    bool truncated = false;
};

class ContextEngine {
public:
    ContextEngine() = default;
    ~ContextEngine() = default;

    bool Initialize(const std::string& repoPath) {
        repoPath_ = repoPath;
        IndexDirectory(repoPath);
        return true;
    }

    void IndexDirectory(const std::string& dirPath) {
        if (!std::filesystem::exists(dirPath)) return;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".h" || 
                    ext == ".hpp" || ext == ".c" || ext == ".py" || ext == ".js" || 
                    ext == ".ts" || ext == ".rs" || ext == ".go" || ext == ".java" ||
                    ext == ".cs" || ext == ".asm") {
                    IndexFile(entry.path().string());
                }
            }
        }
    }

    void IndexFile(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file) return;
        std::stringstream buf;
        buf << file.rdbuf();
        std::string content = buf.str();

        std::lock_guard<std::mutex> lock(mutex_);
        RemoveFileLocked(filePath);

        std::string ext = std::filesystem::path(filePath).extension().string();
        std::istringstream stream(content);
        std::string line;
        uint32_t lineNum = 0;

        if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".h" || ext == ".hpp" || ext == ".c") {
            std::regex classRegex("(class|struct)\\s+(\\w+)");
            std::regex funcRegex("(\\w+[\\s\\*]+)+(\\w+)\\s*\\(([^)]*)\\)");
            while (std::getline(stream, line)) {
                lineNum++;
                std::smatch m;
                if (std::regex_search(line, m, classRegex)) {
                    CodeSymbol sym;
                    sym.name = m[2]; sym.qualifiedName = m[2];
                    sym.type = "class"; sym.filePath = filePath; sym.lineStart = lineNum;
                    symbols_.push_back(sym);
                }
                if (std::regex_search(line, m, funcRegex)) {
                    CodeSymbol sym;
                    sym.name = m[2]; sym.qualifiedName = m[2];
                    sym.type = "function"; sym.filePath = filePath; sym.lineStart = lineNum;
                    sym.signature = m[0];
                    symbols_.push_back(sym);
                }
            }
        } else if (ext == ".py") {
            std::regex funcRegex("def\\s+(\\w+)\\s*\\(");
            std::regex classRegex("class\\s+(\\w+)");
            while (std::getline(stream, line)) {
                lineNum++;
                std::smatch m;
                if (std::regex_search(line, m, funcRegex)) {
                    CodeSymbol sym;
                    sym.name = m[1]; sym.qualifiedName = m[1];
                    sym.type = "function"; sym.filePath = filePath; sym.lineStart = lineNum;
                    symbols_.push_back(sym);
                }
                if (std::regex_search(line, m, classRegex)) {
                    CodeSymbol sym;
                    sym.name = m[1]; sym.qualifiedName = m[1];
                    sym.type = "class"; sym.filePath = filePath; sym.lineStart = lineNum;
                    symbols_.push_back(sym);
                }
            }
        } else if (ext == ".rs") {
            std::regex funcRegex("fn\\s+(\\w+)");
            std::regex structRegex("struct\\s+(\\w+)");
            while (std::getline(stream, line)) {
                lineNum++;
                std::smatch m;
                if (std::regex_search(line, m, funcRegex)) {
                    CodeSymbol sym;
                    sym.name = m[1]; sym.qualifiedName = m[1];
                    sym.type = "function"; sym.filePath = filePath; sym.lineStart = lineNum;
                    symbols_.push_back(sym);
                }
                if (std::regex_search(line, m, structRegex)) {
                    CodeSymbol sym;
                    sym.name = m[1]; sym.qualifiedName = m[1];
                    sym.type = "struct"; sym.filePath = filePath; sym.lineStart = lineNum;
                    symbols_.push_back(sym);
                }
            }
        } else {
            std::regex wordRegex("\\b[A-Z][a-zA-Z0-9]*\\b");
            while (std::getline(stream, line)) {
                lineNum++;
                std::sregex_iterator iter(line.begin(), line.end(), wordRegex);
                std::sregex_iterator end;
                for (; iter != end; ++iter) {
                    CodeSymbol sym;
                    sym.name = iter->str(); sym.qualifiedName = iter->str();
                    sym.type = "symbol"; sym.filePath = filePath; sym.lineStart = lineNum;
                    symbols_.push_back(sym);
                }
            }
        }
    }

    void RemoveFile(const std::string& filePath) {
        std::lock_guard<std::mutex> lock(mutex_);
        RemoveFileLocked(filePath);
    }

    ContextResult GetContextForCompletion(const std::string& prefix, const std::string& filePath, uint32_t line, size_t maxTokens) {
        std::lock_guard<std::mutex> lock(mutex_);
        ContextResult result;
        std::vector<CodeSymbol> relevant;
        for (const auto& sym : symbols_) {
            if (sym.filePath == filePath) relevant.push_back(sym);
        }
        std::stringstream ctx;
        ctx << "// Relevant symbols from codebase:\n";
        size_t tokens = 0;
        for (const auto& sym : relevant) {
            std::string entry = "// " + sym.type + " " + sym.name;
            if (!sym.signature.empty()) entry += " " + sym.signature;
            entry += "\n";
            size_t t = entry.size() / 4;
            if (tokens + t > maxTokens) { result.truncated = true; break; }
            ctx << entry; tokens += t;
        }
        result.contextText = ctx.str();
        result.symbols = relevant;
        result.tokenCount = tokens;
        return result;
    }

    ContextResult GetContextForExplanation(const std::string& symbolName, size_t maxTokens) {
        std::lock_guard<std::mutex> lock(mutex_);
        ContextResult result;
        for (const auto& sym : symbols_) {
            if (sym.name == symbolName || sym.qualifiedName == symbolName) {
                std::stringstream ctx;
                ctx << "Symbol: " << sym.qualifiedName << "\n";
                ctx << "Type: " << sym.type << "\n";
                ctx << "File: " << sym.filePath << ":" << sym.lineStart << "\n";
                if (!sym.signature.empty()) ctx << "Signature: " << sym.signature << "\n";
                result.contextText = ctx.str();
                result.symbols.push_back(sym);
                result.tokenCount = ctx.str().size() / 4;
                break;
            }
        }
        return result;
    }

    std::vector<CodeSymbol> SearchSymbols(const std::string& query) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<CodeSymbol> results;
        for (const auto& sym : symbols_) {
            if (sym.name.find(query) != std::string::npos || 
                sym.qualifiedName.find(query) != std::string::npos) {
                results.push_back(sym);
            }
        }
        return results;
    }

    size_t GetSymbolCount() const { std::lock_guard<std::mutex> lock(mutex_); return symbols_.size(); }
    bool IsReady() const { return !repoPath_.empty(); }
    std::string GetStatus() const {
        return "ContextEngine: " + std::string(IsReady() ? "READY" : "NOT READY") + 
               " | Symbols: " + std::to_string(GetSymbolCount());
    }

private:
    void RemoveFileLocked(const std::string& filePath) {
        symbols_.erase(std::remove_if(symbols_.begin(), symbols_.end(),
            [&](const CodeSymbol& s) { return s.filePath == filePath; }), symbols_.end());
    }

    mutable std::mutex mutex_;
    std::string repoPath_;
    std::vector<CodeSymbol> symbols_;
};

} // namespace RawrXD
