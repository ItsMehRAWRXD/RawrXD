// ============================================================================
// ContextEngine.cpp - Workspace Intelligence Implementation
// ============================================================================

#include "ContextEngine.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <thread>
#include <queue>
#include <filesystem>

namespace fs = std::filesystem;

namespace Sovereign {

// PIMPL implementation
class ContextEngine::Impl {
public:
    std::unordered_map<std::string, Symbol> symbols_;
    std::unordered_map<std::string, FileInfo> files_;
    std::unordered_map<std::string, std::vector<std::string>> dependencies_;
    std::unordered_map<std::string, std::vector<std::string>> dependents_;
    std::unordered_map<std::string, std::unique_ptr<ILanguageParser>> parsers_;
    std::unordered_map<SymbolType, std::vector<std::string>> symbolsByType_;
    std::mutex mutex_;
    bool watching_ = false;
    std::thread watcherThread_;
    std::queue<std::string> fileQueue_;
    std::condition_variable queueCV_;

    Impl() {
        RegisterParser(std::make_unique<CppParser>());
        RegisterParser(std::make_unique<PythonParser>());
    }

    ~Impl() {
        StopWatching();
    }

    void RegisterParser(std::unique_ptr<ILanguageParser> parser) {
        parsers_[parser->GetLanguage()] = std::move(parser);
    }

    void ScanWorkspace(const std::string& rootPath) {
        std::vector<std::string> extensions = {".cpp", ".hpp", ".h", ".c", ".py", ".js", ".ts"};
        
        for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                    ScanFile(entry.path().string());
                }
            }
        }
    }

    void ScanFile(const std::string& filePath) {
        std::ifstream file(filePath);
        if (!file) return;

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();

        // Detect language
        std::string ext = fs::path(filePath).extension().string();
        std::string lang = DetectLanguage(ext);

        // Update file info
        FileInfo info;
        info.path = filePath;
        info.size = content.size();
        info.lastModified = fs::last_write_time(filePath).time_since_epoch().count();
        info.language = lang;
        info.isIndexed = true;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            files_[filePath] = info;
        }

        // Parse with appropriate parser
        auto it = parsers_.find(lang);
        if (it != parsers_.end()) {
            auto symbols = it->second->Parse(filePath, content);
            IndexSymbols(symbols);

            auto deps = it->second->ParseDependencies(content);
            for (const auto& dep : deps) {
                AddDependency(dep);
            }
        }
    }

    void IndexSymbols(const std::vector<Symbol>& symbols) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& sym : symbols) {
            symbols_[sym.qualifiedName] = sym;
            symbolsByType_[sym.type].push_back(sym.qualifiedName);
        }
    }

    void AddDependency(const Dependency& dep) {
        std::lock_guard<std::mutex> lock(mutex_);
        dependencies_[dep.from].push_back(dep.to);
        dependents_[dep.to].push_back(dep.from);
    }

    std::vector<Symbol> FindSymbols(const std::string& query) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<Symbol> results;
        
        std::regex pattern(query, std::regex::icase);
        for (const auto& [name, sym] : symbols_) {
            if (std::regex_search(sym.name, pattern) || 
                std::regex_search(sym.documentation, pattern)) {
                results.push_back(sym);
            }
        }
        return results;
    }

    std::optional<Symbol> FindSymbolByName(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = symbols_.find(name);
        if (it != symbols_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    std::vector<std::string> GetDependencies(const std::string& file) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = dependencies_.find(file);
        if (it != dependencies_.end()) {
            return it->second;
        }
        return {};
    }

    ContextSelection SelectContext(const std::string& task, size_t tokenBudget) {
        ContextSelection selection;
        
        // Find relevant symbols
        auto symbols = FindSymbols(task);
        
        // Sort by relevance (simplified)
        std::sort(symbols.begin(), symbols.end(), 
            [](const Symbol& a, const Symbol& b) {
                return a.references.size() > b.references.size();
            });
        
        // Add symbols until budget exhausted
        size_t currentTokens = 0;
        for (const auto& sym : symbols) {
            size_t symTokens = EstimateTokens(sym);
            if (currentTokens + symTokens > tokenBudget) break;
            
            selection.symbols.push_back(sym);
            if (std::find(selection.files.begin(), selection.files.end(), sym.filePath) == selection.files.end()) {
                selection.files.push_back(sym.filePath);
            }
            currentTokens += symTokens;
        }
        
        selection.estimatedTokens = currentTokens;
        return selection;
    }

    size_t EstimateTokens(const Symbol& sym) {
        // Rough estimate: 4 chars per token
        return (sym.name.size() + sym.signature.size() + sym.documentation.size()) / 4;
    }

    std::string DetectLanguage(const std::string& ext) {
        if (ext == ".cpp" || ext == ".hpp" || ext == ".h" || ext == ".c") return "cpp";
        if (ext == ".py") return "python";
        if (ext == ".js" || ext == ".ts") return "javascript";
        return "unknown";
    }

    void StartWatching() {
        watching_ = true;
        watcherThread_ = std::thread(&Impl::WatcherLoop, this);
    }

    void StopWatching() {
        watching_ = false;
        queueCV_.notify_all();
        if (watcherThread_.joinable()) {
            watcherThread_.join();
        }
    }

    void WatcherLoop() {
        while (watching_) {
            std::unique_lock<std::mutex> lock(mutex_);
            queueCV_.wait(lock, [this] { return !fileQueue_.empty() || !watching_; });
            
            while (!fileQueue_.empty()) {
                std::string file = fileQueue_.front();
                fileQueue_.pop();
                lock.unlock();
                
                ScanFile(file);
                
                lock.lock();
            }
        }
    }
};

// ContextEngine public methods
ContextEngine::ContextEngine() : pImpl(std::make_unique<Impl>()) {}
ContextEngine::~ContextEngine() = default;

void ContextEngine::ScanWorkspace(const std::string& rootPath) {
    pImpl->ScanWorkspace(rootPath);
}

void ContextEngine::ScanFile(const std::string& filePath) {
    pImpl->ScanFile(filePath);
}

void ContextEngine::IndexSymbol(const Symbol& symbol) {
    pImpl->IndexSymbols({symbol});
}

void ContextEngine::IndexSymbols(const std::vector<Symbol>& symbols) {
    pImpl->IndexSymbols(symbols);
}

std::vector<Symbol> ContextEngine::FindSymbols(const std::string& query) {
    return pImpl->FindSymbols(query);
}

std::optional<Symbol> ContextEngine::FindSymbolByName(const std::string& name) {
    return pImpl->FindSymbolByName(name);
}

void ContextEngine::AddDependency(const Dependency& dep) {
    pImpl->AddDependency(dep);
}

std::vector<std::string> ContextEngine::GetDependencies(const std::string& file) {
    return pImpl->GetDependencies(file);
}

ContextSelection ContextEngine::SelectContext(const std::string& task, size_t tokenBudget) {
    return pImpl->SelectContext(task, tokenBudget);
}

size_t ContextEngine::GetIndexedFileCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->files_.size();
}

size_t ContextEngine::GetSymbolCount() const {
    std::lock_guard<std::mutex> lock(pImpl->mutex_);
    return pImpl->symbols_.size();
}

void ContextEngine::StartWatching() {
    pImpl->StartWatching();
}

void ContextEngine::StopWatching() {
    pImpl->StopWatching();
}

// CppParser implementation
std::vector<Symbol> CppParser::Parse(const std::string& filePath, const std::string& content) {
    std::vector<Symbol> symbols;
    
    // Simple regex-based parsing (production would use clang AST)
    std::regex functionRegex(R"((\w+)\s+(\w+)\s*\(([^)]*)\))");
    std::regex classRegex(R"(class\s+(\w+))");
    std::regex structRegex(R"(struct\s+(\w+))");
    
    std::smatch match;
    std::string::const_iterator searchStart(content.cbegin());
    
    // Parse functions
    while (std::regex_search(searchStart, content.cend(), match, functionRegex)) {
        Symbol sym;
        sym.name = match[2];
        sym.qualifiedName = match[2];
        sym.type = SymbolType::FUNCTION;
        sym.filePath = filePath;
        sym.signature = match[0];
        sym.returnType = match[1];
        
        // Extract parameters
        std::string params = match[3];
        std::stringstream ss(params);
        std::string param;
        while (std::getline(ss, param, ',')) {
            sym.parameters.push_back(param);
        }
        
        symbols.push_back(sym);
        searchStart = match.suffix().first;
    }
    
    return symbols;
}

std::vector<Dependency> CppParser::ParseDependencies(const std::string& content) {
    std::vector<Dependency> deps;
    std::regex includeRegex(R"(#include\s+["<]([^">]+)[">])");
    std::smatch match;
    
    std::string::const_iterator searchStart(content.cbegin());
    while (std::regex_search(searchStart, content.cend(), match, includeRegex)) {
        Dependency dep;
        dep.to = match[1];
        dep.type = "include";
        deps.push_back(dep);
        searchStart = match.suffix().first;
    }
    
    return deps;
}

// PythonParser implementation
std::vector<Symbol> PythonParser::Parse(const std::string& filePath, const std::string& content) {
    std::vector<Symbol> symbols;
    std::regex functionRegex(R"(def\s+(\w+)\s*\(([^)]*)\))");
    std::regex classRegex(R"(class\s+(\w+))");
    std::smatch match;
    
    std::string::const_iterator searchStart(content.cbegin());
    while (std::regex_search(searchStart, content.cend(), match, functionRegex)) {
        Symbol sym;
        sym.name = match[1];
        sym.qualifiedName = match[1];
        sym.type = SymbolType::FUNCTION;
        sym.filePath = filePath;
        sym.signature = match[0];
        
        std::string params = match[2];
        std::stringstream ss(params);
        std::string param;
        while (std::getline(ss, param, ',')) {
            sym.parameters.push_back(param);
        }
        
        symbols.push_back(sym);
        searchStart = match.suffix().first;
    }
    
    return symbols;
}

std::vector<Dependency> PythonParser::ParseDependencies(const std::string& content) {
    std::vector<Dependency> deps;
    std::regex importRegex(R"(import\s+(\w+)|from\s+(\w+)\s+import)");
    std::smatch match;
    
    std::string::const_iterator searchStart(content.cbegin());
    while (std::regex_search(searchStart, content.cend(), match, importRegex)) {
        Dependency dep;
        dep.to = match[1].matched ? match[1] : match[2];
        dep.type = "import";
        deps.push_back(dep);
        searchStart = match.suffix().first;
    }
    
    return deps;
}

} // namespace Sovereign
