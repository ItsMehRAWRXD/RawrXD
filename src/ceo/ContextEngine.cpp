// ============================================================================
// ContextEngine.cpp — Intelligent Context Assembly Implementation
// Delegates to Repository Intelligence primitives for deep code understanding
// ============================================================================
#include "ContextEngine.hpp"
#include "../repo/FileIndex.hpp"
#include "../repo/SymbolTable.hpp"
#include "../repo/ASTCache.hpp"
#include "../repo/SearchIndex.hpp"
#include "../repo/CallGraph.hpp"
#include "../repo/IncludeGraph.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>

namespace fs = std::filesystem;

namespace RawrXD {
namespace CEO {

// ============================================================================
// Constructor / Destructor
// ============================================================================
ContextEngine::ContextEngine() = default;
ContextEngine::~ContextEngine() = default;

// ============================================================================
// Initialization
// ============================================================================
bool ContextEngine::Initialize(const std::string& projectRoot) {
    m_projectRoot = projectRoot;
    m_initialized = true;
    return true;
}

void ContextEngine::Shutdown() {
    m_initialized = false;
}

// ============================================================================
// Repository Indexing
// ============================================================================
bool ContextEngine::IndexRepository() {
    if (!m_initialized) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    m_index.rootPath = m_projectRoot;
    m_index.files.clear();
    m_index.symbols.clear();
    m_index.dependencies.clear();
    
    // Collect all source files
    std::vector<fs::path> sourceFiles;
    std::vector<std::string> extensions = {
        ".cpp", ".c", ".h", ".hpp", ".cc", 
        ".py", ".js", ".ts", ".java", 
        ".rs", ".go", ".cs", ".swift",
        ".asm", ".S", ".s"
    };
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(m_projectRoot)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                    sourceFiles.push_back(entry.path());
                }
            }
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[ContextEngine] Index error: %s\n", e.what());
    }
    
    // Index each file
    int current = 0;
    int total = sourceFiles.size();
    
    for (const auto& filePath : sourceFiles) {
        current++;
        
        if (m_indexCb) {
            m_indexCb(filePath.string(), current, total);
        }
        
        FileContext context;
        if (ParseFile(filePath.string(), context)) {
            m_index.files.push_back(context);
            
            // Extract symbols
            std::vector<SymbolInfo> symbols;
            if (ExtractSymbols(context, symbols)) {
                for (const auto& sym : symbols) {
                    m_index.symbols[sym.name] = sym;
                }
            }
            
            // Store dependencies
            m_index.dependencies[context.path] = context.dependencies;
        }
    }
    
    m_index.indexedAt = std::chrono::system_clock::now();
    m_index.isComplete = true;
    
    printf("[ContextEngine] Indexed %zu files, %zu symbols\n", 
           m_index.files.size(), m_index.symbols.size());
    
    return true;
}

// ============================================================================
// Repository Intelligence Integration
// ============================================================================
void ContextEngine::SetRepoPrimitives(IDE::FileIndex* fileIndex,
                                       IDE::SymbolTable* symbolTable,
                                       IDE::ASTCache* astCache,
                                       IDE::SearchIndex* searchIndex,
                                       IDE::CallGraph* callGraph,
                                       IDE::IncludeGraph* includeGraph) {
    m_fileIndex = fileIndex;
    m_symbolTable = symbolTable;
    m_astCache = astCache;
    m_searchIndex = searchIndex;
    m_callGraph = callGraph;
    m_includeGraph = includeGraph;
    
    if (m_fileIndex) {
        printf("[ContextEngine] Wired to FileIndex for live file watching\n");
    }
    if (m_symbolTable) {
        printf("[ContextEngine] Wired to SymbolTable for symbol resolution\n");
    }
    if (m_searchIndex) {
        printf("[ContextEngine] Wired to SearchIndex for full-text search\n");
    }
}

bool ContextEngine::IndexFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    FileContext context;
    if (!ParseFile(filePath, context)) {
        return false;
    }
    
    // Remove existing entry if present
    m_index.files.erase(
        std::remove_if(m_index.files.begin(), m_index.files.end(),
            [&filePath](const FileContext& fc) { return fc.path == filePath; }),
        m_index.files.end()
    );
    
    m_index.files.push_back(context);
    
    // Update symbols
    std::vector<SymbolInfo> symbols;
    if (ExtractSymbols(context, symbols)) {
        for (const auto& sym : symbols) {
            m_index.symbols[sym.name] = sym;
        }
    }
    
    m_index.dependencies[context.path] = context.dependencies;
    
    return true;
}

bool ContextEngine::UpdateFile(const std::string& filePath) {
    return IndexFile(filePath);
}

bool ContextEngine::RemoveFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    m_index.files.erase(
        std::remove_if(m_index.files.begin(), m_index.files.end(),
            [&filePath](const FileContext& fc) { return fc.path == filePath; }),
        m_index.files.end()
    );
    
    // Remove symbols from this file
    auto it = m_index.symbols.begin();
    while (it != m_index.symbols.end()) {
        if (it->second.filePath == filePath) {
            it = m_index.symbols.erase(it);
        } else {
            ++it;
        }
    }
    
    m_index.dependencies.erase(filePath);
    
    return true;
}

// ============================================================================
// Context Assembly
// ============================================================================
json ContextEngine::GetRelevantContext(const std::string& query) {
    ContextRequest request;
    request.query = query;
    request.maxTokens = 8192;
    request.includeHistory = true;
    request.includeDependencies = true;
    request.includeTests = true;
    
    return AssembleContext(request);
}

json ContextEngine::GetContextForCompletion(const std::string& filePath, 
                                            int line, int column) {
    ContextRequest request;
    request.activeFile = filePath;
    request.cursorLine = line;
    request.cursorColumn = column;
    request.maxTokens = 4096; // Smaller for completion
    request.includeHistory = false;
    request.includeDependencies = true;
    request.includeTests = false;
    
    return AssembleContext(request);
}

json ContextEngine::GetContextForError(const std::string& errorMessage) {
    ContextRequest request;
    request.query = errorMessage;
    request.recentErrors.push_back(errorMessage);
    request.maxTokens = 8192;
    request.includeHistory = true;
    request.includeDependencies = true;
    request.includeTests = true;
    
    return AssembleContext(request);
}

json ContextEngine::GetContextForTask(const std::string& taskDescription) {
    ContextRequest request;
    request.query = taskDescription;
    request.maxTokens = 16384; // Larger for task planning
    request.includeHistory = true;
    request.includeDependencies = true;
    request.includeTests = true;
    
    return AssembleContext(request);
}

json ContextEngine::AssembleContext(const ContextRequest& request) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    json context;
    context["query"] = request.query;
    context["files"] = json::array();
    context["symbols"] = json::array();
    context["dependencies"] = json::array();
    context["errors"] = request.recentErrors;
    
    int currentTokens = EstimateTokens(request.query);
    int maxTokens = request.maxTokens;
    
    // Priority 1: Active file
    if (!request.activeFile.empty()) {
        auto it = std::find_if(m_index.files.begin(), m_index.files.end(),
            [&request](const FileContext& fc) { return fc.path == request.activeFile; });
        
        if (it != m_index.files.end()) {
            json fileContext;
            fileContext["path"] = it->path;
            fileContext["content"] = TruncateToTokens(it->content, 
                                                       maxTokens / 4); // 25% for active file
            fileContext["language"] = it->language;
            context["files"].push_back(fileContext);
            
            currentTokens += EstimateTokens(it->content) / 4;
            
            // Add related dependencies
            if (request.includeDependencies) {
                for (const auto& dep : it->dependencies) {
                    if (currentTokens >= maxTokens * 0.8) break;
                    
                    auto depIt = std::find_if(m_index.files.begin(), m_index.files.end(),
                        [&dep](const FileContext& fc) { return fc.path == dep; });
                    
                    if (depIt != m_index.files.end()) {
                        json depContext;
                        depContext["path"] = depIt->path;
                        depContext["content"] = TruncateToTokens(depIt->content, 500);
                        depContext["language"] = depIt->language;
                        context["dependencies"].push_back(depContext);
                        currentTokens += 500;
                    }
                }
            }
        }
    }
    
    // Priority 2: Query-relevant files
    if (!request.query.empty()) {
        // Extract file paths for relevance ranking
        std::vector<std::string> filePaths;
        for (const auto& fc : m_index.files) {
            filePaths.push_back(fc.path);
        }
        auto relevantFiles = RankByRelevance(request.query, filePaths);
        
        for (const auto& filePath : relevantFiles) {
            if (currentTokens >= maxTokens * 0.9) break;
            if (filePath == request.activeFile) continue; // Already added
            
            auto it = std::find_if(m_index.files.begin(), m_index.files.end(),
                [&filePath](const FileContext& fc) { return fc.path == filePath; });
            
            if (it != m_index.files.end()) {
                json fileContext;
                fileContext["path"] = it->path;
                fileContext["content"] = TruncateToTokens(it->content, 1000);
                fileContext["language"] = it->language;
                context["files"].push_back(fileContext);
                currentTokens += 1000;
            }
        }
    }
    
    // Priority 3: Relevant symbols
    if (!request.query.empty()) {
        auto symbols = SearchSymbols(request.query);
        for (const auto& sym : symbols) {
            if (currentTokens >= maxTokens * 0.95) break;
            
            json symContext;
            symContext["name"] = sym.name;
            symContext["type"] = sym.type;
            symContext["file"] = sym.filePath;
            symContext["line"] = sym.lineNumber;
            symContext["signature"] = sym.signature;
            context["symbols"].push_back(symContext);
            currentTokens += 100;
        }
    }
    
    context["token_estimate"] = currentTokens;
    context["file_count"] = context["files"].size();
    context["symbol_count"] = context["symbols"].size();
    
    return context;
}

// ============================================================================
// Symbol Resolution
// ============================================================================
std::vector<SymbolInfo> ContextEngine::FindSymbol(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    std::vector<SymbolInfo> results;
    auto it = m_index.symbols.find(name);
    if (it != m_index.symbols.end()) {
        results.push_back(it->second);
    }
    return results;
}

std::vector<SymbolInfo> ContextEngine::FindReferences(const std::string& symbolName) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    std::vector<SymbolInfo> results;
    auto it = m_index.symbols.find(symbolName);
    if (it != m_index.symbols.end()) {
        for (const auto& ref : it->second.references) {
            SymbolInfo refInfo;
            refInfo.name = symbolName;
            refInfo.filePath = ref;
            results.push_back(refInfo);
        }
    }
    return results;
}

std::vector<std::string> ContextEngine::GetDependencies(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    auto it = m_index.dependencies.find(filePath);
    if (it != m_index.dependencies.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::string> ContextEngine::GetDependents(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    std::vector<std::string> dependents;
    for (const auto& [file, deps] : m_index.dependencies) {
        if (std::find(deps.begin(), deps.end(), filePath) != deps.end()) {
            dependents.push_back(file);
        }
    }
    return dependents;
}

// ============================================================================
// Search
// ============================================================================
std::vector<FileContext> ContextEngine::SearchFiles(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    std::vector<FileContext> results;
    std::regex regex(pattern, std::regex::icase);
    
    for (const auto& file : m_index.files) {
        if (std::regex_search(file.path, regex) ||
            std::regex_search(file.content, regex)) {
            results.push_back(file);
        }
    }
    
    return results;
}

std::vector<SymbolInfo> ContextEngine::SearchSymbols(const std::string& pattern) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    std::vector<SymbolInfo> results;
    std::regex regex(pattern, std::regex::icase);
    
    for (const auto& [name, sym] : m_index.symbols) {
        if (std::regex_search(name, regex)) {
            results.push_back(sym);
        }
    }
    
    return results;
}

// ============================================================================
// Statistics
// ============================================================================
json ContextEngine::GetRepositoryStats() const {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    json stats;
    stats["file_count"] = m_index.files.size();
    stats["symbol_count"] = m_index.symbols.size();
    stats["is_indexed"] = m_index.isComplete;
    
    if (m_index.isComplete) {
        auto now = std::chrono::system_clock::now();
        auto age = std::chrono::duration_cast<std::chrono::minutes>(
            now - m_index.indexedAt).count();
        stats["index_age_minutes"] = age;
    }
    
    // Language breakdown
    std::map<std::string, int> languageCounts;
    for (const auto& file : m_index.files) {
        languageCounts[file.language]++;
    }
    stats["languages"] = languageCounts;
    
    return stats;
}

int ContextEngine::GetFileCount() const {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    return m_index.files.size();
}

int ContextEngine::GetSymbolCount() const {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    return m_index.symbols.size();
}

// ============================================================================
// Cache Management
// ============================================================================
void ContextEngine::ClearCache() {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    m_fileCache.clear();
    m_cacheTimestamps.clear();
}

bool ContextEngine::SaveIndex(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_indexMutex);
    
    try {
        json indexData;
        indexData["root"] = m_index.rootPath;
        indexData["indexed_at"] = std::chrono::system_clock::to_time_t(m_index.indexedAt);
        indexData["is_complete"] = m_index.isComplete;
        indexData["file_count"] = m_index.files.size();
        indexData["symbol_count"] = m_index.symbols.size();
        
        // Save file index
        json filesJson = json::array();
        for (const auto& file : m_index.files) {
            json fj;
            fj["path"] = file.path;
            fj["language"] = file.language;
            fj["line_count"] = file.lineCount;
            fj["is_open"] = file.isOpen;
            fj["has_errors"] = file.hasErrors;
            fj["imports"] = file.imports;
            fj["dependencies"] = file.dependencies;
            
            // Save symbols for this file
            json symsJson = json::array();
            for (const auto& symName : file.symbols) {
                auto it = m_index.symbols.find(symName);
                if (it != m_index.symbols.end()) {
                    json sj;
                    sj["name"] = it->second.name;
                    sj["type"] = it->second.type;
                    sj["file_path"] = it->second.filePath;
                    sj["line_number"] = it->second.lineNumber;
                    sj["signature"] = it->second.signature;
                    symsJson.push_back(sj);
                }
            }
            fj["symbols"] = symsJson;
            filesJson.push_back(fj);
        }
        indexData["files"] = filesJson;
        
        // Save dependency graph
        json depsJson = json::object();
        for (const auto& [file, deps] : m_index.dependencies) {
            depsJson[file] = deps;
        }
        indexData["dependencies"] = depsJson;
        
        std::ofstream file(path);
        if (!file) return false;
        file << indexData.dump(2);
        return true;
    } catch (const std::exception& e) {
        fprintf(stderr, "[ContextEngine] SaveIndex error: %s\n", e.what());
        return false;
    }
}

bool ContextEngine::LoadIndex(const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    
    try {
        json indexData;
        file >> indexData;
        
        std::lock_guard<std::mutex> lock(m_indexMutex);
        
        m_index.rootPath = indexData.value("root", "");
        m_index.isComplete = indexData.value("is_complete", false);
        
        if (indexData.contains("indexed_at")) {
            m_index.indexedAt = std::chrono::system_clock::from_time_t(
                indexData["indexed_at"].get<std::time_t>());
        }
        
        // Load files
        if (indexData.contains("files")) {
            for (const auto& fj : indexData["files"]) {
                FileContext fc;
                fc.path = fj.value("path", "");
                fc.language = fj.value("language", "");
                fc.lineCount = fj.value("line_count", 0);
                fc.isOpen = fj.value("is_open", false);
                fc.hasErrors = fj.value("has_errors", false);
                fc.imports = fj.value("imports", std::vector<std::string>());
                fc.dependencies = fj.value("dependencies", std::vector<std::string>());
                
                // Load symbols
                if (fj.contains("symbols")) {
                    for (const auto& sj : fj["symbols"]) {
                        fc.symbols.push_back(sj.value("name", ""));
                        
                        SymbolInfo si;
                        si.name = sj.value("name", "");
                        si.type = sj.value("type", "");
                        si.filePath = sj.value("file_path", "");
                        si.lineNumber = sj.value("line_number", 0);
                        si.signature = sj.value("signature", "");
                        m_index.symbols[si.name] = si;
                    }
                }
                
                m_index.files.push_back(fc);
            }
        }
        
        // Load dependencies
        if (indexData.contains("dependencies")) {
            for (const auto& [file, deps] : indexData["dependencies"].items()) {
                m_index.dependencies[file] = deps.get<std::vector<std::string>>();
            }
        }
        
        printf("[ContextEngine] Loaded index: %zu files, %zu symbols\n",
               m_index.files.size(), m_index.symbols.size());
        
        return true;
    } catch (const std::exception& e) {
        fprintf(stderr, "[ContextEngine] LoadIndex error: %s\n", e.what());
        return false;
    }
}

// ============================================================================
// Internal Methods
// ============================================================================
bool ContextEngine::ParseFile(const std::string& path, FileContext& context) {
    context.path = path;
    context.language = DetectLanguage(path);
    
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return false;
    }
    
    context.content.assign((std::istreambuf_iterator<char>(file)),
                           std::istreambuf_iterator<char>());
    
    // Count lines
    context.lineCount = std::count(context.content.begin(), 
                                   context.content.end(), '\n');
    
    // Extract imports
    context.imports = ExtractImports(context.content, context.language);
    
    // Get last modified time
    try {
        auto lastWrite = fs::last_write_time(path);
        context.lastModified = std::chrono::system_clock::now(); // Approximation
    } catch (...) {
        context.lastModified = std::chrono::system_clock::now();
    }
    
    return true;
}

bool ContextEngine::ExtractSymbols(const FileContext& file, 
                                  std::vector<SymbolInfo>& symbols) {
    // Simple regex-based symbol extraction
    // In production, this would use a proper parser
    
    std::vector<std::pair<std::regex, std::string>> patterns;
    
    if (file.language == "cpp" || file.language == "c") {
        patterns = {
            {std::regex(R"((\w+)\s*\([^)]*\)\s*\{)"), "function"},
            {std::regex(R"(class\s+(\w+))"), "class"},
            {std::regex(R"(struct\s+(\w+))"), "struct"},
            {std::regex(R"(namespace\s+(\w+))"), "namespace"},
        };
    } else if (file.language == "python") {
        patterns = {
            {std::regex(R"(def\s+(\w+)\s*\()"), "function"},
            {std::regex(R"(class\s+(\w+))"), "class"},
        };
    }
    
    std::istringstream stream(file.content);
    std::string line;
    int lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        for (const auto& [pattern, type] : patterns) {
            std::smatch match;
            if (std::regex_search(line, match, pattern)) {
                SymbolInfo sym;
                sym.name = match[1];
                sym.type = type;
                sym.filePath = file.path;
                sym.lineNumber = lineNum;
                sym.signature = line;
                symbols.push_back(sym);
            }
        }
    }
    
    return true;
}

std::vector<std::string> ContextEngine::FindRelatedFiles(const std::string& filePath) {
    std::vector<std::string> related;
    
    // Get dependencies
    auto deps = GetDependencies(filePath);
    related.insert(related.end(), deps.begin(), deps.end());
    
    // Get dependents
    auto dependents = GetDependents(filePath);
    related.insert(related.end(), dependents.begin(), dependents.end());
    
    // Remove duplicates
    std::sort(related.begin(), related.end());
    related.erase(std::unique(related.begin(), related.end()), related.end());
    
    return related;
}

std::vector<std::string> ContextEngine::RankByRelevance(
    const std::string& query,
    const std::vector<std::string>& candidates) {
    
    // Simple relevance ranking based on string similarity
    // In production, this would use embeddings
    
    std::vector<std::pair<std::string, float>> scored;
    
    for (const auto& candidate : candidates) {
        float score = 0.0f;
        
        // Check if query terms appear in candidate
        std::string lowerQuery = query;
        std::string lowerCandidate = candidate;
        std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
        std::transform(lowerCandidate.begin(), lowerCandidate.end(), lowerCandidate.begin(), ::tolower);
        
        if (lowerCandidate.find(lowerQuery) != std::string::npos) {
            score += 1.0f;
        }
        
        scored.push_back({candidate, score});
    }
    
    // Sort by score descending
    std::sort(scored.begin(), scored.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });
    
    std::vector<std::string> ranked;
    for (const auto& [candidate, score] : scored) {
        ranked.push_back(candidate);
    }
    
    return ranked;
}

int ContextEngine::EstimateTokens(const std::string& text) {
    // Rough estimate: ~4 characters per token
    return static_cast<int>(text.length() / 4);
}

std::string ContextEngine::TruncateToTokens(const std::string& text, int maxTokens) {
    int maxChars = maxTokens * 4;
    if (text.length() <= maxChars) {
        return text;
    }
    return text.substr(0, maxChars) + "\n... [truncated]";
}

std::string ContextEngine::DetectLanguage(const std::string& filePath) {
    std::string ext = fs::path(filePath).extension().string();
    
    if (ext == ".cpp" || ext == ".cc" || ext == ".cxx") return "cpp";
    if (ext == ".c") return "c";
    if (ext == ".h" || ext == ".hpp") return "cpp";
    if (ext == ".py") return "python";
    if (ext == ".js") return "javascript";
    if (ext == ".ts") return "typescript";
    if (ext == ".java") return "java";
    if (ext == ".rs") return "rust";
    if (ext == ".go") return "go";
    if (ext == ".cs") return "csharp";
    if (ext == ".swift") return "swift";
    if (ext == ".asm" || ext == ".S" || ext == ".s") return "assembly";
    
    return "unknown";
}

std::vector<std::string> ContextEngine::ExtractImports(const std::string& content,
                                                         const std::string& language) {
    std::vector<std::string> imports;
    std::istringstream stream(content);
    std::string line;
    
    if (language == "cpp" || language == "c") {
        std::regex includePattern(R"(#include\s*["<]([^">]+)[">])");
        
        while (std::getline(stream, line)) {
            std::smatch match;
            if (std::regex_search(line, match, includePattern)) {
                imports.push_back(match[1]);
            }
        }
    } else if (language == "python") {
        std::regex importPattern(R"((?:from|import)\s+(\S+))");
        
        while (std::getline(stream, line)) {
            std::smatch match;
            if (std::regex_search(line, match, importPattern)) {
                imports.push_back(match[1]);
            }
        }
    }
    
    return imports;
}

} // namespace CEO
} // namespace RawrXD
