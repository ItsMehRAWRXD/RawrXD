// ============================================================================
// ContextEngine.hpp — Intelligent Context Assembly for AI Operations
// Assembles the right context for each model call based on repository state
// Delegates to Repository Intelligence primitives for deep code understanding
// ============================================================================
#pragma once

#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>

namespace RawrXD {
namespace IDE {
class FileIndex;
class SymbolTable;
class ASTCache;
class SearchIndex;
class CallGraph;
class IncludeGraph;
}

namespace CEO {

using json = nlohmann::json;

// ============================================================================
// File Context
// ============================================================================
struct FileContext {
    std::string path;
    std::string content;
    std::string language;
    std::vector<std::string> symbols;
    std::vector<std::string> imports;
    std::vector<std::string> dependencies;
    int lineCount = 0;
    bool isOpen = false;
    bool hasErrors = false;
    std::chrono::system_clock::time_point lastModified;
};

// ============================================================================
// Symbol Information
// ============================================================================
struct SymbolInfo {
    std::string name;
    std::string type; // function, class, variable, etc.
    std::string filePath;
    int lineNumber = 0;
    std::string signature;
    std::vector<std::string> references;
    std::vector<std::string> dependencies;
};

// ============================================================================
// Repository Index
// ============================================================================
struct RepositoryIndex {
    std::string rootPath;
    std::vector<FileContext> files;
    std::map<std::string, SymbolInfo> symbols;
    std::map<std::string, std::vector<std::string>> dependencies;
    std::chrono::system_clock::time_point indexedAt;
    bool isComplete = false;
};

// ============================================================================
// Context Request
// ============================================================================
struct ContextRequest {
    std::string query;
    std::string activeFile;
    int cursorLine = 0;
    int cursorColumn = 0;
    std::vector<std::string> openFiles;
    std::vector<std::string> recentErrors;
    int maxTokens = 8192;
    bool includeHistory = true;
    bool includeDependencies = true;
    bool includeTests = true;
};

// ============================================================================
// Context Engine
// Assembles optimal context for model inference
// ============================================================================
class ContextEngine {
public:
    ContextEngine();
    ~ContextEngine();
    
    // Initialization
    bool Initialize(const std::string& projectRoot);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // Repository Indexing
    bool IndexRepository();
    bool IndexFile(const std::string& filePath);
    bool UpdateFile(const std::string& filePath);
    bool RemoveFile(const std::string& filePath);
    
    // Context Assembly
    json GetRelevantContext(const std::string& query);
    json GetContextForCompletion(const std::string& filePath, int line, int column);
    json GetContextForError(const std::string& errorMessage);
    json GetContextForTask(const std::string& taskDescription);
    json AssembleContext(const ContextRequest& request);
    
    // Symbol Resolution
    std::vector<SymbolInfo> FindSymbol(const std::string& name);
    std::vector<SymbolInfo> FindReferences(const std::string& symbolName);
    std::vector<std::string> GetDependencies(const std::string& filePath);
    std::vector<std::string> GetDependents(const std::string& filePath);
    
    // Search
    std::vector<FileContext> SearchFiles(const std::string& pattern);
    std::vector<SymbolInfo> SearchSymbols(const std::string& pattern);
    
    // Statistics
    json GetRepositoryStats() const;
    int GetFileCount() const;
    int GetSymbolCount() const;
    
    // Cache management
    void ClearCache();
    bool SaveIndex(const std::string& path);
    bool LoadIndex(const std::string& path);
    
    // Callbacks
    using IndexCallback = std::function<void(const std::string& file, int current, int total)>;
    void SetIndexCallback(IndexCallback cb) { m_indexCb = cb; }
    
    // Repository Intelligence integration
    void SetRepoPrimitives(IDE::FileIndex* fileIndex,
                           IDE::SymbolTable* symbolTable,
                           IDE::ASTCache* astCache,
                           IDE::SearchIndex* searchIndex,
                           IDE::CallGraph* callGraph,
                           IDE::IncludeGraph* includeGraph);
    
private:
    // Internal methods
    bool ParseFile(const std::string& path, FileContext& context);
    bool ExtractSymbols(const FileContext& file, std::vector<SymbolInfo>& symbols);
    std::vector<std::string> FindRelatedFiles(const std::string& filePath);
    std::vector<std::string> RankByRelevance(const std::string& query, 
                                               const std::vector<std::string>& candidates);
    int EstimateTokens(const std::string& text);
    std::string TruncateToTokens(const std::string& text, int maxTokens);
    
    // Language detection
    std::string DetectLanguage(const std::string& filePath);
    
    // Import extraction
    std::vector<std::string> ExtractImports(const std::string& content, 
                                             const std::string& language);
    
private:
    bool m_initialized = false;
    std::string m_projectRoot;
    RepositoryIndex m_index;
    mutable std::mutex m_indexMutex;
    
    // Cache
    std::map<std::string, FileContext> m_fileCache;
    std::map<std::string, std::chrono::system_clock::time_point> m_cacheTimestamps;
    
    // Callbacks
    IndexCallback m_indexCb;
    
    // Repository Intelligence primitives (optional, for deep analysis)
    IDE::FileIndex* m_fileIndex = nullptr;
    IDE::SymbolTable* m_symbolTable = nullptr;
    IDE::ASTCache* m_astCache = nullptr;
    IDE::SearchIndex* m_searchIndex = nullptr;
    IDE::CallGraph* m_callGraph = nullptr;
    IDE::IncludeGraph* m_includeGraph = nullptr;
};

} // namespace CEO
} // namespace RawrXD
