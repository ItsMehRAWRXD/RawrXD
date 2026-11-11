// ============================================================================
// RepositoryIntelligence.hpp — Deep Code Understanding
// Provides complete project awareness: symbols, dependencies, semantic search
// ============================================================================
#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>

namespace RawrXD {
namespace Repository {

using json = nlohmann::json;

// ============================================================================
// Symbol Types
// ============================================================================
enum class SymbolType {
    Function,
    Method,
    Class,
    Struct,
    Interface,
    Enum,
    Variable,
    Constant,
    Namespace,
    Module,
    Import,
    Macro,
    TypeAlias,
    Unknown
};

// ============================================================================
// Symbol Location
// ============================================================================
struct SymbolLocation {
    std::string filePath;
    int startLine = 0;
    int startColumn = 0;
    int endLine = 0;
    int endColumn = 0;
};

// ============================================================================
// Symbol Definition
// ============================================================================
struct Symbol {
    std::string name;
    std::string qualifiedName;
    SymbolType type = SymbolType::Unknown;
    SymbolLocation location;
    std::string signature;
    std::string documentation;
    std::vector<std::string> parameters;
    std::string returnType;
    std::vector<std::string> modifiers; // public, static, const, etc.
    std::string parentScope; // Class/namespace containing this symbol
    
    // Relationships
    std::vector<std::string> calls;        // Functions this symbol calls
    std::vector<std::string> calledBy;     // Functions that call this symbol
    std::vector<std::string> references;   // All references to this symbol
    std::vector<std::string> dependencies; // Symbols this depends on
};

// ============================================================================
// File Information
// ============================================================================
struct FileInfo {
    std::string path;
    std::string language;
    int lineCount = 0;
    std::vector<Symbol> symbols;
    std::vector<std::string> imports;
    std::vector<std::string> dependencies;
    std::vector<std::string> dependents;
    std::chrono::system_clock::time_point lastModified;
    bool isTestFile = false;
    bool isGenerated = false;
};

// ============================================================================
// Dependency Graph
// ============================================================================
struct DependencyGraph {
    std::map<std::string, std::set<std::string>> fileDependencies;
    std::map<std::string, std::set<std::string>> symbolDependencies;
    
    std::vector<std::string> GetDependencies(const std::string& file) const;
    std::vector<std::string> GetDependents(const std::string& file) const;
    std::vector<std::string> GetTransitiveDependencies(const std::string& file) const;
    bool HasCircularDependency(const std::string& file) const;
};

// ============================================================================
// Search Result
// ============================================================================
struct SearchResult {
    Symbol symbol;
    float relevanceScore = 0.0f;
    std::string matchedText;
    std::string contextPreview;
};

// ============================================================================
// Change Impact
// ============================================================================
struct ChangeImpact {
    std::string changedFile;
    std::vector<std::string> directlyAffectedFiles;
    std::vector<std::string> transitivelyAffectedFiles;
    std::vector<Symbol> affectedSymbols;
    std::vector<std::string> testsToRun;
    int estimatedRisk = 0; // 0-100
};

// ============================================================================
// Repository Intelligence
// Deep understanding of codebase structure and relationships
// ============================================================================
class RepositoryIntelligence {
public:
    RepositoryIntelligence();
    ~RepositoryIntelligence();
    
    // Initialization
    bool Initialize(const std::string& rootPath);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // Indexing
    bool IndexRepository();
    bool IndexFile(const std::string& filePath);
    bool UpdateFile(const std::string& filePath);
    bool RemoveFile(const std::string& filePath);
    bool IsIndexing() const { return m_indexing.load(); }
    float GetIndexingProgress() const { return m_indexProgress.load(); }
    
    // Symbol queries
    std::vector<Symbol> FindSymbol(const std::string& name);
    std::vector<Symbol> FindSymbolsByType(SymbolType type);
    std::vector<Symbol> FindSymbolsInFile(const std::string& filePath);
    Symbol GetSymbolAtPosition(const std::string& filePath, int line, int column);
    
    // Reference queries
    std::vector<SymbolLocation> FindReferences(const std::string& symbolName);
    std::vector<Symbol> FindCallers(const std::string& functionName);
    std::vector<Symbol> FindCallees(const std::string& functionName);
    
    // Search
    std::vector<SearchResult> Search(const std::string& query);
    std::vector<SearchResult> SemanticSearch(const std::string& query);
    std::vector<SearchResult> FindSimilarCode(const std::string& codeSnippet);
    
    // Dependency analysis
    DependencyGraph GetDependencyGraph() const;
    std::vector<std::string> GetDependencies(const std::string& filePath);
    std::vector<std::string> GetDependents(const std::string& filePath);
    ChangeImpact AnalyzeChangeImpact(const std::string& filePath);
    
    // Context assembly
    std::vector<Symbol> GetRelevantSymbols(const std::string& query, 
                                           const std::string& contextFile,
                                           int maxSymbols = 20);
    std::vector<FileInfo> GetRelevantFiles(const std::string& query, 
                                            int maxFiles = 10);
    json BuildContextForQuery(const std::string& query,
                              const std::string& activeFile = "");
    
    // Code navigation
    std::vector<std::string> GetDefinitionPath(const std::string& fromFile,
                                               const std::string& toFile);
    std::vector<Symbol> GetInheritanceHierarchy(const std::string& className);
    std::vector<Symbol> GetImplementationHierarchy(const std::string& interfaceName);
    
    // Statistics
    json GetRepositoryStats() const;
    int GetFileCount() const;
    int GetSymbolCount() const;
    std::map<std::string, int> GetLanguageDistribution() const;
    
    // Persistence
    bool SaveIndex(const std::string& path);
    bool LoadIndex(const std::string& path);
    bool IsIndexStale() const;
    
    // Callbacks
    using IndexCallback = std::function<void(const std::string& file, 
                                             int current, 
                                             int total)>;
    using ChangeCallback = std::function<void(const std::string& file)>;
    
    void SetIndexCallback(IndexCallback cb) { m_indexCallback = cb; }
    void SetChangeCallback(ChangeCallback cb) { m_changeCallback = cb; }
    
private:
    // Internal methods
    bool ParseFile(const std::string& path, FileInfo& info);
    bool ExtractSymbols(const FileInfo& file, std::vector<Symbol>& symbols);
    bool BuildDependencyGraph();
    float CalculateRelevance(const Symbol& symbol, const std::string& query);
    std::string SymbolTypeToString(SymbolType type);
    SymbolType StringToSymbolType(const std::string& str);
    
    // File watching
    void StartFileWatcher();
    void StopFileWatcher();
    void OnFileChanged(const std::string& path);
    
private:
    bool m_initialized = false;
    std::string m_rootPath;
    
    // Data
    std::map<std::string, FileInfo> m_files;
    std::map<std::string, Symbol> m_symbols; // qualified name -> symbol
    DependencyGraph m_dependencies;
    mutable std::mutex m_dataMutex;
    
    // Indexing state
    std::atomic<bool> m_indexing{false};
    std::atomic<float> m_indexProgress{0.0f};
    std::chrono::system_clock::time_point m_lastIndexTime;
    
    // File watching
    std::unique_ptr<std::thread> m_watcherThread;
    std::atomic<bool> m_watching{false};
    
    // Callbacks
    IndexCallback m_indexCallback;
    ChangeCallback m_changeCallback;
};

} // namespace Repository
} // namespace RawrXD
