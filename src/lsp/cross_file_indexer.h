/**
 * @file cross_file_indexer.h
 * @brief Cross-File Symbol Resolution - Real Multi-File Intelligence
 * @status PRODUCTION - Full workspace-wide symbol indexing
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <mutex>
#include <future>

namespace RawrXD::LSP {

struct SymbolLocation {
    std::string file;
    uint32_t line;
    uint32_t column;
    std::string context;  // Line content for preview
};

struct CrossFileSymbol {
    std::string name;
    std::string fullyQualifiedName;
    std::string kind;  // class, function, variable, etc.
    std::string type;  // For variables/functions
    SymbolLocation definition;
    std::vector<SymbolLocation> declarations;
    std::vector<SymbolLocation> references;
    std::vector<std::string> parentScopes;
    bool isPublic;
    std::string documentation;
};

struct IncludeDependency {
    std::string sourceFile;
    std::string includedFile;
    bool isSystemInclude;
    uint32_t line;
};

struct FileMetadata {
    std::string path;
    std::time_t lastModified;
    std::time_t lastIndexed;
    size_t symbolCount;
    std::set<std::string> includedBy;
    std::set<std::string> includes;
    bool needsReindex;
};

class CrossFileIndexer {
public:
    CrossFileIndexer();
    ~CrossFileIndexer();
    
    // Workspace management
    void SetWorkspaceRoot(const std::string& root);
    void AddFile(const std::string& path);
    void RemoveFile(const std::string& path);
    void UpdateFile(const std::string& path);
    
    // Indexing
    void StartBackgroundIndexing();
    void StopBackgroundIndexing();
    bool IsIndexing() const { return m_indexing; }
    
    // Synchronous indexing for specific file
    void IndexFile(const std::string& path);
    
    // Symbol queries
    std::vector<CrossFileSymbol> FindSymbolsByName(const std::string& name);
    std::vector<CrossFileSymbol> FindSymbolsByPrefix(const std::string& prefix, size_t maxResults = 100);
    std::vector<CrossFileSymbol> FindSymbolsByKind(const std::string& kind);
    
    // Cross-file navigation
    CrossFileSymbol* FindDefinition(const std::string& name, const std::string& contextFile);
    std::vector<SymbolLocation> FindReferences(const std::string& name, const std::string& contextFile);
    std::vector<SymbolLocation> FindDeclarations(const std::string& name);
    
    // Semantic queries
    std::vector<CrossFileSymbol> FindSymbolsInScope(const std::string& scope);
    std::vector<CrossFileSymbol> FindDerivedClasses(const std::string& baseClass);
    std::vector<CrossFileSymbol> FindImplementations(const std::string& interface);
    
    // Include graph
    std::vector<std::string> GetIncludeChain(const std::string& from, const std::string& to);
    std::vector<std::string> GetTransitiveIncludes(const std::string& file);
    std::vector<std::string> GetFilesIncluding(const std::string& header);
    
    // Dependency analysis
    std::vector<std::string> GetFilesAffectedByChange(const std::string& changedFile);
    std::vector<std::string> GetRebuildOrder(const std::vector<std::string>& modifiedFiles);
    
    // Status
    size_t GetIndexedFileCount() const;
    size_t GetSymbolCount() const;
    FileMetadata GetFileMetadata(const std::string& path) const;
    
    // Persistence
    bool SaveIndex(const std::string& path);
    bool LoadIndex(const std::string& path);
    
    // Callbacks
    void SetProgressCallback(std::function<void(const std::string&, int)> callback);
    void SetIndexCompleteCallback(std::function<void(const std::string&)> callback);

private:
    std::string m_workspaceRoot;
    std::map<std::string, CrossFileSymbol> m_symbols;
    std::map<std::string, FileMetadata> m_fileMetadata;
    std::vector<IncludeDependency> m_includes;
    
    mutable std::mutex m_mutex;
    std::atomic<bool> m_indexing;
    std::thread m_indexThread;
    std::condition_variable m_indexCV;
    std::queue<std::string> m_pendingFiles;
    
    std::function<void(const std::string&, int)> m_progressCallback;
    std::function<void(const std::string&)> m_completeCallback;
    
    void IndexerThread();
    void ParseFile(const std::string& path);
    void ExtractSymbols(const std::string& path, const std::string& content);
    void ExtractIncludes(const std::string& path, const std::string& content);
    std::string ResolveInclude(const std::string& includePath, const std::string& contextFile);
    void UpdateIncludeGraph();
    
    // C++ parsing helpers
    std::vector<std::string> Tokenize(const std::string& content);
    std::string ExtractScope(const std::vector<std::string>& tokens, size_t pos);
    bool IsPublicDeclaration(const std::vector<std::string>& tokens, size_t pos);
};

} // namespace RawrXD::LSP
