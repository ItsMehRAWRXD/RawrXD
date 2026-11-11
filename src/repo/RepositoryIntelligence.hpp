// ============================================================================
// RepositoryIntelligence.hpp - Semantic Code Indexing System
// AST graphs, symbol tables, type databases, cross-references
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <functional>
#include <optional>
#include <filesystem>
#include <ctime>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace Repo {

// ============================================================================
// Symbol Kinds
// ============================================================================
enum class SymbolKind {
    Unknown,
    Namespace,
    Class,
    Struct,
    Enum,
    Function,
    Method,
    Variable,
    Field,
    Parameter,
    Template,
    Concept,
    Macro,
    Typedef,
    Using
};

// ============================================================================
// Symbol Location
// ============================================================================
struct SourceLocation {
    std::string filePath;
    uint32_t line;
    uint32_t column;
    uint32_t offset;
    
    bool operator==(const SourceLocation& other) const {
        return filePath == other.filePath && 
               line == other.line && 
               column == other.column;
    }
    
    nlohmann::json toJson() const;
    static SourceLocation fromJson(const nlohmann::json& j);
};

// ============================================================================
// Symbol Definition
// ============================================================================
struct Symbol {
    std::string id;              // Unique symbol ID (mangled name or hash)
    std::string name;            // Display name
    std::string qualifiedName;   // Fully qualified name
    SymbolKind kind;
    SourceLocation location;
    SourceLocation definition;   // Where defined
    std::vector<SourceLocation> declarations;
    std::string type;            // For variables/fields
    std::string signature;       // For functions/methods
    std::string parent;          // Parent symbol ID (class/namespace)
    std::vector<std::string> children;
    std::vector<std::string> modifiers; // public, static, const, etc.
    std::string documentation;   // Doxygen/comments
    std::string sourceHash;      // Hash of containing file
    
    nlohmann::json toJson() const;
    static Symbol fromJson(const nlohmann::json& j);
};

// ============================================================================
// Reference Types
// ============================================================================
enum class ReferenceKind {
    Definition,
    Declaration,
    Call,
    Read,
    Write,
    AddressOf,
    Inheritance,
    Implementation,
    Override
};

struct Reference {
    std::string symbolId;
    ReferenceKind kind;
    SourceLocation location;
    std::string context;         // Enclosing function/class
    
    nlohmann::json toJson() const;
};

// ============================================================================
// Type Information
// ============================================================================
struct TypeInfo {
    std::string name;
    std::string canonicalType;
    std::string baseType;        // For pointers, references
    std::vector<std::string> templateArgs;
    bool isConst;
    bool isPointer;
    bool isReference;
    bool isArray;
    size_t arraySize;
    
    nlohmann::json toJson() const;
};

// ============================================================================
// Call Graph Edge
// ============================================================================
struct CallEdge {
    std::string caller;          // Function ID
    std::string callee;          // Function ID
    SourceLocation callSite;
    bool isVirtual;
    bool isRecursive;
};

// ============================================================================
// Include/Import Graph
// ============================================================================
struct IncludeEdge {
    std::string fromFile;
    std::string toFile;
    bool isSystem;               // #include <...> vs "..."
    SourceLocation location;
};

// ============================================================================
// AST Node (Simplified)
// ============================================================================
struct ASTNode {
    std::string kind;            // CXXRecordDecl, FunctionDecl, etc.
    SourceLocation location;
    std::vector<ASTNode> children;
    std::map<std::string, std::string> attributes;
    std::string symbolId;        // Link to symbol table
};

// ============================================================================
// File Info Entry (for FileIndex)
// ============================================================================
struct FileInfo {
    uint32_t id = 0;
    std::filesystem::path path;
    std::string pathStr;
    std::string extension;
    std::string content;
    std::string hash;
    uint64_t size = 0;
    std::time_t mtime = 0;
    bool isDirty = false;
};

// ============================================================================
// File Index Entry
// ============================================================================
struct FileIndex {
    std::string path;
    std::string hash;            // Content hash
    uint64_t lastModified;
    std::vector<std::string> symbols;      // Symbols defined in file
    std::vector<std::string> references;   // External symbols referenced
    std::vector<std::string> includes;     // Files this file includes
    std::vector<std::string> includedBy;   // Files that include this
    bool isIndexed;
    bool needsReindex;
    
    nlohmann::json toJson() const;
    static FileIndex fromJson(const nlohmann::json& j);
};

// ============================================================================
// File Index Manager - Incremental Filesystem Tracking
// ============================================================================
class FileIndexManager {
public:
    FileIndexManager();
    ~FileIndexManager();

    void IndexWorkspace(const std::filesystem::path& root);
    void IndexFile(const std::filesystem::path& path);
    void ReindexFile(const std::string& fileId);

    std::optional<FileInfo> GetFile(const std::string& fileId) const;
    std::optional<FileInfo> GetFileByPath(const std::filesystem::path& path) const;
    std::vector<FileInfo> GetAllFiles() const;
    std::vector<FileInfo> GetModifiedSince(std::time_t timestamp) const;
    std::vector<FileInfo> GetFilesByExtension(const std::string& ext) const;

    void MarkDirty(const std::string& fileId);
    void MarkClean(const std::string& fileId);
    std::vector<FileInfo> GetDirtyFiles() const;

    void StartWatching();
    void StopWatching();
    std::vector<std::filesystem::path> PollChanges();

    static std::string ComputeHash(const std::string& content);

private:
    void IndexFileInternal(const std::filesystem::path& path);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Search Result
// ============================================================================
struct SearchResult {
    std::string symbolId;
    std::string name;
    SymbolKind kind;
    SourceLocation location;
    float relevance;
    std::string summary;
};

// ============================================================================
// Repository Intelligence - Main Interface
// ============================================================================
class RepositoryIntelligence {
public:
    RepositoryIntelligence();
    ~RepositoryIntelligence();
    
    // Initialization
    bool Initialize(const std::string& repoRoot);
    bool LoadFromDisk();
    bool SaveToDisk();
    
    // Indexing
    void IndexFile(const std::string& filePath);
    void IndexDirectory(const std::string& dirPath);
    void IncrementalUpdate();
    void FullReindex();
    
    // Symbol queries
    std::optional<Symbol> FindSymbol(const std::string& id) const;
    std::optional<Symbol> FindSymbolAt(const SourceLocation& loc) const;
    std::vector<Symbol> FindSymbolsByName(const std::string& name) const;
    std::vector<Symbol> FindSymbolsInFile(const std::string& filePath) const;
    std::vector<Symbol> GetChildren(const std::string& parentId) const;
    std::optional<Symbol> GetParent(const std::string& symbolId) const;
    
    // Reference queries
    std::vector<Reference> FindReferences(const std::string& symbolId) const;
    std::vector<Reference> FindReferencesAt(const SourceLocation& loc) const;
    std::vector<Reference> FindCallers(const std::string& functionId) const;
    std::vector<Reference> FindCallees(const std::string& functionId) const;
    
    // Navigation
    std::optional<SourceLocation> GoToDefinition(const SourceLocation& loc) const;
    std::optional<SourceLocation> GoToDeclaration(const SourceLocation& loc) const;
    std::vector<SourceLocation> FindImplementations(const std::string& interfaceId) const;
    std::vector<SourceLocation> FindOverrides(const std::string& methodId) const;
    
    // Search
    std::vector<SearchResult> SearchSymbols(const std::string& query) const;
    std::vector<SearchResult> FuzzySearch(const std::string& query) const;
    std::vector<SearchResult> SearchByType(const std::string& typeName) const;
    
    // Graph queries
    std::vector<CallEdge> GetCallGraph() const;
    std::vector<CallEdge> GetCallers(const std::string& functionId) const;
    std::vector<CallEdge> GetCallees(const std::string& functionId) const;
    std::vector<std::string> GetTransitiveIncludes(const std::string& filePath) const;
    std::vector<std::string> GetDependents(const std::string& filePath) const;
    
    // Type queries
    std::optional<TypeInfo> GetTypeInfo(const std::string& typeName) const;
    std::vector<Symbol> FindDerivedTypes(const std::string& baseType) const;
    std::vector<Symbol> FindBaseTypes(const std::string& derivedType) const;
    
    // Impact analysis
    std::vector<std::string> FindAffectedFiles(const std::string& symbolId) const;
    std::vector<std::string> FindAffectedSymbols(const std::string& filePath) const;
    
    // Statistics
    size_t GetSymbolCount() const;
    size_t GetFileCount() const;
    size_t GetReferenceCount() const;
    nlohmann::json GetStatistics() const;
    
    // Maintenance
    void Compact();
    void InvalidateFile(const std::string& filePath);
    void InvalidateSymbol(const std::string& symbolId);
    
    // Event callbacks
    using FileChangeCallback = std::function<void(const std::string& filePath)>;
    void SetFileChangeCallback(FileChangeCallback cb);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Workspace Scanner - File System Watcher
// ============================================================================
class WorkspaceScanner {
public:
    WorkspaceScanner();
    ~WorkspaceScanner();
    
    bool Initialize(const std::string& rootPath);
    void StartWatching();
    void StopWatching();
    
    std::vector<std::string> GetSourceFiles() const;
    std::vector<std::string> GetHeaderFiles() const;
    std::vector<std::string> GetModifiedFiles() const;
    
    void SetChangeCallback(std::function<void(const std::string&)> cb);

private:
    std::string rootPath_;
    std::vector<std::string> sourceFiles_;
    std::vector<std::string> modifiedFiles_;
    std::function<void(const std::string&)> changeCallback_;
    bool watching_;
};

// ============================================================================
// Semantic Database - Type Graph Storage
// ============================================================================
class SemanticDatabase {
public:
    SemanticDatabase();
    ~SemanticDatabase();
    
    bool Initialize(const std::string& dbPath);
    
    // Type graph
    void AddType(const TypeInfo& type);
    void AddInheritance(const std::string& derived, const std::string& base);
    void AddConversion(const std::string& from, const std::string& to);
    
    // Queries
    std::vector<std::string> GetBaseTypes(const std::string& type) const;
    std::vector<std::string> GetDerivedTypes(const std::string& type) const;
    bool IsConvertible(const std::string& from, const std::string& to) const;
    std::vector<std::string> GetCompatibleTypes(const std::string& type) const;
    
    // Save/Load
    bool Save();
    bool Load();

private:
    std::unordered_map<std::string, TypeInfo> types_;
    std::unordered_map<std::string, std::vector<std::string>> inheritance_;
    std::unordered_map<std::string, std::vector<std::string>> conversions_;
    std::string dbPath_;
};

// ============================================================================
// Build Graph - Compile Dependency Tracking
// ============================================================================
class BuildGraph {
public:
    BuildGraph();
    ~BuildGraph();
    
    void AddTarget(const std::string& name, const std::vector<std::string>& sources);
    void AddDependency(const std::string& target, const std::string& dependsOn);
    void AddInclude(const std::string& file, const std::string& includes);
    
    std::vector<std::string> GetBuildOrder() const;
    std::vector<std::string> GetAffectedTargets(const std::string& changedFile) const;
    std::vector<std::string> GetDependencies(const std::string& target) const;
    
    bool HasCycle() const;
    std::vector<std::string> FindCycles() const;

private:
    std::unordered_map<std::string, std::vector<std::string>> dependencies_;
    std::unordered_map<std::string, std::vector<std::string>> includes_;
};

} // namespace Repo
} // namespace RawrXD
