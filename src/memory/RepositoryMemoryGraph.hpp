// Repository Memory Graph - Persistent Project Understanding
//
// Eliminates the need to reconstruct context per prompt by maintaining:
// - AST (Abstract Syntax Tree) for all source files
// - Symbol table with cross-references
// - Build dependency graph
// - File change tracking
// - Semantic relationships
//
// This is the "memory" of the Sovereign Substrate - the project lives here,
// not in serialized prompts.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace Memory {

// Forward declarations
class ASTNode;
class Symbol;
class DependencyEdge;
class FileNode;
class RepositoryGraph;

// ============================================================================
// Core Types
// ============================================================================

using NodeId = uint64_t;
using SymbolId = uint64_t;
using FileId = uint64_t;
using EdgeId = uint64_t;
using Timestamp = std::chrono::steady_clock::time_point;

enum class NodeType : uint32_t {
    FILE = 0,
    DIRECTORY = 1,
    NAMESPACE = 2,
    CLASS = 3,
    STRUCT = 4,
    FUNCTION = 5,
    METHOD = 6,
    VARIABLE = 7,
    ENUM = 8,
    TYPEDEF = 9,
    MACRO = 10,
    TEMPLATE = 11,
    CONCEPT = 12,
    
    COUNT = 13
};

enum class EdgeType : uint32_t {
    CONTAINS = 0,           // Parent contains child
    DEPENDS_ON = 1,         // File depends on another
    CALLS = 2,              // Function calls function
    REFERENCES = 3,         // Symbol references symbol
    INHERITS_FROM = 4,      // Class inherits from class
    IMPLEMENTS = 5,         // Implements interface
    IMPORTS = 6,            // Imports module/header
    INSTANTIATES = 7,       // Template instantiation
    
    COUNT = 8
};

enum class SymbolVisibility : uint32_t {
    PUBLIC = 0,
    PROTECTED = 1,
    PRIVATE = 2,
    INTERNAL = 3,
    ANONYMOUS = 4
};

// ============================================================================
// Source Location - Where something lives in code
// ============================================================================

struct SourceLocation {
    FileId fileId;
    std::string filePath;
    uint32_t line;
    uint32_t column;
    uint32_t offset;        // Byte offset in file
    uint32_t length;        // Length of construct
    
    std::string ToString() const;
    bool IsValid() const { return fileId != 0 && line > 0; }
};

// ============================================================================
// AST Node - Any construct in the code
// ============================================================================

class ASTNode : public std::enable_shared_from_this<ASTNode> {
public:
    NodeId nodeId;
    NodeType type;
    std::string name;
    std::string qualifiedName;  // Fully qualified (namespace::class::method)
    SourceLocation location;
    
    // Hierarchy
    std::weak_ptr<ASTNode> parent;
    std::vector<std::shared_ptr<ASTNode>> children;
    
    // Semantic info
    std::string signature;      // For functions: "void foo(int, const string&)"
    std::string documentation;  // Extracted comments
    std::vector<std::string> annotations; // [[nodiscard]], [[deprecated]], etc.
    
    // State
    Timestamp lastModified;
    uint64_t contentHash;       // Hash of source text
    bool isDirty{false};        // Needs re-analysis
    bool isGenerated{false};    // Generated code (build output)
    
    // Methods
    std::string GetTypeString() const;
    std::vector<std::shared_ptr<ASTNode>> GetChildrenOfType(NodeType type) const;
    std::shared_ptr<ASTNode> FindChild(const std::string& name) const;
    std::shared_ptr<ASTNode> GetAncestorOfType(NodeType type) const;
    
    // Serialization
    std::string ToJson() const;
    static std::shared_ptr<ASTNode> FromJson(const std::string& json);
};

// ============================================================================
// Symbol - Named entity that can be referenced
// ============================================================================

class Symbol : public std::enable_shared_from_this<Symbol> {
public:
    SymbolId symbolId;
    std::string name;
    std::string mangledName;    // For linking
    NodeType kind;
    SymbolVisibility visibility;
    
    // Location
    SourceLocation definition;
    std::vector<SourceLocation> declarations;
    std::vector<SourceLocation> references;  // All usage sites
    
    // Type info (for variables/functions)
    std::string typeName;       // "int", "std::string", "void(*)()"
    std::string returnType;      // For functions
    std::vector<std::pair<std::string, std::string>> parameters; // (name, type)
    
    // Relationships
    std::weak_ptr<Symbol> parentScope;
    std::vector<std::weak_ptr<Symbol>> childSymbols;
    std::vector<std::weak_ptr<Symbol>> relatedSymbols; // Related by usage
    
    // State
    bool isDefined{false};
    bool isExported{false};
    bool isTemplate{false};
    bool isConstexpr{false};
    bool isNoexcept{false};
    
    // Methods
    std::string GetSignature() const;
    std::vector<std::shared_ptr<Symbol>> GetReferences() const;
    std::shared_ptr<Symbol> GetDefinition() const;
    
    // Serialization
    std::string ToJson() const;
};

// ============================================================================
// Dependency Edge - Relationship between nodes
// ============================================================================

class DependencyEdge : public std::enable_shared_from_this<DependencyEdge> {
public:
    EdgeId edgeId;
    EdgeType type;
    std::weak_ptr<ASTNode> source;
    std::weak_ptr<ASTNode> target;
    
    // Metadata
    uint32_t strength{1};      // How strong the dependency (call count, etc.)
    bool isCyclic{false};      // Part of a cycle
    bool isOptional{false};      // Optional dependency (weak import)
    
    // For build dependencies
    std::string buildCondition; // "#ifdef DEBUG", etc.
    
    SourceLocation referenceLocation; // Where the dependency is expressed
    
    // Methods
    std::string GetTypeString() const;
    bool IsValid() const;
    
    // Serialization
    std::string ToJson() const;
};

// ============================================================================
// File Node - Source file in the repository
// ============================================================================

class FileNode : public ASTNode {
public:
    FileId fileId;
    std::string absolutePath;
    std::string relativePath;   // From repo root
    std::string extension;
    
    // Content
    uint64_t contentHash;
    uint64_t fileSize;
    Timestamp lastModified;
    
    // Language
    enum class Language {
        UNKNOWN = 0,
        CPP = 1,
        C = 2,
        HLSL = 3,
        CUDA = 4,
        MASM = 5,
        PYTHON = 6,
        CMAKE = 7,
        JSON = 8,
        XML = 9
    } language;
    
    // Build info
    std::string targetName;     // Which build target owns this
    bool isHeader{false};
    bool isSource{false};
    bool isGenerated{false};
    bool isExternal{false};     // Third-party code
    
    // State
    bool needsReparse{false};
    bool hasErrors{false};
    std::vector<std::string> errorMessages;
    
    // Methods
    std::string GetLanguageString() const;
    std::vector<std::shared_ptr<FileNode>> GetDependencies() const;
    std::vector<std::shared_ptr<FileNode>> GetDependents() const;
};

// ============================================================================
// Query Types - How to search the graph
// ============================================================================

struct SymbolQuery {
    std::string namePattern;           // "*Matrix*" or exact "MatrixMul"
    NodeType type{NodeType::COUNT};    // Any type or specific
    SymbolVisibility visibility{SymbolVisibility::PUBLIC};
    FileId inFile{0};                // Limit to specific file
    bool includeGenerated{false};
    uint32_t maxResults{100};
};

struct DependencyQuery {
    FileId fromFile;
    EdgeType edgeType{EdgeType::DEPENDS_ON};
    bool transitive{false};          // Follow dependencies recursively
    uint32_t maxDepth{5};
};

struct ImpactQuery {
    FileId changedFile;
    bool includeTests{true};
    bool includeGenerated{false};
    uint32_t maxResults{100};
};

// ============================================================================
// Repository Graph - The main memory structure
// ============================================================================

class RepositoryGraph {
public:
    static RepositoryGraph& Instance();
    
    // Lifecycle
    bool Initialize(const std::string& repoRoot);
    void Shutdown();
    bool IsInitialized() const { return initialized_.load(); }
    
    // File management
    std::shared_ptr<FileNode> AddFile(const std::string& path);
    void RemoveFile(FileId fileId);
    void UpdateFile(FileId fileId, const std::string& newContent);
    std::shared_ptr<FileNode> GetFile(FileId fileId) const;
    std::shared_ptr<FileNode> GetFileByPath(const std::string& path) const;
    std::vector<std::shared_ptr<FileNode>> GetAllFiles() const;
    std::vector<std::shared_ptr<FileNode>> GetDirtyFiles() const;
    
    // Symbol management
    std::shared_ptr<Symbol> AddSymbol(const std::string& name, NodeType kind);
    void RemoveSymbol(SymbolId symbolId);
    std::shared_ptr<Symbol> GetSymbol(SymbolId symbolId) const;
    std::shared_ptr<Symbol> FindSymbol(const std::string& qualifiedName) const;
    std::vector<std::shared_ptr<Symbol>> QuerySymbols(const SymbolQuery& query) const;
    
    // Dependency management
    std::shared_ptr<DependencyEdge> AddDependency(
        std::shared_ptr<ASTNode> source,
        std::shared_ptr<ASTNode> target,
        EdgeType type
    );
    void RemoveDependency(EdgeId edgeId);
    std::vector<std::shared_ptr<DependencyEdge>> GetDependencies(
        std::shared_ptr<ASTNode> node,
        EdgeType type = EdgeType::DEPENDS_ON
    ) const;
    std::vector<std::shared_ptr<DependencyEdge>> GetDependents(
        std::shared_ptr<ASTNode> node,
        EdgeType type = EdgeType::DEPENDS_ON
    ) const;
    
    // Impact analysis
    std::vector<std::shared_ptr<FileNode>> GetImpactSet(
        const ImpactQuery& query
    ) const;
    std::vector<std::shared_ptr<Symbol>> GetAffectedSymbols(
        FileId changedFile
    ) const;
    
    // Build graph
    std::vector<std::shared_ptr<FileNode>> GetBuildOrder(
        const std::vector<FileId>& targets
    ) const;
    std::vector<std::vector<std::shared_ptr<FileNode>>> GetBuildLevels() const;
    
    // Cross-reference
    void AddReference(SymbolId symbol, const SourceLocation& location);
    std::vector<SourceLocation> GetReferences(SymbolId symbol) const;
    std::shared_ptr<Symbol> FindSymbolAtLocation(const SourceLocation& location) const;
    
    // Incremental updates
    void MarkFileDirty(FileId fileId);
    void ReparseFile(FileId fileId);
    void ReparseDirtyFiles();
    
    // Persistence
    bool SaveToDisk(const std::string& path);
    bool LoadFromDisk(const std::string& path);
    
    // Statistics
    struct Stats {
        uint64_t fileCount{0};
        uint64_t symbolCount{0};
        uint64_t edgeCount{0};
        uint64_t referenceCount{0};
        uint64_t dirtyFileCount{0};
        double memoryUsageMB{0.0};
        Timestamp lastUpdate;
    };
    Stats GetStats() const;
    
    // Events
    using FileChangeCallback = std::function<void(FileId, const std::string&)>;
    void SubscribeToFileChanges(FileChangeCallback callback);
    
    // Context extraction for models
    std::string ExtractContextForSymbol(
        SymbolId symbol,
        uint32_t contextLines = 50
    ) const;
    std::vector<std::string> ExtractRelatedSymbols(
        SymbolId symbol,
        uint32_t maxDepth = 2
    ) const;
    std::string ExtractBuildContextForFile(FileId file) const;

private:
    RepositoryGraph() = default;
    
    mutable std::mutex mutex_;
    std::atomic<bool> initialized_{false};
    std::string repoRoot_;
    
    // Storage
    std::unordered_map<FileId, std::shared_ptr<FileNode>> files_;
    std::unordered_map<SymbolId, std::shared_ptr<Symbol>> symbols_;
    std::unordered_map<EdgeId, std::shared_ptr<DependencyEdge>> edges_;
    std::unordered_map<NodeId, std::shared_ptr<ASTNode>> nodes_;
    
    // Indexes
    std::unordered_map<std::string, FileId> pathToFile_;
    std::unordered_map<std::string, SymbolId> qualifiedNameToSymbol_;
    std::unordered_multimap<std::string, SymbolId> nameToSymbols_;
    
    // Change tracking
    std::unordered_set<FileId> dirtyFiles_;
    std::vector<FileChangeCallback> fileChangeCallbacks_;
    
    // ID generators
    std::atomic<FileId> nextFileId_{1};
    std::atomic<SymbolId> nextSymbolId_{1};
    std::atomic<EdgeId> nextEdgeId_{1};
    std::atomic<NodeId> nextNodeId_{1};
    
    // Helpers
    FileId GenerateFileId() { return nextFileId_++; }
    SymbolId GenerateSymbolId() { return nextSymbolId_++; }
    EdgeId GenerateEdgeId() { return nextEdgeId_++; }
    NodeId GenerateNodeId() { return nextNodeId_++; }
    
    void BuildIndexes();
    void InvalidateCache(FileId fileId);
};

// ============================================================================
// Graph Walker - Traverse the graph with callbacks
// ============================================================================

class GraphWalker {
public:
    using VisitCallback = std::function<bool(std::shared_ptr<ASTNode>, uint32_t depth)>;
    using EdgeFilter = std::function<bool(std::shared_ptr<DependencyEdge>)>;
    
    static void Walk(
        std::shared_ptr<ASTNode> start,
        VisitCallback visitor,
        EdgeFilter filter = nullptr,
        uint32_t maxDepth = 10
    );
    
    static std::vector<std::shared_ptr<ASTNode>> FindPath(
        std::shared_ptr<ASTNode> from,
        std::shared_ptr<ASTNode> to,
        EdgeType edgeType = EdgeType::DEPENDS_ON
    );
    
    static std::vector<std::shared_ptr<ASTNode>> FindCycles(
        std::shared_ptr<ASTNode> start,
        EdgeType edgeType = EdgeType::DEPENDS_ON
    );
};

// ============================================================================
// Context Assembler - Build model context from graph
// ============================================================================

class ContextAssembler {
public:
    static ContextAssembler& Instance();
    
    // Build context for specific tasks
    std::string AssembleContextForIntent(
        const std::string& intentType,
        const std::string& targetSymbol,
        uint32_t maxTokens = 4096
    );
    
    std::string AssembleContextForBuild(
        FileId changedFile,
        const std::vector<std::string>& errors
    );
    
    std::string AssembleContextForDebug(
        const std::string& symbol,
        const std::string& errorMessage
    );
    
    std::string AssembleContextForOptimize(
        SymbolId targetFunction,
        const std::string& optimizationGoal
    );
    
    // Token management
    uint32_t EstimateTokens(const std::string& text) const;
    std::string TruncateToTokens(const std::string& text, uint32_t maxTokens) const;
    
    // Priority-based context assembly
    struct ContextFragment {
        std::string content;
        uint32_t priority;      // Higher = more important
        uint32_t tokenCount;
        std::string source;     // Where this came from
    };
    
    std::string AssembleFromFragments(
        const std::vector<ContextFragment>& fragments,
        uint32_t maxTokens
    );

private:
    ContextAssembler() = default;
};

} // namespace Memory
} // namespace RawrXD
