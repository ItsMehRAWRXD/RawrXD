#pragma once

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <functional>

namespace RawrXD {

// ============================================================================
// Repository Intelligence — Semantic Context Retrieval
// Phase 15 — Unification Layer
// ============================================================================
// Upgrades ContextEngine from regex-based to AST-based symbol indexing.
// Provides "Cursor/Copilot-level" repository understanding.
// ============================================================================

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
    TypeAlias,
    Namespace,
    Module,
    Import,
    Unknown
};

// ============================================================================
// Code Symbol — Rich metadata for each indexed symbol
// ============================================================================
struct CodeSymbol {
    std::string name;
    std::string qualifiedName;      // namespace::class::method
    SymbolType type;
    std::string filePath;
    uint32_t lineStart = 0;
    uint32_t lineEnd = 0;
    uint32_t columnStart = 0;
    uint32_t columnEnd = 0;
    
    // Signature for functions/methods
    std::string signature;
    std::string returnType;
    std::vector<std::string> parameters;
    
    // Documentation
    std::string docComment;
    std::string briefDescription;
    
    // Relationships
    std::vector<std::string> references;      // Where this symbol is used
    std::vector<std::string> dependencies;   // What this symbol depends on
    std::string parentScope;                 // Containing class/namespace
    
    // For ranking
    uint32_t usageCount = 0;
    float relevanceScore = 0.0f;
};

// ============================================================================
// Symbol Graph — Dependency and relationship tracking
// ============================================================================
class SymbolGraph {
public:
    void AddSymbol(const CodeSymbol& symbol);
    void AddReference(const std::string& from, const std::string& to);
    void AddDependency(const std::string& from, const std::string& to);
    
    std::vector<CodeSymbol> FindRelated(const std::string& symbolName, uint32_t maxDepth = 2);
    std::vector<CodeSymbol> FindDependents(const std::string& symbolName);
    std::vector<CodeSymbol> FindDependencies(const std::string& symbolName);
    
    std::vector<CodeSymbol> GetSymbolsInFile(const std::string& filePath);
    std::vector<CodeSymbol> GetSymbolsInScope(const std::string& scope);
    
private:
    std::unordered_map<std::string, CodeSymbol> symbols_;
    std::unordered_map<std::string, std::vector<std::string>> references_;
    std::unordered_map<std::string, std::vector<std::string>> dependencies_;
};

// ============================================================================
// Semantic Index — Fast symbol lookup
// ============================================================================
class SemanticIndex {
public:
    void IndexSymbol(const CodeSymbol& symbol);
    void RemoveFile(const std::string& filePath);
    void Clear();
    
    // Search methods
    std::vector<CodeSymbol> SearchByName(const std::string& query, uint32_t maxResults = 10);
    std::vector<CodeSymbol> SearchByType(SymbolType type);
    std::vector<CodeSymbol> SearchInFile(const std::string& filePath);
    std::vector<CodeSymbol> SearchBySignature(const std::string& signature);
    
    // Fuzzy search
    std::vector<CodeSymbol> FuzzySearch(const std::string& query, float threshold = 0.7f);
    
    // Exact lookup
    bool FindByQualifiedName(const std::string& qualifiedName, CodeSymbol& out);
    
private:
    std::unordered_map<std::string, CodeSymbol> byQualifiedName_;
    std::unordered_map<std::string, std::vector<CodeSymbol*>> byName_;
    std::unordered_map<SymbolType, std::vector<CodeSymbol*>> byType_;
    std::unordered_map<std::string, std::vector<CodeSymbol*>> byFile_;
};

// ============================================================================
// Context Retriever — The main interface for AI context building
// ============================================================================
struct ContextResult {
    std::string contextText;        // Formatted context for prompt
    std::vector<CodeSymbol> symbols; // Source symbols
    uint32_t tokenCount = 0;         // Estimated tokens
    bool truncated = false;
};

class ContextRetriever {
public:
    // Initialize with index and graph
    void Initialize(SemanticIndex* index, SymbolGraph* graph);
    
    // Main retrieval method — gets relevant context for a query
    ContextResult RetrieveContext(
        const std::string& query,           // User query or cursor context
        const std::string& currentFile,    // Active file
        uint32_t cursorLine,                // Cursor position
        size_t maxTokens                    // Budget for context
    );
    
    // Specialized retrievals
    ContextResult RetrieveForCompletion(
        const std::string& prefix,
        const std::string& filePath,
        uint32_t line,
        size_t maxTokens
    );
    
    ContextResult RetrieveForExplanation(
        const std::string& symbolName,
        size_t maxTokens
    );
    
    ContextResult RetrieveForDebugging(
        const std::string& errorMessage,
        const std::string& filePath,
        uint32_t line,
        size_t maxTokens
    );
    
private:
    SemanticIndex* index_ = nullptr;
    SymbolGraph* graph_ = nullptr;
    
    std::vector<CodeSymbol> RankByRelevance(
        const std::vector<CodeSymbol>& symbols,
        const std::string& query,
        const std::string& currentFile
    );
    
    std::string FormatSymbolsForPrompt(
        const std::vector<CodeSymbol>& symbols,
        size_t maxTokens
    );
};

// ============================================================================
// AST Indexer — Parses source files into symbols
// ============================================================================
class ASTIndexer {
public:
    // Index a single file
    std::vector<CodeSymbol> IndexFile(const std::string& filePath);
    
    // Index entire directory
    void IndexDirectory(
        const std::string& dirPath,
        std::function<void(const std::string& file)> progress = nullptr
    );
    
    // Language detection and parsing
    bool CanIndex(const std::string& filePath);
    
    // Supported languages
    static std::vector<std::string> GetSupportedLanguages();
    
private:
    std::vector<CodeSymbol> ParseCpp(const std::string& content, const std::string& filePath);
    std::vector<CodeSymbol> ParsePython(const std::string& content, const std::string& filePath);
    std::vector<CodeSymbol> ParseJavaScript(const std::string& content, const std::string& filePath);
    std::vector<CodeSymbol> ParseRust(const std::string& content, const std::string& filePath);
    
    // Language-agnostic regex-based fallback
    std::vector<CodeSymbol> ParseGeneric(const std::string& content, const std::string& filePath);
};

// ============================================================================
// Embedding Store — Semantic similarity search (future enhancement)
// ============================================================================
struct SymbolEmbedding {
    std::string symbolName;
    std::vector<float> vector;
    uint32_t dimension = 0;
};

class EmbeddingStore {
public:
    void AddEmbedding(const SymbolEmbedding& embedding);
    
    // Find symbols semantically similar to query
    std::vector<std::string> FindSimilar(
        const std::vector<float>& queryVector,
        uint32_t topK = 5
    );
    
    // Compute cosine similarity
    static float CosineSimilarity(const std::vector<float>& a, const std::vector<float>& b);
    
private:
    std::vector<SymbolEmbedding> embeddings_;
};

// ============================================================================
// Repository Intelligence Engine — Main facade
// ============================================================================
class RepositoryIntelligence {
public:
    RepositoryIntelligence();
    ~RepositoryIntelligence();
    
    // Initialize and index repository
    bool Initialize(const std::string& repoPath);
    
    // Update index (incremental)
    void UpdateFile(const std::string& filePath);
    void RemoveFile(const std::string& filePath);
    
    // Query interface
    ContextRetriever* GetRetriever() { return &retriever_; }
    SemanticIndex* GetIndex() { return &index_; }
    SymbolGraph* GetGraph() { return &graph_; }
    
    // Status
    bool IsReady() const { return ready_; }
    std::string GetStatus() const;
    size_t GetIndexedSymbolCount() const;
    
    // Save/load index
    void SaveIndex(const std::string& path);
    bool LoadIndex(const std::string& path);
    
private:
    ASTIndexer indexer_;
    SemanticIndex index_;
    SymbolGraph graph_;
    ContextRetriever retriever_;
    std::string repoPath_;
    bool ready_ = false;
    
    void BuildIndex();
};

} // namespace RawrXD
