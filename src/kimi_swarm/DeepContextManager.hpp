// =============================================================================
// DeepContextManager.hpp — Kimi K2.6 Deep Context Reasoning (256K)
// =============================================================================
// Keeps the entire project in memory with:
//   - 256K token context window management
//   - Automatic TypeScript type consistency checking
//   - DB migration synchronization with backend
//   - On-the-fly documentation updates
//   - Cross-file dependency tracking
//   - Semantic code graph for agent navigation
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#pragma once

#include "KimiSwarmRoles.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <memory>
#include <atomic>

namespace KimiSwarm {

// =============================================================================
// CONTEXT WINDOW CONFIGURATION
// =============================================================================

struct ContextConfig {
    uint32_t maxTokens = 262144;        // 256K context window
    uint32_t reservedForSystem = 4096;  // System prompt overhead
    uint32_t reservedForOutput = 8192;  // Generation budget
    uint32_t fileSummaryBudget = 51200; // Tokens for file summaries
    uint32_t dependencyGraphBudget = 10240; // Tokens for dep graph
    uint32_t typeRegistryBudget = 10240;    // Tokens for type registry
    bool     enableTypeChecking = true;
    bool     enableDocSync = true;
    bool     enableMigrationSync = true;
};

// =============================================================================
// FILE CONTEXT ENTRY
// =============================================================================

struct FileContext {
    std::string path;
    std::string language;
    std::string content;           // Full file content (if fits)
    std::string summary;           // LLM-generated summary (if too large)
    uint32_t    tokenCount;        // Estimated token count
    uint32_t    lineCount;
    std::vector<std::string> imports;      // Imported modules
    std::vector<std::string> exports;      // Exported symbols
    std::vector<std::string> dependencies;  // Files this depends on
    std::vector<std::string> dependents;    // Files that depend on this
    bool        isTruncated;       // Content was truncated, summary used
    int64_t     lastModified;      // Unix timestamp
    std::string contentHash;       // SHA-256 of content
};

// =============================================================================
// TYPE REGISTRY — TypeScript type consistency
// =============================================================================

struct TypeDefinition {
    std::string name;              // Type name
    std::string filePath;          // Where defined
    std::string definition;        // Full type definition
    std::string kind;              // "interface", "type", "enum", "class"
    std::vector<std::string> properties;  // Property names
    std::vector<std::string> usedIn;      // Files that reference this type
    bool        isExported;
};

struct TypeInconsistency {
    std::string typeName;
    std::string fileA;
    std::string fileB;
    std::string conflictDescription;
    std::string suggestedFix;
};

// =============================================================================
// DATABASE MIGRATION TRACKING
// =============================================================================

struct MigrationEntry {
    std::string version;           // e.g. "001", "002"
    std::string filePath;
    std::string upSQL;             // Forward migration
    std::string downSQL;           // Rollback
    std::string modelFile;         // Backend model that uses this schema
    std::string tableName;
    std::vector<std::string> columns;
    bool        applied;
};

struct MigrationDrift {
    std::string tableName;
    std::string migrationFile;
    std::string modelFile;
    std::string driftDescription;  // What's out of sync
    std::string suggestedFix;
};

// =============================================================================
// DOCUMENTATION SYNC
// =============================================================================

struct DocEntry {
    std::string docPath;           // e.g. "docs/api.md"
    std::string sourcePath;        // Source file it documents
    std::string content;
    std::string contentHash;
    int64_t     lastSynced;        // When doc was last updated
    bool        isStale;           // Source changed since last sync
};

// =============================================================================
// SEMANTIC CODE GRAPH
// =============================================================================

struct CodeGraphNode {
    std::string id;                // Unique node ID (file path + symbol)
    std::string filePath;
    std::string symbolName;
    std::string symbolKind;        // "function", "class", "variable", "type"
    std::string signature;         // Function/type signature
    uint32_t    lineStart;
    uint32_t    lineEnd;
};

struct CodeGraphEdge {
    std::string fromNode;
    std::string toNode;
    std::string edgeType;          // "calls", "imports", "implements", "extends"
};

struct SemanticCodeGraph {
    std::unordered_map<std::string, CodeGraphNode> nodes;
    std::vector<CodeGraphEdge> edges;
    std::unordered_map<std::string, std::vector<std::string>> adjacency; // node → neighbors
};

// =============================================================================
// CONTEXT BUDGET TRACKER
// =============================================================================

struct ContextBudget {
    uint32_t totalBudget;
    uint32_t systemPrompt;
    uint32_t fileSummaries;
    uint32_t dependencyGraph;
    uint32_t typeRegistry;
    uint32_t output;
    uint32_t used;
    uint32_t remaining;

    float utilization() const {
        if (totalBudget == 0) return 0.0f;
        return static_cast<float>(used) / static_cast<float>(totalBudget);
    }
};

// =============================================================================
// DEEP CONTEXT MANAGER
// =============================================================================

class DeepContextManager {
public:
    explicit DeepContextManager(const ContextConfig& config = ContextConfig{});

    // ---- File Management ----
    void addFile(const std::string& path, const std::string& content,
                 const std::string& language);
    void updateFile(const std::string& path, const std::string& content);
    void removeFile(const std::string& path);
    const FileContext* getFile(const std::string& path) const;
    std::vector<std::string> getAllFiles() const;

    // ---- Context Window Construction ----
    // Build a context string that fits within the token budget
    std::string buildContextForAgent(KimiRole role,
                                      const std::string& focusFile = "",
                                      const std::vector<std::string>& relatedFiles = {});

    // Get current budget utilization
    ContextBudget getBudget() const;

    // ---- Type Consistency ----
    void registerType(const TypeDefinition& type);
    std::vector<TypeInconsistency> detectTypeInconsistencies() const;
    std::vector<TypeDefinition> getTypesForFile(const std::string& filePath) const;
    std::vector<TypeDefinition> getAllTypes() const;

    // ---- Migration Sync ----
    void registerMigration(const MigrationEntry& migration);
    std::vector<MigrationDrift> detectMigrationDrift() const;
    std::vector<MigrationEntry> getMigrations() const;

    // ---- Documentation Sync ----
    void registerDoc(const DocEntry& doc);
    std::vector<DocEntry> getStaleDocs() const;
    void markDocSynced(const std::string& docPath);
    std::vector<DocEntry> getAllDocs() const;

    // ---- Semantic Code Graph ----
    void buildCodeGraph();
    const SemanticCodeGraph& getCodeGraph() const;
    std::vector<std::string> getRelatedFiles(const std::string& filePath,
                                              uint32_t maxDepth = 2) const;
    std::vector<CodeGraphNode> getSymbolsInFile(const std::string& filePath) const;
    std::vector<CodeGraphNode> getCallers(const std::string& symbolName) const;
    std::vector<CodeGraphNode> getCallees(const std::string& symbolName) const;

    // ---- Token Estimation ----
    uint32_t estimateTokens(const std::string& text) const;
    uint32_t getTotalProjectTokens() const;

    // ---- Project Summary ----
    std::string getProjectSummary() const;
    std::string getDependencyTree() const;
    std::string getTypeRegistrySummary() const;

    // ---- Configuration ----
    void setConfig(const ContextConfig& config);
    const ContextConfig& getConfig() const { return config_; }

    // ---- Statistics ----
    size_t fileCount() const;
    size_t typeCount() const;
    size_t migrationCount() const;
    size_t docCount() const;
    size_t graphNodeCount() const;
    size_t graphEdgeCount() const;

private:
    ContextConfig config_;
    mutable std::mutex mutex_;

    std::unordered_map<std::string, FileContext> files_;
    std::unordered_map<std::string, TypeDefinition> typeRegistry_;
    std::unordered_map<std::string, std::vector<TypeDefinition>> typesByFile_;
    std::vector<MigrationEntry> migrations_;
    std::unordered_map<std::string, DocEntry> docs_;
    SemanticCodeGraph codeGraph_;

    std::atomic<uint32_t> totalTokens_{0};

    // Internal helpers
    std::string summarizeFile(const FileContext& fc) const;
    void updateDependencies(const std::string& path,
                            const std::vector<std::string>& imports);
    void rebuildAdjacency();
    std::string truncateToFit(const std::string& content, uint32_t maxTokens) const;
    std::string computeHash(const std::string& content) const;
};

} // namespace KimiSwarm