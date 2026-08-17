// =============================================================================
// DeepContextManager.cpp — Kimi K2.6 Deep Context Reasoning Implementation
// =============================================================================
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#include "DeepContextManager.hpp"
#include <algorithm>
#include <sstream>
#include <chrono>
#include <functional>

namespace KimiSwarm {

// =============================================================================
// CONSTRUCTION
// =============================================================================

DeepContextManager::DeepContextManager(const ContextConfig& config)
    : config_(config) {}

void DeepContextManager::setConfig(const ContextConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
}

// =============================================================================
// FILE MANAGEMENT
// =============================================================================

void DeepContextManager::addFile(const std::string& path, const std::string& content,
                                   const std::string& language) {
    std::lock_guard<std::mutex> lock(mutex_);

    FileContext fc;
    fc.path = path;
    fc.language = language;
    fc.content = content;
    fc.tokenCount = estimateTokens(content);
    fc.lineCount = static_cast<uint32_t>(std::count(content.begin(), content.end(), '\n') + 1);
    fc.isTruncated = false;
    fc.lastModified = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    fc.contentHash = computeHash(content);

    // Extract imports (simplified — real implementation would use lexer)
    std::istringstream iss(content);
    std::string line;
    while (std::getline(iss, line)) {
        std::string trimmed = line;
        // Trim whitespace
        size_t start = trimmed.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        trimmed = trimmed.substr(start);

        // Detect import statements
        if (trimmed.substr(0, 7) == "import " || trimmed.substr(0, 5) == "#incl" ||
            trimmed.substr(0, 5) == "from " || trimmed.substr(0, 7) == "require") {
            fc.imports.push_back(trimmed);
        }
        // Detect exports
        if (trimmed.substr(0, 7) == "export " || trimmed.substr(0, 7) == "public " ||
            trimmed.substr(0, 8) == "module.e") {
            fc.exports.push_back(trimmed);
        }
    }

    files_[path] = fc;
    totalTokens_ += fc.tokenCount;
}

void DeepContextManager::updateFile(const std::string& path, const std::string& content) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = files_.find(path);
    if (it == files_.end()) {
        // Determine language from extension
        std::string lang = "text";
        auto pos = path.rfind('.');
        if (pos != std::string::npos) {
            std::string ext = path.substr(pos + 1);
            if (ext == "ts" || ext == "tsx") lang = "typescript";
            else if (ext == "js" || ext == "jsx") lang = "javascript";
            else if (ext == "py") lang = "python";
            else if (ext == "go") lang = "go";
            else if (ext == "rs") lang = "rust";
            else if (ext == "cpp" || ext == "cc" || ext == "cxx") lang = "cpp";
            else if (ext == "h" || ext == "hpp") lang = "cpp";
            else if (ext == "c") lang = "c";
            else if (ext == "asm") lang = "asm";
            else if (ext == "sql") lang = "sql";
            else if (ext == "css") lang = "css";
            else if (ext == "html") lang = "html";
            else if (ext == "json") lang = "json";
            else if (ext == "md") lang = "markdown";
        }
        mutex_.unlock();
        addFile(path, content, lang);
        return;
    }

    // Update existing
    totalTokens_ -= it->second.tokenCount;
    it->second.content = content;
    it->second.tokenCount = estimateTokens(content);
    it->second.lineCount = static_cast<uint32_t>(std::count(content.begin(), content.end(), '\n') + 1);
    it->second.lastModified = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    it->second.contentHash = computeHash(content);
    totalTokens_ += it->second.tokenCount;

    // Mark related docs as stale
    for (auto& [docPath, doc] : docs_) {
        if (doc.sourcePath == path) {
            doc.isStale = true;
        }
    }
}

void DeepContextManager::removeFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = files_.find(path);
    if (it != files_.end()) {
        totalTokens_ -= it->second.tokenCount;
        files_.erase(it);
    }
    // Remove from type registry
    auto typeIt = typesByFile_.find(path);
    if (typeIt != typesByFile_.end()) {
        for (const auto& type : typeIt->second) {
            typeRegistry_.erase(type.name);
        }
        typesByFile_.erase(typeIt);
    }
}

const FileContext* DeepContextManager::getFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = files_.find(path);
    if (it != files_.end()) return &it->second;
    return nullptr;
}

std::vector<std::string> DeepContextManager::getAllFiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    result.reserve(files_.size());
    for (const auto& [path, _] : files_) {
        result.push_back(path);
    }
    std::sort(result.begin(), result.end());
    return result;
}

// =============================================================================
// CONTEXT WINDOW CONSTRUCTION
// =============================================================================

std::string DeepContextManager::buildContextForAgent(KimiRole role,
                                                       const std::string& focusFile,
                                                       const std::vector<std::string>& relatedFiles) {
    std::lock_guard<std::mutex> lock(mutex_);

    uint32_t budget = config_.maxTokens - config_.reservedForSystem - config_.reservedForOutput;
    uint32_t used = 0;
    std::ostringstream ctx;

    // 1. Project summary
    std::string summary = getProjectSummary();
    uint32_t summaryTokens = estimateTokens(summary);
    if (used + summaryTokens < budget) {
        ctx << "=== PROJECT CONTEXT ===\n" << summary << "\n\n";
        used += summaryTokens;
    }

    // 2. Type registry summary (for type consistency)
    if (config_.enableTypeChecking) {
        std::string typeSummary = getTypeRegistrySummary();
        uint32_t typeTokens = estimateTokens(typeSummary);
        if (typeTokens > config_.typeRegistryBudget) {
            typeSummary = truncateToFit(typeSummary, config_.typeRegistryBudget);
            typeTokens = estimateTokens(typeSummary);
        }
        if (used + typeTokens < budget) {
            ctx << "=== TYPE REGISTRY ===\n" << typeSummary << "\n\n";
            used += typeTokens;
        }
    }

    // 3. Dependency tree (abbreviated)
    std::string depTree = getDependencyTree();
    uint32_t depTokens = estimateTokens(depTree);
    if (depTokens > config_.dependencyGraphBudget) {
        depTree = truncateToFit(depTree, config_.dependencyGraphBudget);
        depTokens = estimateTokens(depTree);
    }
    if (used + depTokens < budget) {
        ctx << "=== DEPENDENCY GRAPH ===\n" << depTree << "\n\n";
        used += depTokens;
    }

    // 4. Focus file (full content if it fits)
    if (!focusFile.empty()) {
        auto it = files_.find(focusFile);
        if (it != files_.end()) {
            std::string fileContent = it->second.content;
            uint32_t fileTokens = it->second.tokenCount;
            if (used + fileTokens < budget) {
                ctx << "=== FOCUS FILE: " << focusFile << " ===\n"
                    << fileContent << "\n\n";
                used += fileTokens;
            } else {
                // Use summary instead
                std::string fileSummary = summarizeFile(it->second);
                uint32_t sumTokens = estimateTokens(fileSummary);
                if (used + sumTokens < budget) {
                    ctx << "=== FOCUS FILE SUMMARY: " << focusFile << " ===\n"
                        << fileSummary << "\n\n";
                    used += sumTokens;
                }
            }
        }
    }

    // 5. Related files (summaries)
    for (const auto& relPath : relatedFiles) {
        if (relPath == focusFile) continue;
        auto it = files_.find(relPath);
        if (it == files_.end()) continue;
        std::string relSummary = summarizeFile(it->second);
        uint32_t relTokens = estimateTokens(relSummary);
        if (used + relTokens < budget) {
            ctx << "=== RELATED: " << relPath << " ===\n"
                << relSummary << "\n\n";
            used += relTokens;
        }
    }

    // 6. Auto-discover related files if not specified
    if (relatedFiles.empty() && !focusFile.empty()) {
        auto related = getRelatedFiles(focusFile, 1);
        for (const auto& relPath : related) {
            if (relPath == focusFile) continue;
            auto it = files_.find(relPath);
            if (it == files_.end()) continue;
            std::string relSummary = summarizeFile(it->second);
            uint32_t relTokens = estimateTokens(relSummary);
            if (used + relTokens < budget) {
                ctx << "=== AUTO-RELATED: " << relPath << " ===\n"
                    << relSummary << "\n\n";
                used += relTokens;
            }
        }
    }

    // 7. Migration drift warnings
    if (config_.enableMigrationSync) {
        auto drifts = detectMigrationDrift();
        if (!drifts.empty()) {
            ctx << "=== MIGRATION DRIFT WARNINGS ===\n";
            for (const auto& d : drifts) {
                ctx << "  - " << d.tableName << ": " << d.driftDescription << "\n";
            }
            ctx << "\n";
        }
    }

    // 8. Stale documentation warnings
    if (config_.enableDocSync) {
        auto staleDocs = getStaleDocs();
        if (!staleDocs.empty()) {
            ctx << "=== STALE DOCUMENTATION ===\n";
            for (const auto& d : staleDocs) {
                ctx << "  - " << d.docPath << " (source: " << d.sourcePath << ")\n";
            }
            ctx << "\n";
        }
    }

    return ctx.str();
}

ContextBudget DeepContextManager::getBudget() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ContextBudget budget;
    budget.totalBudget = config_.maxTokens;
    budget.systemPrompt = config_.reservedForSystem;
    budget.fileSummaries = config_.fileSummaryBudget;
    budget.dependencyGraph = config_.dependencyGraphBudget;
    budget.typeRegistry = config_.typeRegistryBudget;
    budget.output = config_.reservedForOutput;
    budget.used = totalTokens_.load();
    budget.remaining = (budget.used > budget.totalBudget) ? 0 : (budget.totalBudget - budget.used);
    return budget;
}

// =============================================================================
// TYPE CONSISTENCY
// =============================================================================

void DeepContextManager::registerType(const TypeDefinition& type) {
    std::lock_guard<std::mutex> lock(mutex_);
    typeRegistry_[type.name] = type;
    typesByFile_[type.filePath].push_back(type);
}

std::vector<TypeInconsistency> DeepContextManager::detectTypeInconsistencies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TypeInconsistency> inconsistencies;

    // Check for duplicate type names with different definitions
    std::unordered_map<std::string, std::vector<const TypeDefinition*>> byName;
    for (const auto& [name, type] : typeRegistry_) {
        byName[name].push_back(&type);
    }

    for (const auto& [name, defs] : byName) {
        if (defs.size() > 1) {
            // Check if definitions differ
            for (size_t i = 0; i < defs.size(); ++i) {
                for (size_t j = i + 1; j < defs.size(); ++j) {
                    if (defs[i]->definition != defs[j]->definition) {
                        TypeInconsistency inc;
                        inc.typeName = name;
                        inc.fileA = defs[i]->filePath;
                        inc.fileB = defs[j]->filePath;
                        inc.conflictDescription = "Type '" + name +
                            "' has different definitions in " + defs[i]->filePath +
                            " and " + defs[j]->filePath;
                        inc.suggestedFix = "Unify the type definition and export from a single source";
                        inconsistencies.push_back(inc);
                    }
                }
            }
        }
    }

    return inconsistencies;
}

std::vector<TypeDefinition> DeepContextManager::getTypesForFile(const std::string& filePath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = typesByFile_.find(filePath);
    if (it != typesByFile_.end()) return it->second;
    return {};
}

std::vector<TypeDefinition> DeepContextManager::getAllTypes() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TypeDefinition> result;
    result.reserve(typeRegistry_.size());
    for (const auto& [_, type] : typeRegistry_) {
        result.push_back(type);
    }
    return result;
}

// =============================================================================
// MIGRATION SYNC
// =============================================================================

void DeepContextManager::registerMigration(const MigrationEntry& migration) {
    std::lock_guard<std::mutex> lock(mutex_);
    migrations_.push_back(migration);
}

std::vector<MigrationDrift> DeepContextManager::detectMigrationDrift() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<MigrationDrift> drifts;

    // Check if model files reference tables/columns not in migrations
    for (const auto& migration : migrations_) {
        if (migration.modelFile.empty()) continue;
        auto modelIt = files_.find(migration.modelFile);
        if (modelIt == files_.end()) continue;

        // Check if model references columns not in migration
        for (const auto& col : migration.columns) {
            if (modelIt->second.content.find(col) == std::string::npos) {
                MigrationDrift drift;
                drift.tableName = migration.tableName;
                drift.migrationFile = migration.filePath;
                drift.modelFile = migration.modelFile;
                drift.driftDescription = "Column '" + col + "' in migration but not referenced in model";
                drift.suggestedFix = "Update model to include column '" + col + "' or remove from migration";
                drifts.push_back(drift);
            }
        }
    }

    return drifts;
}

std::vector<MigrationEntry> DeepContextManager::getMigrations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return migrations_;
}

// =============================================================================
// DOCUMENTATION SYNC
// =============================================================================

void DeepContextManager::registerDoc(const DocEntry& doc) {
    std::lock_guard<std::mutex> lock(mutex_);
    docs_[doc.docPath] = doc;
}

std::vector<DocEntry> DeepContextManager::getStaleDocs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DocEntry> stale;
    for (const auto& [_, doc] : docs_) {
        if (doc.isStale) stale.push_back(doc);
    }
    return stale;
}

void DeepContextManager::markDocSynced(const std::string& docPath) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = docs_.find(docPath);
    if (it != docs_.end()) {
        it->second.isStale = false;
        it->second.lastSynced = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
}

std::vector<DocEntry> DeepContextManager::getAllDocs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DocEntry> result;
    result.reserve(docs_.size());
    for (const auto& [_, doc] : docs_) {
        result.push_back(doc);
    }
    return result;
}

// =============================================================================
// SEMANTIC CODE GRAPH
// =============================================================================

void DeepContextManager::buildCodeGraph() {
    std::lock_guard<std::mutex> lock(mutex_);
    codeGraph_.nodes.clear();
    codeGraph_.edges.clear();
    codeGraph_.adjacency.clear();

    // Build nodes from file exports
    for (const auto& [path, fc] : files_) {
        for (const auto& exportLine : fc.exports) {
            CodeGraphNode node;
            node.id = path + "::" + exportLine;
            node.filePath = path;
            node.symbolName = exportLine;
            node.symbolKind = "export";
            node.signature = exportLine;
            codeGraph_.nodes[node.id] = node;
        }
    }

    // Build edges from imports
    for (const auto& [path, fc] : files_) {
        for (const auto& importLine : fc.imports) {
            CodeGraphEdge edge;
            edge.fromNode = path;
            edge.toNode = importLine;
            edge.edgeType = "imports";
            codeGraph_.edges.push_back(edge);
            codeGraph_.adjacency[path].push_back(importLine);
        }
    }

    rebuildAdjacency();
}

const SemanticCodeGraph& DeepContextManager::getCodeGraph() const {
    // Note: caller should ensure buildCodeGraph() was called
    std::lock_guard<std::mutex> lock(mutex_);
    return codeGraph_;
}

std::vector<std::string> DeepContextManager::getRelatedFiles(const std::string& filePath,
                                                               uint32_t maxDepth) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> related;
    std::unordered_set<std::string> visited;
    std::vector<std::pair<std::string, uint32_t>> queue;
    queue.push_back({filePath, 0});
    visited.insert(filePath);

    while (!queue.empty()) {
        auto [current, depth] = queue.front();
        queue.erase(queue.begin());
        if (depth >= maxDepth) continue;

        auto adjIt = codeGraph_.adjacency.find(current);
        if (adjIt != codeGraph_.adjacency.end()) {
            for (const auto& neighbor : adjIt->second) {
                if (visited.find(neighbor) == visited.end()) {
                    visited.insert(neighbor);
                    related.push_back(neighbor);
                    queue.push_back({neighbor, depth + 1});
                }
            }
        }

        // Also check reverse dependencies
        for (const auto& [node, neighbors] : codeGraph_.adjacency) {
            if (std::find(neighbors.begin(), neighbors.end(), current) != neighbors.end()) {
                if (visited.find(node) == visited.end()) {
                    visited.insert(node);
                    related.push_back(node);
                    queue.push_back({node, depth + 1});
                }
            }
        }
    }

    return related;
}

std::vector<CodeGraphNode> DeepContextManager::getSymbolsInFile(const std::string& filePath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CodeGraphNode> result;
    for (const auto& [id, node] : codeGraph_.nodes) {
        if (node.filePath == filePath) result.push_back(node);
    }
    return result;
}

std::vector<CodeGraphNode> DeepContextManager::getCallers(const std::string& symbolName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CodeGraphNode> result;
    for (const auto& edge : codeGraph_.edges) {
        if (edge.toNode.find(symbolName) != std::string::npos) {
            auto it = codeGraph_.nodes.find(edge.fromNode);
            if (it != codeGraph_.nodes.end()) {
                result.push_back(it->second);
            }
        }
    }
    return result;
}

std::vector<CodeGraphNode> DeepContextManager::getCallees(const std::string& symbolName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<CodeGraphNode> result;
    for (const auto& edge : codeGraph_.edges) {
        if (edge.fromNode.find(symbolName) != std::string::npos) {
            auto it = codeGraph_.nodes.find(edge.toNode);
            if (it != codeGraph_.nodes.end()) {
                result.push_back(it->second);
            }
        }
    }
    return result;
}

// =============================================================================
// TOKEN ESTIMATION
// =============================================================================

uint32_t DeepContextManager::estimateTokens(const std::string& text) const {
    // Rough estimate: ~4 characters per token for English/code
    return static_cast<uint32_t>(text.size() / 4);
}

uint32_t DeepContextManager::getTotalProjectTokens() const {
    return totalTokens_.load();
}

// =============================================================================
// PROJECT SUMMARY
// =============================================================================

std::string DeepContextManager::getProjectSummary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream summary;
    summary << "Files: " << files_.size() << "\n"
            << "Total tokens: " << totalTokens_.load() << "\n"
            << "Types registered: " << typeRegistry_.size() << "\n"
            << "Migrations: " << migrations_.size() << "\n"
            << "Documentation entries: " << docs_.size() << "\n"
            << "Code graph nodes: " << codeGraph_.nodes.size() << "\n"
            << "Code graph edges: " << codeGraph_.edges.size() << "\n\n"
            << "File list:\n";
    for (const auto& [path, fc] : files_) {
        summary << "  " << path << " (" << fc.tokenCount << " tokens, "
                << fc.lineCount << " lines, " << fc.language << ")\n";
    }
    return summary.str();
}

std::string DeepContextManager::getDependencyTree() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream tree;
    for (const auto& [path, fc] : files_) {
        if (fc.dependencies.empty() && fc.dependents.empty()) continue;
        tree << path << ":\n";
        if (!fc.dependencies.empty()) {
            tree << "  depends on:\n";
            for (const auto& dep : fc.dependencies) {
                tree << "    -> " << dep << "\n";
            }
        }
        if (!fc.dependents.empty()) {
            tree << "  depended by:\n";
            for (const auto& dep : fc.dependents) {
                tree << "    <- " << dep << "\n";
            }
        }
    }
    return tree.str();
}

std::string DeepContextManager::getTypeRegistrySummary() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream summary;
    for (const auto& [name, type] : typeRegistry_) {
        summary << "  " << name << " (" << type.kind << ") in " << type.filePath;
        if (type.isExported) summary << " [exported]";
        summary << "\n";
    }
    return summary.str();
}

// =============================================================================
// STATISTICS
// =============================================================================

size_t DeepContextManager::fileCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return files_.size();
}

size_t DeepContextManager::typeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return typeRegistry_.size();
}

size_t DeepContextManager::migrationCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return migrations_.size();
}

size_t DeepContextManager::docCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return docs_.size();
}

size_t DeepContextManager::graphNodeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return codeGraph_.nodes.size();
}

size_t DeepContextManager::graphEdgeCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return codeGraph_.edges.size();
}

// =============================================================================
// INTERNAL HELPERS
// =============================================================================

std::string DeepContextManager::summarizeFile(const FileContext& fc) const {
    if (fc.tokenCount < 500) {
        return fc.content;  // Small enough to include fully
    }
    // Generate a summary: first 20 lines + last 10 lines + export list
    std::istringstream iss(fc.content);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(iss, line)) {
        lines.push_back(line);
    }

    std::ostringstream summary;
    summary << "File: " << fc.path << " (" << fc.lineCount << " lines, "
            << fc.tokenCount << " tokens)\n";
    summary << "Language: " << fc.language << "\n";
    summary << "Hash: " << fc.contentHash << "\n\n";

    if (!fc.exports.empty()) {
        summary << "Exports:\n";
        for (const auto& e : fc.exports) {
            summary << "  " << e << "\n";
        }
        summary << "\n";
    }

    if (!fc.imports.empty()) {
        summary << "Imports:\n";
        for (const auto& i : fc.imports) {
            summary << "  " << i << "\n";
        }
        summary << "\n";
    }

    // First 20 lines
    uint32_t headLines = std::min(static_cast<uint32_t>(20), static_cast<uint32_t>(lines.size()));
    summary << "--- First " << headLines << " lines ---\n";
    for (uint32_t i = 0; i < headLines; ++i) {
        summary << lines[i] << "\n";
    }

    if (lines.size() > 30) {
        summary << "... (" << (lines.size() - 30) << " lines omitted) ...\n";
        summary << "--- Last 10 lines ---\n";
        uint32_t tailStart = static_cast<uint32_t>(lines.size()) - 10;
        for (uint32_t i = tailStart; i < lines.size(); ++i) {
            summary << lines[i] << "\n";
        }
    }

    return summary.str();
}

void DeepContextManager::updateDependencies(const std::string& path,
                                             const std::vector<std::string>& imports) {
    auto it = files_.find(path);
    if (it == files_.end()) return;

    it->second.imports = imports;
    it->second.dependencies.clear();
    for (const auto& imp : imports) {
        // Try to resolve import to a file path
        for (const auto& [otherPath, _] : files_) {
            if (otherPath.find(imp) != std::string::npos || imp.find(otherPath) != std::string::npos) {
                it->second.dependencies.push_back(otherPath);
                files_[otherPath].dependents.push_back(path);
            }
        }
    }
}

void DeepContextManager::rebuildAdjacency() {
    codeGraph_.adjacency.clear();
    for (const auto& edge : codeGraph_.edges) {
        codeGraph_.adjacency[edge.fromNode].push_back(edge.toNode);
    }
}

std::string DeepContextManager::truncateToFit(const std::string& content, uint32_t maxTokens) const {
    uint32_t maxChars = maxTokens * 4;
    if (content.size() <= maxChars) return content;
    return content.substr(0, maxChars) + "\n... [truncated to fit context budget] ...";
}

std::string DeepContextManager::computeHash(const std::string& content) const {
    // Simple FNV-1a hash for content identification
    uint64_t hash = 14695981039346656037ULL;
    for (char c : content) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    std::ostringstream hex;
    hex << std::hex << hash;
    return hex.str();
}

} // namespace KimiSwarm