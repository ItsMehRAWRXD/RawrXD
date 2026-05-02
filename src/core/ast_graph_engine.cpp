// ============================================================================
// ast_graph_engine.cpp — Persistent Incremental AST Graph Implementation
// ============================================================================

#include "ast_graph_engine.h"
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace AST {

// ============================================================================
// ASTGraphEngine Implementation
// ============================================================================

ASTGraphEngine::ASTGraphEngine() = default;
ASTGraphEngine::~ASTGraphEngine() { shutdown(); }

bool ASTGraphEngine::initialize() {
    m_nextNodeID.store(1);
    m_nextFileID.store(1);
    m_currentVersion.store(1);
    return true;
}

void ASTGraphEngine::shutdown() {
    std::unique_lock<std::shared_mutex> lock(m_nodeMutex);
    m_nodes.clear();
    
    std::unique_lock<std::shared_mutex> fileLock(m_fileMutex);
    m_files.clear();
    m_pathToFileID.clear();
}

uint32_t ASTGraphEngine::registerFile(const std::string& path, const std::string& content) {
    std::unique_lock<std::shared_mutex> lock(m_fileMutex);
    
    // Check if already registered
    auto it = m_pathToFileID.find(path);
    if (it != m_pathToFileID.end()) {
        return it->second;
    }
    
    uint32_t fileID = allocateFileID();
    FileInfo info;
    info.path = path;
    info.content = content;
    info.rootNode = INVALID_NODE_ID;
    info.lastParsedVersion = 0;
    info.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    m_files[fileID] = std::move(info);
    m_pathToFileID[path] = fileID;
    
    // Trigger initial parse
    lock.unlock();
    updateFile(fileID, content);
    
    return fileID;
}

GraphDiff ASTGraphEngine::updateFile(uint32_t fileID, const std::string& newContent) {
    std::shared_lock<std::shared_mutex> lock(m_fileMutex);
    auto it = m_files.find(fileID);
    if (it == m_files.end()) {
        return GraphDiff{};
    }
    
    FileInfo oldFile = it->second; // Copy
    lock.unlock();
    
    // Compute diff
    GraphDiff diff = computeDiff(oldFile, FileInfo{oldFile.path, newContent, 
        oldFile.rootNode, oldFile.lastParsedVersion, oldFile.lastModified});
    
    // Apply diff
    applyDiff(diff);
    
    // Update file info
    std::unique_lock<std::shared_mutex> writeLock(m_fileMutex);
    auto& file = m_files[fileID];
    file.content = newContent;
    file.lastModified = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    file.lastParsedVersion = diff.toVersion;
    
    m_incrementalUpdates++;
    
    return diff;
}

void ASTGraphEngine::unregisterFile(uint32_t fileID) {
    std::unique_lock<std::shared_mutex> lock(m_fileMutex);
    auto it = m_files.find(fileID);
    if (it == m_files.end()) return;
    
    // Remove all nodes for this file
    NodeID root = it->second.rootNode;
    m_pathToFileID.erase(it->second.path);
    m_files.erase(it);
    lock.unlock();
    
    // Clean up nodes (simplified - would traverse and remove subtree)
    std::unique_lock<std::shared_mutex> nodeLock(m_nodeMutex);
    // In real implementation: traverse from root and remove all descendants
}

const ASTNode* ASTGraphEngine::getNode(NodeID id) const {
    std::shared_lock<std::shared_mutex> lock(m_nodeMutex);
    auto it = m_nodes.find(id);
    if (it == m_nodes.end()) return nullptr;
    return it->second.get();
}

NodeID ASTGraphEngine::findNodeAt(uint32_t fileID, uint32_t line, uint32_t column) const {
    std::shared_lock<std::shared_mutex> lock(m_fileMutex);
    auto it = m_files.find(fileID);
    if (it == m_files.end()) return INVALID_NODE_ID;
    
    NodeID root = it->second.rootNode;
    lock.unlock();
    
    // Traverse to find deepest node containing position
    const ASTNode* current = getNode(root);
    if (!current) return INVALID_NODE_ID;
    
    NodeID result = root;
    bool foundChild = true;
    
    while (foundChild) {
        foundChild = false;
        for (NodeID childID : current->children) {
            const ASTNode* child = getNode(childID);
            if (!child) continue;
            
            if (child->location.line <= line && 
                child->location.line + child->location.length >= line) {
                result = childID;
                current = child;
                foundChild = true;
                break;
            }
        }
    }
    
    return result;
}

NodeID ASTGraphEngine::getFileRoot(uint32_t fileID) const {
    std::shared_lock<std::shared_mutex> lock(m_fileMutex);
    auto it = m_files.find(fileID);
    if (it == m_files.end()) return INVALID_NODE_ID;
    return it->second.rootNode;
}

NodeID ASTGraphEngine::getEnclosingScope(NodeID nodeID) const {
    const ASTNode* node = getNode(nodeID);
    if (!node) return INVALID_NODE_ID;
    
    // Walk up parent chain looking for scope node
    NodeID current = node->parent;
    while (current != INVALID_NODE_ID) {
        const ASTNode* parent = getNode(current);
        if (!parent) break;
        
        // Scope nodes: Namespace, Class, Function, Block
        if (parent->type == NodeType::Namespace ||
            parent->type == NodeType::Class ||
            parent->type == NodeType::Function ||
            parent->type == NodeType::Block) {
            return current;
        }
        current = parent->parent;
    }
    
    return INVALID_NODE_ID;
}

NodeID ASTGraphEngine::resolveSymbol(const std::string& symbol, NodeID scopeNode) const {
    // Walk up scope chain looking for symbol definition
    NodeID currentScope = scopeNode;
    while (currentScope != INVALID_NODE_ID) {
        const ASTNode* scope = getNode(currentScope);
        if (!scope) break;
        
        // Look for symbol in this scope
        for (NodeID childID : scope->children) {
            const ASTNode* child = getNode(childID);
            if (!child) continue;
            
            if (child->symbol == symbol) {
                return childID;
            }
        }
        
        currentScope = scope->scope;
    }
    
    return INVALID_NODE_ID;
}

std::vector<NodeID> ASTGraphEngine::getReferences(NodeID definitionNode) const {
    std::vector<NodeID> refs;
    
    const ASTNode* def = getNode(definitionNode);
    if (!def || def->symbol.empty()) return refs;
    
    // In real implementation: use reverse index
    // For now: scan all nodes (inefficient but functional)
    std::shared_lock<std::shared_mutex> lock(m_nodeMutex);
    for (const auto& [id, node] : m_nodes) {
        for (NodeID ref : node->references) {
            if (ref == definitionNode) {
                refs.push_back(id);
                break;
            }
        }
    }
    
    return refs;
}

void ASTGraphEngine::traverse(NodeID root, std::function<void(const ASTNode&)> visitor) const {
    const ASTNode* node = getNode(root);
    if (!node) return;
    
    visitor(*node);
    
    for (NodeID childID : node->children) {
        traverse(childID, visitor);
    }
}

std::vector<NodeID> ASTGraphEngine::findNodes(NodeID root, 
                                               std::function<bool(const ASTNode&)> predicate) const {
    std::vector<NodeID> results;
    
    traverse(root, [&](const ASTNode& node) {
        if (predicate(node)) {
            results.push_back(node.id);
        }
    });
    
    return results;
}

std::vector<NodeID> ASTGraphEngine::getPathToRoot(NodeID nodeID) const {
    std::vector<NodeID> path;
    
    NodeID current = nodeID;
    while (current != INVALID_NODE_ID) {
        path.push_back(current);
        const ASTNode* node = getNode(current);
        if (!node) break;
        current = node->parent;
    }
    
    return path;
}

void ASTGraphEngine::applyDiff(const GraphDiff& diff) {
    std::unique_lock<std::mutex> versionLock(m_versionMutex);
    m_versionDiffs[diff.toVersion] = diff;
    m_currentVersion.store(diff.toVersion);
    versionLock.unlock();
    
    // Remove deleted nodes
    std::unique_lock<std::shared_mutex> nodeLock(m_nodeMutex);
    for (NodeID id : diff.deletedNodes) {
        m_nodes.erase(id);
    }
    
    // Invalidate completion cache
    invalidateCompletionCache(diff);
}

GraphDiff ASTGraphEngine::getDiff(GraphVersion from, GraphVersion to) const {
    std::shared_lock<std::mutex> lock(m_versionMutex);
    
    GraphDiff diff;
    diff.fromVersion = from;
    diff.toVersion = to;
    
    // Aggregate diffs between versions
    for (GraphVersion v = from + 1; v <= to; ++v) {
        auto it = m_versionDiffs.find(v);
        if (it != m_versionDiffs.end()) {
            diff.addedNodes.insert(diff.addedNodes.end(), 
                                   it->second.addedNodes.begin(),
                                   it->second.addedNodes.end());
            diff.modifiedNodes.insert(diff.modifiedNodes.end(),
                                      it->second.modifiedNodes.begin(),
                                      it->second.modifiedNodes.end());
            diff.deletedNodes.insert(diff.deletedNodes.end(),
                                     it->second.deletedNodes.begin(),
                                     it->second.deletedNodes.end());
        }
    }
    
    return diff;
}

ContextFingerprint ASTGraphEngine::buildFingerprint(uint32_t fileID, uint32_t line, 
                                                       uint32_t column, const std::string& partial) {
    ContextFingerprint fp;
    fp.cursorNode = findNodeAt(fileID, line, column);
    fp.scopeNode = getEnclosingScope(fp.cursorNode);
    fp.partialSymbol = partial;
    
    // Build surrounding hash from context nodes
    uint64_t hash = 0;
    std::vector<NodeID> path = getPathToRoot(fp.cursorNode);
    for (size_t i = 0; i < std::min(path.size(), size_t(5)); ++i) {
        const ASTNode* node = getNode(path[i]);
        if (node) {
            hash = hash * 31 + std::hash<std::string>{}(node->text);
        }
    }
    fp.surroundingHash = hash;
    
    return fp;
}

void ASTGraphEngine::cacheCompletions(const ContextFingerprint& fingerprint, 
                                      const std::vector<std::string>& completions) {
    std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
    
    CompletionCacheEntry entry;
    entry.fingerprint = fingerprint;
    entry.completions = completions;
    entry.timestamp = m_cacheTimestamp++;
    entry.hitCount = 0;
    
    m_completionCache[fingerprint] = std::move(entry);
}

const std::vector<std::string>* ASTGraphEngine::getCachedCompletions(
    const ContextFingerprint& fingerprint) {
    std::shared_lock<std::shared_mutex> lock(m_cacheMutex);
    
    auto it = m_completionCache.find(fingerprint);
    if (it == m_completionCache.end()) {
        m_cacheMisses++;
        return nullptr;
    }
    
    it->second.hitCount++;
    m_cacheHits++;
    return &it->second.completions;
}

void ASTGraphEngine::invalidateCompletionCache(const GraphDiff& diff) {
    std::unique_lock<std::shared_mutex> lock(m_cacheMutex);
    
    // Remove entries affected by modified/deleted nodes
    for (auto it = m_completionCache.begin(); it != m_completionCache.end();) {
        bool affected = false;
        
        // Check if cursor node or scope was modified
        for (NodeID mod : diff.modifiedNodes) {
            if (it->second.fingerprint.cursorNode == mod ||
                it->second.fingerprint.scopeNode == mod) {
                affected = true;
                break;
            }
        }
        
        if (affected) {
            it = m_completionCache.erase(it);
        } else {
            ++it;
        }
    }
}

bool ASTGraphEngine::awaitVersion(GraphVersion version, uint64_t timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (m_currentVersion.load() < version) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - start).count();
        
        if (elapsed >= static_cast<int64_t>(timeoutMs)) {
            return false;
        }
        
        std::this_thread::yield();
    }
    
    return true;
}

ASTGraphEngine::Stats ASTGraphEngine::getStats() const {
    Stats stats;
    
    std::shared_lock<std::shared_mutex> nodeLock(m_nodeMutex);
    stats.totalNodes = m_nodes.size();
    nodeLock.unlock();
    
    std::shared_lock<std::shared_mutex> fileLock(m_fileMutex);
    stats.totalFiles = m_files.size();
    fileLock.unlock();
    
    stats.cacheHits = m_cacheHits.load();
    stats.cacheMisses = m_cacheMisses.load();
    stats.incrementalUpdates = m_incrementalUpdates.load();
    stats.fullReparses = m_fullReparses.load();
    
    return stats;
}

NodeID ASTGraphEngine::allocateNodeID() {
    return m_nextNodeID.fetch_add(1);
}

uint32_t ASTGraphEngine::allocateFileID() {
    return m_nextFileID.fetch_add(1);
}

GraphDiff ASTGraphEngine::computeDiff(const FileInfo& oldFile, const FileInfo& newFile) {
    GraphDiff diff;
    diff.fromVersion = m_currentVersion.load();
    diff.toVersion = diff.fromVersion + 1;
    
    // Simplified diff: if content changed significantly, mark as modified
    // Real implementation would use Myers diff or similar
    if (oldFile.content != newFile.content) {
        // For now: mark root as modified
        if (oldFile.rootNode != INVALID_NODE_ID) {
            diff.modifiedNodes.push_back(oldFile.rootNode);
        }
    }
    
    return diff;
}

void ASTGraphEngine::pruneOldVersions() {
    std::unique_lock<std::mutex> lock(m_versionMutex);
    
    GraphVersion current = m_currentVersion.load();
    GraphVersion keepThreshold = current > 100 ? current - 100 : 0;
    
    for (auto it = m_versionDiffs.begin(); it != m_versionDiffs.end();) {
        if (it->first < keepThreshold) {
            it = m_versionDiffs.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// Global Instance
// ============================================================================

ASTGraphEngine& getASTGraphEngine() {
    static ASTGraphEngine instance;
    return instance;
}

} // namespace AST
} // namespace RawrXD
