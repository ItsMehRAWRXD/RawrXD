// Repository Memory Graph - Implementation
// Persistent project understanding for the Sovereign Substrate

#include "RepositoryMemoryGraph.hpp"
#include "../kernel/AgentKernel.hpp"

#include <sstream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <queue>
#include <stack>

namespace RawrXD {
namespace Memory {

// ============================================================================
// Utility Functions
// ============================================================================

static std::string GenerateTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

static uint64_t HashString(const std::string& str) {
    // FNV-1a hash
    uint64_t hash = 14695981039346656037ULL;
    for (char c : str) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 1099511628211ULL;
    }
    return hash;
}

// ============================================================================
// SourceLocation Implementation
// ============================================================================

std::string SourceLocation::ToString() const {
    std::stringstream ss;
    ss << filePath << ":" << line << ":" << column;
    return ss.str();
}

// ============================================================================
// ASTNode Implementation
// ============================================================================

std::string ASTNode::GetTypeString() const {
    switch (type) {
        case NodeType::FILE: return "file";
        case NodeType::DIRECTORY: return "directory";
        case NodeType::NAMESPACE: return "namespace";
        case NodeType::CLASS: return "class";
        case NodeType::STRUCT: return "struct";
        case NodeType::FUNCTION: return "function";
        case NodeType::METHOD: return "method";
        case NodeType::VARIABLE: return "variable";
        case NodeType::ENUM: return "enum";
        case NodeType::TYPEDEF: return "typedef";
        case NodeType::MACRO: return "macro";
        case NodeType::TEMPLATE: return "template";
        case NodeType::CONCEPT: return "concept";
        default: return "unknown";
    }
}

std::vector<std::shared_ptr<ASTNode>> ASTNode::GetChildrenOfType(NodeType targetType) const {
    std::vector<std::shared_ptr<ASTNode>> result;
    for (auto& child : children) {
        if (child->type == targetType) {
            result.push_back(child);
        }
    }
    return result;
}

std::shared_ptr<ASTNode> ASTNode::FindChild(const std::string& childName) const {
    for (auto& child : children) {
        if (child->name == childName) {
            return child;
        }
    }
    return nullptr;
}

std::shared_ptr<ASTNode> ASTNode::GetAncestorOfType(NodeType ancestorType) const {
    auto current = parent.lock();
    while (current) {
        if (current->type == ancestorType) {
            return current;
        }
        current = current->parent.lock();
    }
    return nullptr;
}

std::string ASTNode::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"nodeId\":" << nodeId << ",";
    ss << "\"type\":\"" << GetTypeString() << "\",";
    ss << "\"name\":\"" << name << "\",";
    ss << "\"qualifiedName\":\"" << qualifiedName << "\",";
    ss << "\"location\":\"" << location.ToString() << "\",";
    ss << "\"signature\":\"" << signature << "\",";
    ss << "\"isDirty\":" << (isDirty ? "true" : "false") << ",";
    ss << "\"children\":" << children.size();
    ss << "}";
    return ss.str();
}

// ============================================================================
// Symbol Implementation
// ============================================================================

std::string Symbol::GetSignature() const {
    if (kind == NodeType::FUNCTION || kind == NodeType::METHOD) {
        std::stringstream ss;
        ss << returnType << " " << name << "(";
        for (size_t i = 0; i < parameters.size(); ++i) {
            if (i > 0) ss << ", ";
            ss << parameters[i].second; // type
        }
        ss << ")";
        if (isConstexpr) ss << " constexpr";
        if (isNoexcept) ss << " noexcept";
        return ss.str();
    }
    return name;
}

std::vector<std::shared_ptr<Symbol>> Symbol::GetReferences() const {
    std::vector<std::shared_ptr<Symbol>> result;
    // This would query the graph for all symbols that reference this one
    // For now, return related symbols
    for (auto& weakRef : relatedSymbols) {
        if (auto sym = weakRef.lock()) {
            result.push_back(sym);
        }
    }
    return result;
}

std::shared_ptr<Symbol> Symbol::GetDefinition() const {
    if (isDefined) {
        return std::const_pointer_cast<Symbol>(shared_from_this());
    }
    // Find definition in parent scope
    auto scope = parentScope.lock();
    while (scope) {
        for (auto& child : scope->childSymbols) {
            if (auto childSym = child.lock()) {
                if (childSym->name == name && childSym->isDefined) {
                    return childSym;
                }
            }
        }
        scope = scope->parentScope.lock();
    }
    return nullptr;
}

std::string Symbol::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"symbolId\":" << symbolId << ",";
    ss << "\"name\":\"" << name << "\",";
    ss << "\"kind\":\"" << static_cast<int>(kind) << "\",";
    ss << "\"typeName\":\"" << typeName << "\",";
    ss << "\"isDefined\":" << (isDefined ? "true" : "false") << ",";
    ss << "\"referenceCount\":" << references.size();
    ss << "}";
    return ss.str();
}

// ============================================================================
// DependencyEdge Implementation
// ============================================================================

std::string DependencyEdge::GetTypeString() const {
    switch (type) {
        case EdgeType::CONTAINS: return "contains";
        case EdgeType::DEPENDS_ON: return "depends_on";
        case EdgeType::CALLS: return "calls";
        case EdgeType::REFERENCES: return "references";
        case EdgeType::INHERITS_FROM: return "inherits_from";
        case EdgeType::IMPLEMENTS: return "implements";
        case EdgeType::IMPORTS: return "imports";
        case EdgeType::INSTANTIATES: return "instantiates";
        default: return "unknown";
    }
}

bool DependencyEdge::IsValid() const {
    return !source.expired() && !target.expired();
}

std::string DependencyEdge::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"edgeId\":" << edgeId << ",";
    ss << "\"type\":\"" << GetTypeString() << "\",";
    ss << "\"strength\":" << strength << ",";
    ss << "\"isCyclic\":" << (isCyclic ? "true" : "false");
    ss << "}";
    return ss.str();
}

// ============================================================================
// FileNode Implementation
// ============================================================================

std::string FileNode::GetLanguageString() const {
    switch (language) {
        case Language::CPP: return "C++";
        case Language::C: return "C";
        case Language::HLSL: return "HLSL";
        case Language::CUDA: return "CUDA";
        case Language::MASM: return "MASM";
        case Language::PYTHON: return "Python";
        case Language::CMAKE: return "CMake";
        case Language::JSON: return "JSON";
        case Language::XML: return "XML";
        default: return "Unknown";
    }
}

std::vector<std::shared_ptr<FileNode>> FileNode::GetDependencies() const {
    std::vector<std::shared_ptr<FileNode>> result;
    auto& graph = RepositoryGraph::Instance();
    
    // Get all DEPENDS_ON edges from this file
    auto deps = graph.GetDependencies(
        std::const_pointer_cast<FileNode>(shared_from_this()),
        EdgeType::DEPENDS_ON
    );
    
    for (auto& edge : deps) {
        if (auto target = edge->target.lock()) {
            if (auto fileNode = std::dynamic_pointer_cast<FileNode>(target)) {
                result.push_back(fileNode);
            }
        }
    }
    return result;
}

std::vector<std::shared_ptr<FileNode>> FileNode::GetDependents() const {
    std::vector<std::shared_ptr<FileNode>> result;
    auto& graph = RepositoryGraph::Instance();
    
    auto deps = graph.GetDependents(
        std::const_pointer_cast<FileNode>(shared_from_this()),
        EdgeType::DEPENDS_ON
    );
    
    for (auto& edge : deps) {
        if (auto source = edge->source.lock()) {
            if (auto fileNode = std::dynamic_pointer_cast<FileNode>(source)) {
                result.push_back(fileNode);
            }
        }
    }
    return result;
}

// ============================================================================
// RepositoryGraph Implementation
// ============================================================================

RepositoryGraph& RepositoryGraph::Instance() {
    static RepositoryGraph instance;
    return instance;
}

bool RepositoryGraph::Initialize(const std::string& repoRoot) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (initialized_.load()) {
        return true; // Already initialized
    }
    
    repoRoot_ = repoRoot;
    
    // Normalize path
    std::filesystem::path rootPath(repoRoot_);
    repoRoot_ = std::filesystem::absolute(rootPath).string();
    
    // Scan directory structure
    if (std::filesystem::exists(repoRoot_)) {
        for (auto& entry : std::filesystem::recursive_directory_iterator(repoRoot_)) {
            if (entry.is_regular_file()) {
                auto path = entry.path().string();
                
                // Skip build directories and hidden files
                if (path.find("/build/") != std::string::npos ||
                    path.find("/.git/") != std::string::npos ||
                    path.find("/.rawrxd/") != std::string::npos) {
                    continue;
                }
                
                AddFile(path);
            }
        }
    }
    
    BuildIndexes();
    initialized_.store(true);
    
    return true;
}

void RepositoryGraph::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    files_.clear();
    symbols_.clear();
    edges_.clear();
    nodes_.clear();
    pathToFile_.clear();
    qualifiedNameToSymbol_.clear();
    nameToSymbols_.clear();
    dirtyFiles_.clear();
    
    initialized_.store(false);
}

std::shared_ptr<FileNode> RepositoryGraph::AddFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check if already exists
    auto it = pathToFile_.find(path);
    if (it != pathToFile_.end()) {
        return files_[it->second];
    }
    
    auto file = std::make_shared<FileNode>();
    file->fileId = GenerateFileId();
    file->nodeId = file->fileId; // Files are also nodes
    file->type = NodeType::FILE;
    file->absolutePath = std::filesystem::absolute(path).string();
    file->relativePath = std::filesystem::relative(path, repoRoot_).string();
    file->extension = std::filesystem::path(path).extension().string();
    file->name = std::filesystem::path(path).filename().string();
    
    // Detect language
    if (file->extension == ".cpp" || file->extension == ".cc" || file->extension == ".cxx") {
        file->language = FileNode::Language::CPP;
        file->isSource = true;
    } else if (file->extension == ".h" || file->extension == ".hpp" || file->extension == ".hxx") {
        file->language = FileNode::Language::CPP;
        file->isHeader = true;
    } else if (file->extension == ".c") {
        file->language = FileNode::Language::C;
        file->isSource = true;
    } else if (file->extension == ".py") {
        file->language = FileNode::Language::PYTHON;
    } else if (file->extension == ".cmake" || file->name == "CMakeLists.txt") {
        file->language = FileNode::Language::CMAKE;
    } else if (file->extension == ".asm" || file->extension == ".masm") {
        file->language = FileNode::Language::MASM;
        file->isSource = true;
    }
    
    // Get file info
    if (std::filesystem::exists(file->absolutePath)) {
        file->fileSize = std::filesystem::file_size(file->absolutePath);
        auto lastWrite = std::filesystem::last_write_time(file->absolutePath);
        file->lastModified = std::chrono::steady_clock::now(); // Approximation
        
        // Compute hash
        std::ifstream f(file->absolutePath, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(f)),
                             std::istreambuf_iterator<char>());
        file->contentHash = HashString(content);
    }
    
    // Store
    files_[file->fileId] = file;
    nodes_[file->nodeId] = file;
    pathToFile_[path] = file->fileId;
    
    return file;
}

void RepositoryGraph::RemoveFile(FileId fileId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = files_.find(fileId);
    if (it == files_.end()) return;
    
    auto file = it->second;
    
    // Remove from path index
    pathToFile_.erase(file->absolutePath);
    pathToFile_.erase(file->relativePath);
    
    // Remove from dirty set
    dirtyFiles_.erase(fileId);
    
    // Remove from nodes
    nodes_.erase(file->nodeId);
    
    // Remove file
    files_.erase(it);
}

std::shared_ptr<FileNode> RepositoryGraph::GetFile(FileId fileId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = files_.find(fileId);
    if (it != files_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<FileNode> RepositoryGraph::GetFileByPath(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = pathToFile_.find(path);
    if (it != pathToFile_.end()) {
        return files_.at(it->second);
    }
    
    // Try relative path
    std::filesystem::repoRoot_;
    std::filesystem::path absPath = std::filesystem::absolute(path);
    auto relPath = std::filesystem::relative(absPath, repoRoot_);
    
    it = pathToFile_.find(relPath.string());
    if (it != pathToFile_.end()) {
        return files_.at(it->second);
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<FileNode>> RepositoryGraph::GetAllFiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<FileNode>> result;
    for (auto& [id, file] : files_) {
        result.push_back(file);
    }
    return result;
}

std::vector<std::shared_ptr<FileNode>> RepositoryGraph::GetDirtyFiles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<FileNode>> result;
    for (FileId id : dirtyFiles_) {
        auto it = files_.find(id);
        if (it != files_.end()) {
            result.push_back(it->second);
        }
    }
    return result;
}

std::shared_ptr<Symbol> RepositoryGraph::AddSymbol(const std::string& name, NodeType kind) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto symbol = std::make_shared<Symbol>();
    symbol->symbolId = GenerateSymbolId();
    symbol->name = name;
    symbol->kind = kind;
    
    symbols_[symbol->symbolId] = symbol;
    nameToSymbols_.insert({name, symbol->symbolId});
    
    return symbol;
}

std::shared_ptr<Symbol> RepositoryGraph::FindSymbol(const std::string& qualifiedName) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = qualifiedNameToSymbol_.find(qualifiedName);
    if (it != qualifiedNameToSymbol_.end()) {
        return symbols_.at(it->second);
    }
    
    // Try simple name lookup
    auto range = nameToSymbols_.equal_range(qualifiedName);
    if (range.first != range.second) {
        return symbols_.at(range.first->second);
    }
    
    return nullptr;
}

std::vector<std::shared_ptr<Symbol>> RepositoryGraph::QuerySymbols(const SymbolQuery& query) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<Symbol>> result;
    
    for (auto& [id, symbol] : symbols_) {
        // Filter by type
        if (query.type != NodeType::COUNT && symbol->kind != query.type) {
            continue;
        }
        
        // Filter by visibility
        if (symbol->visibility != query.visibility) {
            continue;
        }
        
        // Filter by file
        if (query.inFile != 0) {
            // Would need to check symbol's definition location
            // Simplified: skip for now
        }
        
        // Filter by generated
        if (!query.includeGenerated) {
            // Would need to track generated symbols
        }
        
        // Name pattern matching (simplified - exact or contains)
        if (query.namePattern.find("*") != std::string::npos) {
            // Wildcard pattern
            std::string pattern = query.namePattern;
            pattern.replace(pattern.find("*"), 1, "");
            if (symbol->name.find(pattern) == std::string::npos) {
                continue;
            }
        } else if (symbol->name != query.namePattern) {
            continue;
        }
        
        result.push_back(symbol);
        
        if (result.size() >= query.maxResults) {
            break;
        }
    }
    
    return result;
}

std::shared_ptr<DependencyEdge> RepositoryGraph::AddDependency(
    std::shared_ptr<ASTNode> source,
    std::shared_ptr<ASTNode> target,
    EdgeType type
) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto edge = std::make_shared<DependencyEdge>();
    edge->edgeId = GenerateEdgeId();
    edge->type = type;
    edge->source = source;
    edge->target = target;
    
    edges_[edge->edgeId] = edge;
    
    return edge;
}

std::vector<std::shared_ptr<DependencyEdge>> RepositoryGraph::GetDependencies(
    std::shared_ptr<ASTNode> node,
    EdgeType type
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<DependencyEdge>> result;
    
    for (auto& [id, edge] : edges_) {
        if (auto src = edge->source.lock()) {
            if (src->nodeId == node->nodeId && edge->type == type) {
                result.push_back(edge);
            }
        }
    }
    
    return result;
}

std::vector<std::shared_ptr<DependencyEdge>> RepositoryGraph::GetDependents(
    std::shared_ptr<ASTNode> node,
    EdgeType type
) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<DependencyEdge>> result;
    
    for (auto& [id, edge] : edges_) {
        if (auto tgt = edge->target.lock()) {
            if (tgt->nodeId == node->nodeId && edge->type == type) {
                result.push_back(edge);
            }
        }
    }
    
    return result;
}

void RepositoryGraph::MarkFileDirty(FileId fileId) {
    std::lock_guard<std::mutex> lock(mutex_);
    dirtyFiles_.insert(fileId);
    
    auto it = files_.find(fileId);
    if (it != files_.end()) {
        it->second->isDirty = true;
        it->second->needsReparse = true;
    }
    
    // Notify subscribers
    for (auto& callback : fileChangeCallbacks_) {
        if (it != files_.end()) {
            callback(fileId, it->second->relativePath);
        }
    }
}

RepositoryGraph::Stats RepositoryGraph::GetStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    Stats stats;
    stats.fileCount = files_.size();
    stats.symbolCount = symbols_.size();
    stats.edgeCount = edges_.size();
    stats.dirtyFileCount = dirtyFiles_.size();
    
    // Count references
    for (auto& [id, sym] : symbols_) {
        stats.referenceCount += sym->references.size();
    }
    
    // Estimate memory (very rough)
    stats.memoryUsageMB = (
        files_.size() * 1024 +
        symbols_.size() * 512 +
        edges_.size() * 256 +
        nodes_.size() * 1024
    ) / (1024.0 * 1024.0);
    
    stats.lastUpdate = std::chrono::steady_clock::now();
    
    return stats;
}

void RepositoryGraph::BuildIndexes() {
    // Build qualified name index
    qualifiedNameToSymbol_.clear();
    for (auto& [id, symbol] : symbols_) {
        if (!symbol->qualifiedName.empty()) {
            qualifiedNameToSymbol_[symbol->qualifiedName] = id;
        }
    }
}

void RepositoryGraph::SubscribeToFileChanges(FileChangeCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    fileChangeCallbacks_.push_back(callback);
}

// ============================================================================
// Persistence Implementation
// ============================================================================

bool RepositoryGraph::SaveToDisk(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Write header
    const char* magic = "RAWRGRAPH";
    file.write(magic, 9);
    
    uint32_t version = 1;
    file.write(reinterpret_cast<const char*>(&version), sizeof(version));
    
    // Write repo root
    uint32_t rootLen = static_cast<uint32_t>(repoRoot_.length());
    file.write(reinterpret_cast<const char*>(&rootLen), sizeof(rootLen));
    file.write(repoRoot_.c_str(), rootLen);
    
    // Write files
    uint64_t fileCount = files_.size();
    file.write(reinterpret_cast<const char*>(&fileCount), sizeof(fileCount));
    
    for (auto& [id, fileNode] : files_) {
        file.write(reinterpret_cast<const char*>(&id), sizeof(id));
        
        uint32_t absPathLen = static_cast<uint32_t>(fileNode->absolutePath.length());
        file.write(reinterpret_cast<const char*>(&absPathLen), sizeof(absPathLen));
        file.write(fileNode->absolutePath.c_str(), absPathLen);
        
        uint32_t relPathLen = static_cast<uint32_t>(fileNode->relativePath.length());
        file.write(reinterpret_cast<const char*>(&relPathLen), sizeof(relPathLen));
        file.write(fileNode->relativePath.c_str(), relPathLen);
        
        file.write(reinterpret_cast<const char*>(&fileNode->contentHash), sizeof(fileNode->contentHash));
        file.write(reinterpret_cast<const char*>(&fileNode->fileSize), sizeof(fileNode->fileSize));
        file.write(reinterpret_cast<const char*>(&fileNode->language), sizeof(fileNode->language));
        file.write(reinterpret_cast<const char*>(&fileNode->isHeader), sizeof(fileNode->isHeader));
        file.write(reinterpret_cast<const char*>(&fileNode->isSource), sizeof(fileNode->isSource));
    }
    
    // Write symbols
    uint64_t symbolCount = symbols_.size();
    file.write(reinterpret_cast<const char*>(&symbolCount), sizeof(symbolCount));
    
    for (auto& [id, symbol] : symbols_) {
        file.write(reinterpret_cast<const char*>(&id), sizeof(id));
        
        uint32_t nameLen = static_cast<uint32_t>(symbol->name.length());
        file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
        file.write(symbol->name.c_str(), nameLen);
        
        uint32_t qnameLen = static_cast<uint32_t>(symbol->qualifiedName.length());
        file.write(reinterpret_cast<const char*>(&qnameLen), sizeof(qnameLen));
        file.write(symbol->qualifiedName.c_str(), qnameLen);
        
        file.write(reinterpret_cast<const char*>(&symbol->kind), sizeof(symbol->kind));
        file.write(reinterpret_cast<const char*>(&symbol->isDefined), sizeof(symbol->isDefined));
        file.write(reinterpret_cast<const char*>(&symbol->isExported), sizeof(symbol->isExported));
    }
    
    // Write edges
    uint64_t edgeCount = edges_.size();
    file.write(reinterpret_cast<const char*>(&edgeCount), sizeof(edgeCount));
    
    for (auto& [id, edge] : edges_) {
        file.write(reinterpret_cast<const char*>(&id), sizeof(id));
        file.write(reinterpret_cast<const char*>(&edge->type), sizeof(edge->type));
        
        NodeId sourceId = edge->source.expired() ? 0 : edge->source.lock()->nodeId;
        NodeId targetId = edge->target.expired() ? 0 : edge->target.lock()->nodeId;
        
        file.write(reinterpret_cast<const char*>(&sourceId), sizeof(sourceId));
        file.write(reinterpret_cast<const char*>(&targetId), sizeof(targetId));
        file.write(reinterpret_cast<const char*>(&edge->strength), sizeof(edge->strength));
    }
    
    // Write dirty files
    uint64_t dirtyCount = dirtyFiles_.size();
    file.write(reinterpret_cast<const char*>(&dirtyCount), sizeof(dirtyCount));
    for (FileId dirtyId : dirtyFiles_) {
        file.write(reinterpret_cast<const char*>(&dirtyId), sizeof(dirtyId));
    }
    
    // Write ID generators
    FileId nextFile = nextFileId_.load();
    SymbolId nextSymbol = nextSymbolId_.load();
    EdgeId nextEdge = nextEdgeId_.load();
    NodeId nextNode = nextNodeId_.load();
    
    file.write(reinterpret_cast<const char*>(&nextFile), sizeof(nextFile));
    file.write(reinterpret_cast<const char*>(&nextSymbol), sizeof(nextSymbol));
    file.write(reinterpret_cast<const char*>(&nextEdge), sizeof(nextEdge));
    file.write(reinterpret_cast<const char*>(&nextNode), sizeof(nextNode));
    
    file.close();
    return true;
}

bool RepositoryGraph::LoadFromDisk(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Read header
    char magic[10] = {};
    file.read(magic, 9);
    if (std::string(magic, 9) != "RAWRGRAPH") {
        return false; // Invalid file format
    }
    
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != 1) {
        return false; // Unsupported version
    }
    
    // Clear existing data
    files_.clear();
    symbols_.clear();
    edges_.clear();
    nodes_.clear();
    pathToFile_.clear();
    qualifiedNameToSymbol_.clear();
    nameToSymbols_.clear();
    dirtyFiles_.clear();
    
    // Read repo root
    uint32_t rootLen;
    file.read(reinterpret_cast<char*>(&rootLen), sizeof(rootLen));
    repoRoot_.resize(rootLen);
    file.read(&repoRoot_[0], rootLen);
    
    // Read files
    uint64_t fileCount;
    file.read(reinterpret_cast<char*>(&fileCount), sizeof(fileCount));
    
    for (uint64_t i = 0; i < fileCount; i++) {
        FileId id;
        file.read(reinterpret_cast<char*>(&id), sizeof(id));
        
        auto fileNode = std::make_shared<FileNode>();
        fileNode->fileId = id;
        fileNode->nodeId = id;
        fileNode->type = NodeType::FILE;
        
        uint32_t absPathLen;
        file.read(reinterpret_cast<char*>(&absPathLen), sizeof(absPathLen));
        fileNode->absolutePath.resize(absPathLen);
        file.read(&fileNode->absolutePath[0], absPathLen);
        
        uint32_t relPathLen;
        file.read(reinterpret_cast<char*>(&relPathLen), sizeof(relPathLen));
        fileNode->relativePath.resize(relPathLen);
        file.read(&fileNode->relativePath[0], relPathLen);
        
        file.read(reinterpret_cast<char*>(&fileNode->contentHash), sizeof(fileNode->contentHash));
        file.read(reinterpret_cast<char*>(&fileNode->fileSize), sizeof(fileNode->fileSize));
        file.read(reinterpret_cast<char*>(&fileNode->language), sizeof(fileNode->language));
        file.read(reinterpret_cast<char*>(&fileNode->isHeader), sizeof(fileNode->isHeader));
        file.read(reinterpret_cast<char*>(&fileNode->isSource), sizeof(fileNode->isSource));
        
        fileNode->name = std::filesystem::path(fileNode->absolutePath).filename().string();
        fileNode->extension = std::filesystem::path(fileNode->absolutePath).extension().string();
        
        files_[id] = fileNode;
        nodes_[id] = fileNode;
        pathToFile_[fileNode->absolutePath] = id;
        pathToFile_[fileNode->relativePath] = id;
    }
    
    // Read symbols
    uint64_t symbolCount;
    file.read(reinterpret_cast<char*>(&symbolCount), sizeof(symbolCount));
    
    for (uint64_t i = 0; i < symbolCount; i++) {
        SymbolId id;
        file.read(reinterpret_cast<char*>(&id), sizeof(id));
        
        auto symbol = std::make_shared<Symbol>();
        symbol->symbolId = id;
        
        uint32_t nameLen;
        file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
        symbol->name.resize(nameLen);
        file.read(&symbol->name[0], nameLen);
        
        uint32_t qnameLen;
        file.read(reinterpret_cast<char*>(&qnameLen), sizeof(qnameLen));
        symbol->qualifiedName.resize(qnameLen);
        file.read(&symbol->qualifiedName[0], qnameLen);
        
        file.read(reinterpret_cast<char*>(&symbol->kind), sizeof(symbol->kind));
        file.read(reinterpret_cast<char*>(&symbol->isDefined), sizeof(symbol->isDefined));
        file.read(reinterpret_cast<char*>(&symbol->isExported), sizeof(symbol->isExported));
        
        symbols_[id] = symbol;
        nameToSymbols_.insert({symbol->name, id});
        if (!symbol->qualifiedName.empty()) {
            qualifiedNameToSymbol_[symbol->qualifiedName] = id;
        }
    }
    
    // Read edges
    uint64_t edgeCount;
    file.read(reinterpret_cast<char*>(&edgeCount), sizeof(edgeCount));
    
    for (uint64_t i = 0; i < edgeCount; i++) {
        EdgeId id;
        file.read(reinterpret_cast<char*>(&id), sizeof(id));
        
        auto edge = std::make_shared<DependencyEdge>();
        edge->edgeId = id;
        
        file.read(reinterpret_cast<char*>(&edge->type), sizeof(edge->type));
        
        NodeId sourceId, targetId;
        file.read(reinterpret_cast<char*>(&sourceId), sizeof(sourceId));
        file.read(reinterpret_cast<char*>(&targetId), sizeof(targetId));
        file.read(reinterpret_cast<char*>(&edge->strength), sizeof(edge->strength));
        
        // Restore weak pointers
        if (sourceId != 0 && nodes_.find(sourceId) != nodes_.end()) {
            edge->source = nodes_[sourceId];
        }
        if (targetId != 0 && nodes_.find(targetId) != nodes_.end()) {
            edge->target = nodes_[targetId];
        }
        
        edges_[id] = edge;
    }
    
    // Read dirty files
    uint64_t dirtyCount;
    file.read(reinterpret_cast<char*>(&dirtyCount), sizeof(dirtyCount));
    for (uint64_t i = 0; i < dirtyCount; i++) {
        FileId dirtyId;
        file.read(reinterpret_cast<char*>(&dirtyId), sizeof(dirtyId));
        dirtyFiles_.insert(dirtyId);
    }
    
    // Read ID generators
    FileId nextFile;
    SymbolId nextSymbol;
    EdgeId nextEdge;
    NodeId nextNode;
    
    file.read(reinterpret_cast<char*>(&nextFile), sizeof(nextFile));
    file.read(reinterpret_cast<char*>(&nextSymbol), sizeof(nextSymbol));
    file.read(reinterpret_cast<char*>(&nextEdge), sizeof(nextEdge));
    file.read(reinterpret_cast<char*>(&nextNode), sizeof(nextNode));
    
    nextFileId_.store(nextFile);
    nextSymbolId_.store(nextSymbol);
    nextEdgeId_.store(nextEdge);
    nextNodeId_.store(nextNode);
    
    file.close();
    initialized_.store(true);
    return true;
}

// ============================================================================
// GraphWalker Implementation
// ============================================================================

void GraphWalker::Walk(
    std::shared_ptr<ASTNode> start,
    VisitCallback visitor,
    EdgeFilter filter,
    uint32_t maxDepth
) {
    if (!start) return;
    
    std::unordered_set<NodeId> visited;
    std::queue<std::pair<std::shared_ptr<ASTNode>, uint32_t>> queue;
    queue.push({start, 0});
    visited.insert(start->nodeId);
    
    auto& graph = RepositoryGraph::Instance();
    
    while (!queue.empty()) {
        auto [current, depth] = queue.front();
        queue.pop();
        
        if (depth > maxDepth) continue;
        
        // Visit node
        if (!visitor(current, depth)) {
            break; // Visitor requested stop
        }
        
        // Get dependencies
        auto deps = graph.GetDependencies(current);
        for (auto& edge : deps) {
            if (filter && !filter(edge)) continue;
            
            if (auto target = edge->target.lock()) {
                if (visited.insert(target->nodeId).second) {
                    queue.push({target, depth + 1});
                }
            }
        }
    }
}

// ============================================================================
// ContextAssembler Implementation
// ============================================================================

ContextAssembler& ContextAssembler::Instance() {
    static ContextAssembler instance;
    return instance;
}

uint32_t ContextAssembler::EstimateTokens(const std::string& text) const {
    // Rough estimate: ~4 characters per token for code
    return static_cast<uint32_t>(text.length() / 4);
}

std::string ContextAssembler::TruncateToTokens(const std::string& text, uint32_t maxTokens) const {
    uint32_t estimatedTokens = EstimateTokens(text);
    if (estimatedTokens <= maxTokens) {
        return text;
    }
    
    // Truncate to approximate token count
    size_t charLimit = maxTokens * 4;
    if (charLimit >= text.length()) {
        return text;
    }
    
    return text.substr(0, charLimit) + "\n... [truncated]";
}

std::string ContextAssembler::AssembleFromFragments(
    const std::vector<ContextFragment>& fragments,
    uint32_t maxTokens
) {
    // Sort by priority (highest first)
    auto sortedFragments = fragments;
    std::sort(sortedFragments.begin(), sortedFragments.end(),
        [](const ContextFragment& a, const ContextFragment& b) {
            return a.priority > b.priority;
        });
    
    std::stringstream result;
    uint32_t currentTokens = 0;
    
    for (auto& fragment : sortedFragments) {
        if (currentTokens + fragment.tokenCount > maxTokens) {
            break;
        }
        
        result << "// Source: " << fragment.source << "\n";
        result << fragment.content << "\n\n";
        currentTokens += fragment.tokenCount;
    }
    
    return result.str();
}

std::string ContextAssembler::AssembleContextForIntent(
    const std::string& intentType,
    const std::string& targetSymbol,
    uint32_t maxTokens
) {
    auto& graph = RepositoryGraph::Instance();
    
    std::vector<ContextFragment> fragments;
    
    // Find target symbol
    auto symbol = graph.FindSymbol(targetSymbol);
    if (symbol) {
        // Add symbol definition (highest priority)
        ContextFragment defFragment;
        defFragment.content = symbol->GetSignature();
        defFragment.priority = 100;
        defFragment.tokenCount = EstimateTokens(defFragment.content);
        defFragment.source = symbol->definition.ToString();
        fragments.push_back(defFragment);
        
        // Add related symbols
        auto related = symbol->GetReferences();
        for (auto& rel : related) {
            ContextFragment relFragment;
            relFragment.content = rel->GetSignature();
            relFragment.priority = 50;
            relFragment.tokenCount = EstimateTokens(relFragment.content);
            relFragment.source = "related:" + rel->name;
            fragments.push_back(relFragment);
        }
    }
    
    return AssembleFromFragments(fragments, maxTokens);
}

} // namespace Memory
} // namespace RawrXD
