// ============================================================================
// IncludeGraph.cpp - Header Dependency Tracker
// WORKING IMPLEMENTATION
// ============================================================================

#include "IncludeGraph.hpp"
#include <fstream>
#include <sstream>
#include <regex>

namespace RawrXD {
namespace IDE {

// ============================================================================
// Include Graph Node Implementation
// ============================================================================

IncludeGraphNode::IncludeGraphNode(const std::string& filePath)
    : filePath(filePath), isSystemHeader(false) {}

void IncludeGraphNode::AddInclude(std::shared_ptr<IncludeGraphNode> included,
                                  size_t line, bool isSystem) {
    IncludeEdge edge;
    edge.target = included;
    edge.includeLine = line;
    edge.isSystemInclude = isSystem;
    includes.push_back(edge);
    included->includedBy.push_back(shared_from_this());
}

// ============================================================================
// Include Graph Implementation
// ============================================================================

struct IncludeGraph::Impl {
    // File path -> Node
    std::unordered_map<std::string, std::shared_ptr<IncludeGraphNode>> nodes_;
    
    // System include paths
    std::vector<std::string> systemPaths_;
    
    // Project include paths
    std::vector<std::string> projectPaths_;
    
    mutable std::shared_mutex mutex_;
};

IncludeGraph::IncludeGraph() : impl_(std::make_unique<Impl>()) {}
IncludeGraph::~IncludeGraph() = default;

void IncludeGraph::AddSystemPath(const std::string& path) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->systemPaths_.push_back(path);
}

void IncludeGraph::AddProjectPath(const std::string& path) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->projectPaths_.push_back(path);
}

std::shared_ptr<IncludeGraphNode> IncludeGraph::GetOrCreateNode(const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->nodes_.find(filePath);
    if (it != impl_->nodes_.end()) {
        return it->second;
    }
    
    auto node = std::make_shared<IncludeGraphNode>(filePath);
    impl_->nodes_[filePath] = node;
    return node;
}

void IncludeGraph::AddInclude(const std::string& fromFile, const std::string& toFile,
                              size_t line, bool isSystem) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto fromNode = GetOrCreateNode(fromFile);
    auto toNode = GetOrCreateNode(toFile);
    
    fromNode->AddInclude(toNode, line, isSystem);
}

void IncludeGraph::ParseFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) return;
    
    std::string line;
    size_t lineNum = 0;
    
    // Regex for #include statements
    std::regex includeRegex(R"(#include\s*(["<])([^">]+)[">]))");
    
    while (std::getline(file, line)) {
        lineNum++;
        
        std::smatch match;
        if (std::regex_search(line, match, includeRegex)) {
            std::string delimiter = match[1];
            std::string includePath = match[2];
            bool isSystem = (delimiter == "<");
            
            // Resolve include path
            std::string resolvedPath = ResolveIncludePath(includePath, isSystem);
            if (!resolvedPath.empty()) {
                AddInclude(filePath, resolvedPath, lineNum, isSystem);
            }
        }
    }
}

std::string IncludeGraph::ResolveIncludePath(const std::string& includePath, bool isSystem) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    // Check if it's already an absolute path
    if (std::filesystem::exists(includePath)) {
        return std::filesystem::canonical(includePath).string();
    }
    
    // Search in appropriate paths
    const auto& searchPaths = isSystem ? impl_->systemPaths_ : impl_->projectPaths_;
    
    for (const auto& basePath : searchPaths) {
        std::filesystem::path fullPath = std::filesystem::path(basePath) / includePath;
        if (std::filesystem::exists(fullPath)) {
            return std::filesystem::canonical(fullPath).string();
        }
    }
    
    // Also check current directory
    if (std::filesystem::exists(includePath)) {
        return std::filesystem::canonical(includePath).string();
    }
    
    return "";
}

std::vector<std::string> IncludeGraph::GetIncludedFiles(const std::string& filePath) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::string> result;
    auto it = impl_->nodes_.find(filePath);
    if (it != impl_->nodes_.end()) {
        for (const auto& edge : it->second->includes) {
            if (auto target = edge.target.lock()) {
                result.push_back(target->filePath);
            }
        }
    }
    return result;
}

std::vector<std::string> IncludeGraph::GetFilesIncluding(const std::string& filePath) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::string> result;
    auto it = impl_->nodes_.find(filePath);
    if (it != impl_->nodes_.end()) {
        for (const auto& weakNode : it->second->includedBy) {
            if (auto node = weakNode.lock()) {
                result.push_back(node->filePath);
            }
        }
    }
    return result;
}

std::vector<std::string> IncludeGraph::GetTransitiveIncludes(const std::string& filePath) {
    std::vector<std::string> result;
    std::set<std::string> visited;
    std::queue<std::string> queue;
    
    queue.push(filePath);
    visited.insert(filePath);
    
    while (!queue.empty()) {
        std::string current = queue.front();
        queue.pop();
        
        auto direct = GetIncludedFiles(current);
        for (const auto& inc : direct) {
            if (visited.insert(inc).second) {
                result.push_back(inc);
                queue.push(inc);
            }
        }
    }
    
    return result;
}

std::vector<std::string> IncludeGraph::GetTransitiveIncludedBy(const std::string& filePath) {
    std::vector<std::string> result;
    std::set<std::string> visited;
    std::queue<std::string> queue;
    
    queue.push(filePath);
    visited.insert(filePath);
    
    while (!queue.empty()) {
        std::string current = queue.front();
        queue.pop();
        
        auto including = GetFilesIncluding(current);
        for (const auto& inc : including) {
            if (visited.insert(inc).second) {
                result.push_back(inc);
                queue.push(inc);
            }
        }
    }
    
    return result;
}

std::vector<std::string> IncludeGraph::GetIncludePath(const std::string& fromFile,
                                                        const std::string& toFile) {
    // BFS to find path
    std::queue<std::pair<std::string, std::vector<std::string>>> queue;
    std::set<std::string> visited;
    
    queue.push({fromFile, {fromFile}});
    visited.insert(fromFile);
    
    while (!queue.empty()) {
        auto [current, path] = queue.front();
        queue.pop();
        
        if (current == toFile) {
            return path;
        }
        
        auto includes = GetIncludedFiles(current);
        for (const auto& inc : includes) {
            if (visited.insert(inc).second) {
                auto newPath = path;
                newPath.push_back(inc);
                queue.push({inc, newPath});
            }
        }
    }
    
    return {};
}

std::vector<std::string> IncludeGraph::FindCircularDependencies() {
    std::vector<std::string> cycles;
    std::set<std::string> visited;
    std::set<std::string> recursionStack;
    std::vector<std::string> currentPath;
    
    std::function<void(const std::string&)> dfs = [&](const std::string& file) {
        visited.insert(file);
        recursionStack.insert(file);
        currentPath.push_back(file);
        
        auto includes = GetIncludedFiles(file);
        for (const auto& inc : includes) {
            if (recursionStack.count(inc)) {
                // Found cycle
                auto cycleStart = std::find(currentPath.begin(), currentPath.end(), inc);
                std::string cycle;
                for (auto it = cycleStart; it != currentPath.end(); ++it) {
                    if (!cycle.empty()) cycle += " -> ";
                    cycle += *it;
                }
                cycle += " -> " + inc;
                cycles.push_back(cycle);
            } else if (!visited.count(inc)) {
                dfs(inc);
            }
        }
        
        recursionStack.erase(file);
        currentPath.pop_back();
    };
    
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    for (const auto& [path, _] : impl_->nodes_) {
        if (!visited.count(path)) {
            dfs(path);
        }
    }
    
    return cycles;
}

std::vector<std::string> IncludeGraph::GetUnusedIncludes(const std::string& filePath) {
    // This would require semantic analysis to determine which includes are actually used
    // For now, return empty (placeholder for future implementation)
    return {};
}

void IncludeGraph::RemoveFile(const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->nodes_.find(filePath);
    if (it != impl_->nodes_.end()) {
        auto node = it->second;
        
        // Remove from includedBy lists
        for (const auto& edge : node->includes) {
            if (auto target = edge.target.lock()) {
                target->includedBy.erase(
                    std::remove_if(target->includedBy.begin(), target->includedBy.end(),
                        [&](const std::weak_ptr<IncludeGraphNode>& wp) {
                            if (auto sp = wp.lock()) {
                                return sp->filePath == filePath;
                            }
                            return true;
                        }), target->includedBy.end());
            }
        }
        
        // Remove from includes lists
        for (const auto& weakNode : node->includedBy) {
            if (auto including = weakNode.lock()) {
                including->includes.erase(
                    std::remove_if(including->includes.begin(), including->includes.end(),
                        [&](const IncludeEdge& edge) {
                            if (auto target = edge.target.lock()) {
                                return target->filePath == filePath;
                            }
                            return true;
                        }), including->includes.end());
            }
        }
        
        impl_->nodes_.erase(it);
    }
}

void IncludeGraph::Clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->nodes_.clear();
}

size_t IncludeGraph::GetNodeCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->nodes_.size();
}

size_t IncludeGraph::GetEdgeCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    size_t count = 0;
    for (const auto& [_, node] : impl_->nodes_) {
        count += node->includes.size();
    }
    return count;
}

} // namespace IDE
} // namespace RawrXD
