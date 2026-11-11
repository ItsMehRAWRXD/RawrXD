// ============================================================================
// CallGraph.cpp - Function Call Relationship Tracker
// WORKING IMPLEMENTATION
// ============================================================================

#include "CallGraph.hpp"
#include <algorithm>

namespace RawrXD {
namespace IDE {

// ============================================================================
// Call Graph Node Implementation
// ============================================================================

CallGraphNode::CallGraphNode(const std::string& functionName, const std::string& filePath,
                             size_t line, size_t column)
    : functionName(functionName), filePath(filePath), line(line), column(column) {}

void CallGraphNode::AddCallee(std::shared_ptr<CallGraphNode> callee) {
    callees.push_back(callee);
    callee->callers.push_back(shared_from_this());
}

void CallGraphNode::AddCaller(std::shared_ptr<CallGraphNode> caller) {
    callers.push_back(caller);
}

// ============================================================================
// Call Graph Implementation
// ============================================================================

struct CallGraph::Impl {
    // Function signature -> Node
    std::unordered_map<std::string, std::shared_ptr<CallGraphNode>> nodes_;
    
    // File path -> functions in file
    std::unordered_map<std::string, std::vector<std::string>> fileFunctions_;
    
    // Call sites: caller -> list of callees at each call site
    std::unordered_map<std::string, std::vector<CallSite>> callSites_;
    
    mutable std::shared_mutex mutex_;
};

CallGraph::CallGraph() : impl_(std::make_unique<Impl>()) {}
CallGraph::~CallGraph() = default;

std::shared_ptr<CallGraphNode> CallGraph::AddFunction(const std::string& functionName,
                                                       const std::string& filePath,
                                                       size_t line, size_t column) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::string signature = functionName + "@" + filePath + ":" + std::to_string(line);
    
    auto it = impl_->nodes_.find(signature);
    if (it != impl_->nodes_.end()) {
        return it->second;
    }
    
    auto node = std::make_shared<CallGraphNode>(functionName, filePath, line, column);
    impl_->nodes_[signature] = node;
    impl_->fileFunctions_[filePath].push_back(signature);
    
    return node;
}

void CallGraph::AddCall(const std::string& callerName, const std::string& callerFile, size_t callerLine,
                        const std::string& calleeName, const std::string& calleeFile, size_t calleeLine) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::string callerSig = callerName + "@" + callerFile + ":" + std::to_string(callerLine);
    std::string calleeSig = calleeName + "@" + calleeFile + ":" + std::to_string(calleeLine);
    
    // Get or create nodes
    auto callerIt = impl_->nodes_.find(callerSig);
    if (callerIt == impl_->nodes_.end()) {
        auto node = std::make_shared<CallGraphNode>(callerName, callerFile, callerLine, 0);
        callerIt = impl_->nodes_.insert({callerSig, node}).first;
        impl_->fileFunctions_[callerFile].push_back(callerSig);
    }
    
    auto calleeIt = impl_->nodes_.find(calleeSig);
    if (calleeIt == impl_->nodes_.end()) {
        auto node = std::make_shared<CallGraphNode>(calleeName, calleeFile, calleeLine, 0);
        calleeIt = impl_->nodes_.insert({calleeSig, node}).first;
        impl_->fileFunctions_[calleeFile].push_back(calleeSig);
    }
    
    // Add call relationship
    callerIt->second->AddCallee(calleeIt->second);
    
    // Record call site
    CallSite site;
    site.caller = callerIt->second;
    site.callee = calleeIt->second;
    site.callLine = callerLine;
    site.callColumn = 0;
    impl_->callSites_[callerSig].push_back(site);
}

std::shared_ptr<CallGraphNode> CallGraph::FindFunction(const std::string& functionName,
                                                           const std::string& filePath) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    // Try exact match first
    for (const auto& [sig, node] : impl_->nodes_) {
        if (node->functionName == functionName) {
            if (filePath.empty() || node->filePath == filePath) {
                return node;
            }
        }
    }
    return nullptr;
}

std::vector<std::shared_ptr<CallGraphNode>> CallGraph::GetCallers(const std::string& functionName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<CallGraphNode>> result;
    
    for (const auto& [sig, node] : impl_->nodes_) {
        if (node->functionName == functionName) {
            for (const auto& caller : node->callers) {
                if (auto sp = caller.lock()) {
                    result.push_back(sp);
                }
            }
        }
    }
    
    return result;
}

std::vector<std::shared_ptr<CallGraphNode>> CallGraph::GetCallees(const std::string& functionName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<CallGraphNode>> result;
    
    for (const auto& [sig, node] : impl_->nodes_) {
        if (node->functionName == functionName) {
            for (const auto& callee : node->callees) {
                result.push_back(callee);
            }
        }
    }
    
    return result;
}

std::vector<std::shared_ptr<CallGraphNode>> CallGraph::GetCallChain(
    const std::string& fromFunction, const std::string& toFunction) {
    
    std::vector<std::shared_ptr<CallGraphNode>> result;
    
    // BFS to find path
    auto start = FindFunction(fromFunction);
    auto target = FindFunction(toFunction);
    
    if (!start || !target) return result;
    
    std::queue<std::pair<std::shared_ptr<CallGraphNode>, std::vector<std::shared_ptr<CallGraphNode>>>> queue;
    std::set<std::string> visited;
    
    queue.push({start, {start}});
    visited.insert(start->functionName);
    
    while (!queue.empty()) {
        auto [current, path] = queue.front();
        queue.pop();
        
        if (current->functionName == toFunction) {
            return path;
        }
        
        for (const auto& callee : current->callees) {
            if (visited.insert(callee->functionName).second) {
                auto newPath = path;
                newPath.push_back(callee);
                queue.push({callee, newPath});
            }
        }
    }
    
    return result;
}

std::vector<std::shared_ptr<CallGraphNode>> CallGraph::GetTransitiveCallers(
    const std::string& functionName, size_t maxDepth) {
    
    std::vector<std::shared_ptr<CallGraphNode>> result;
    std::set<std::string> visited;
    std::queue<std::pair<std::shared_ptr<CallGraphNode>, size_t>> queue;
    
    auto start = FindFunction(functionName);
    if (!start) return result;
    
    // Find all nodes with this function name
    std::vector<std::shared_ptr<CallGraphNode>> startNodes;
    {
        std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
        for (const auto& [sig, node] : impl_->nodes_) {
            if (node->functionName == functionName) {
                startNodes.push_back(node);
            }
        }
    }
    
    for (const auto& node : startNodes) {
        queue.push({node, 0});
        visited.insert(node->functionName + "@" + node->filePath);
    }
    
    while (!queue.empty()) {
        auto [current, depth] = queue.front();
        queue.pop();
        
        if (depth >= maxDepth) continue;
        
        for (const auto& weakCaller : current->callers) {
            if (auto caller = weakCaller.lock()) {
                std::string key = caller->functionName + "@" + caller->filePath;
                if (visited.insert(key).second) {
                    result.push_back(caller);
                    queue.push({caller, depth + 1});
                }
            }
        }
    }
    
    return result;
}

std::vector<std::shared_ptr<CallGraphNode>> CallGraph::GetTransitiveCallees(
    const std::string& functionName, size_t maxDepth) {
    
    std::vector<std::shared_ptr<CallGraphNode>> result;
    std::set<std::string> visited;
    std::queue<std::pair<std::shared_ptr<CallGraphNode>, size_t>> queue;
    
    auto start = FindFunction(functionName);
    if (!start) return result;
    
    // Find all nodes with this function name
    std::vector<std::shared_ptr<CallGraphNode>> startNodes;
    {
        std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
        for (const auto& [sig, node] : impl_->nodes_) {
            if (node->functionName == functionName) {
                startNodes.push_back(node);
            }
        }
    }
    
    for (const auto& node : startNodes) {
        queue.push({node, 0});
        visited.insert(node->functionName + "@" + node->filePath);
    }
    
    while (!queue.empty()) {
        auto [current, depth] = queue.front();
        queue.pop();
        
        if (depth >= maxDepth) continue;
        
        for (const auto& callee : current->callees) {
            std::string key = callee->functionName + "@" + callee->filePath;
            if (visited.insert(key).second) {
                result.push_back(callee);
                queue.push({callee, depth + 1});
            }
        }
    }
    
    return result;
}

std::vector<CallSite> CallGraph::GetCallSites(const std::string& callerName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->callSites_.find(callerName);
    if (it != impl_->callSites_.end()) {
        return it->second;
    }
    return {};
}

std::vector<std::shared_ptr<CallGraphNode>> CallGraph::GetFunctionsInFile(
    const std::string& filePath) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<CallGraphNode>> result;
    auto it = impl_->fileFunctions_.find(filePath);
    if (it != impl_->fileFunctions_.end()) {
        for (const auto& sig : it->second) {
            auto nodeIt = impl_->nodes_.find(sig);
            if (nodeIt != impl_->nodes_.end()) {
                result.push_back(nodeIt->second);
            }
        }
    }
    return result;
}

void CallGraph::RemoveFunction(const std::string& functionName, const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::string signature = functionName + "@" + filePath;
    
    auto it = impl_->nodes_.find(signature);
    if (it != impl_->nodes_.end()) {
        auto node = it->second;
        
        // Remove from callers' callee lists
        for (const auto& weakCaller : node->callers) {
            if (auto caller = weakCaller.lock()) {
                caller->callees.erase(
                    std::remove_if(caller->callees.begin(), caller->callees.end(),
                        [&](const std::shared_ptr<CallGraphNode>& n) {
                            return n->functionName == functionName;
                        }), caller->callees.end());
            }
        }
        
        // Remove from callees' caller lists
        for (const auto& callee : node->callees) {
            callee->callers.erase(
                std::remove_if(callee->callers.begin(), callee->callers.end(),
                    [&](const std::weak_ptr<CallGraphNode>& wp) {
                        if (auto sp = wp.lock()) {
                            return sp->functionName == functionName;
                        }
                        return true;
                    }), callee->callers.end());
        }
        
        // Remove from file index
        auto fileIt = impl_->fileFunctions_.find(filePath);
        if (fileIt != impl_->fileFunctions_.end()) {
            auto& funcs = fileIt->second;
            funcs.erase(std::remove(funcs.begin(), funcs.end(), signature), funcs.end());
        }
        
        // Remove call sites
        impl_->callSites_.erase(signature);
        
        // Remove node
        impl_->nodes_.erase(it);
    }
}

void CallGraph::Clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->nodes_.clear();
    impl_->fileFunctions_.clear();
    impl_->callSites_.clear();
}

size_t CallGraph::GetNodeCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->nodes_.size();
}

size_t CallGraph::GetEdgeCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    size_t count = 0;
    for (const auto& [_, node] : impl_->nodes_) {
        count += node->callees.size();
    }
    return count;
}

} // namespace IDE
} // namespace RawrXD
