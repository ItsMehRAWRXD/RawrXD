// ============================================================================
// CallGraph.hpp - Function Call Relationship Tracker
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>
#include <queue>
#include <set>

namespace RawrXD {
namespace IDE {

class CallGraphNode : public std::enable_shared_from_this<CallGraphNode> {
public:
    CallGraphNode(const std::string& functionName, const std::string& filePath,
                  size_t line, size_t column);
    void AddCallee(std::shared_ptr<CallGraphNode> callee);
    void AddCaller(std::shared_ptr<CallGraphNode> caller);

    std::string functionName;
    std::string filePath;
    size_t line;
    size_t column;
    std::vector<std::shared_ptr<CallGraphNode>> callees;
    std::vector<std::weak_ptr<CallGraphNode>> callers;
};

struct CallSite {
    std::shared_ptr<CallGraphNode> caller;
    std::shared_ptr<CallGraphNode> callee;
    size_t callLine;
    size_t callColumn;
};

class CallGraph {
public:
    CallGraph();
    ~CallGraph();

    std::shared_ptr<CallGraphNode> AddFunction(const std::string& functionName,
                                                const std::string& filePath,
                                                size_t line, size_t column);
    void AddCall(const std::string& callerName, const std::string& callerFile, size_t callerLine,
                 const std::string& calleeName, const std::string& calleeFile, size_t calleeLine);

    std::shared_ptr<CallGraphNode> FindFunction(const std::string& functionName,
                                                const std::string& filePath = "");
    std::vector<std::shared_ptr<CallGraphNode>> GetCallers(const std::string& functionName);
    std::vector<std::shared_ptr<CallGraphNode>> GetCallees(const std::string& functionName);
    std::vector<std::shared_ptr<CallGraphNode>> GetCallChain(const std::string& fromFunction,
                                                              const std::string& toFunction);
    std::vector<std::shared_ptr<CallGraphNode>> GetTransitiveCallers(const std::string& functionName,
                                                                      size_t maxDepth = 10);
    std::vector<std::shared_ptr<CallGraphNode>> GetTransitiveCallees(const std::string& functionName,
                                                                      size_t maxDepth = 10);
    std::vector<CallSite> GetCallSites(const std::string& callerName);
    std::vector<std::shared_ptr<CallGraphNode>> GetFunctionsInFile(const std::string& filePath);

    void RemoveFunction(const std::string& functionName, const std::string& filePath);
    void Clear();
    size_t GetNodeCount() const;
    size_t GetEdgeCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
