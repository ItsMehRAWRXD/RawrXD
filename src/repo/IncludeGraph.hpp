// ============================================================================
// IncludeGraph.hpp - Header Dependency Tracker
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>
#include <queue>
#include <set>
#include <filesystem>
#include <functional>

namespace RawrXD {
namespace IDE {

struct IncludeEdge {
    std::weak_ptr<class IncludeGraphNode> target;
    size_t includeLine;
    bool isSystemInclude;
};

class IncludeGraphNode : public std::enable_shared_from_this<IncludeGraphNode> {
public:
    IncludeGraphNode(const std::string& filePath);
    void AddInclude(std::shared_ptr<IncludeGraphNode> included, size_t line, bool isSystem);

    std::string filePath;
    bool isSystemHeader;
    std::vector<IncludeEdge> includes;
    std::vector<std::weak_ptr<IncludeGraphNode>> includedBy;
};

class IncludeGraph {
public:
    IncludeGraph();
    ~IncludeGraph();

    void AddSystemPath(const std::string& path);
    void AddProjectPath(const std::string& path);

    std::shared_ptr<IncludeGraphNode> GetOrCreateNode(const std::string& filePath);
    void AddInclude(const std::string& fromFile, const std::string& toFile,
                    size_t line, bool isSystem);
    void ParseFile(const std::string& filePath);
    std::string ResolveIncludePath(const std::string& includePath, bool isSystem);

    std::vector<std::string> GetIncludedFiles(const std::string& filePath);
    std::vector<std::string> GetFilesIncluding(const std::string& filePath);
    std::vector<std::string> GetTransitiveIncludes(const std::string& filePath);
    std::vector<std::string> GetTransitiveIncludedBy(const std::string& filePath);
    std::vector<std::string> GetIncludePath(const std::string& fromFile, const std::string& toFile);
    std::vector<std::string> FindCircularDependencies();
    std::vector<std::string> GetUnusedIncludes(const std::string& filePath);

    void RemoveFile(const std::string& filePath);
    void Clear();
    size_t GetNodeCount() const;
    size_t GetEdgeCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
