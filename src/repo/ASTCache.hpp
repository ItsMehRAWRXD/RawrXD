// ============================================================================
// ASTCache.hpp - Abstract Syntax Tree Caching
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <shared_mutex>
#include <filesystem>

namespace RawrXD {
namespace IDE {

struct Token {
    enum Type { Identifier, Keyword, Number, String, Symbol, Preprocessor, Comment, Whitespace, End };
    Type type;
    std::string text;
    size_t line;
    size_t column;
};

class ASTNode : public std::enable_shared_from_this<ASTNode> {
public:
    enum NodeKind {
        TranslationUnit, Namespace, Class, Struct, Enum,
        Function, Method, Variable, Field, Parameter,
        Template, Concept, Macro, Typedef, Using
    };

    ASTNode(NodeKind kind, const std::string& name, size_t line, size_t column);
    void AddChild(std::shared_ptr<ASTNode> child);
    void AddAttribute(const std::string& key, const std::string& value);
    std::string GetAttribute(const std::string& key) const;

    NodeKind kind;
    std::string name;
    size_t line;
    size_t column;
    std::shared_ptr<ASTNode> parent;
    std::vector<std::shared_ptr<ASTNode>> children;
    std::unordered_map<std::string, std::string> attributes;
};

struct ASTCacheStats {
    size_t totalFiles = 0;
    size_t totalNodes = 0;
    size_t cacheHits = 0;
    size_t cacheMisses = 0;
};

class ASTCache {
public:
    ASTCache();
    ~ASTCache();

    std::shared_ptr<ASTNode> ParseFile(const std::string& filePath);
    std::shared_ptr<ASTNode> GetCachedAST(const std::string& filePath);
    void Invalidate(const std::string& filePath);
    void InvalidateAll();

    std::vector<std::shared_ptr<ASTNode>> FindNodesByName(const std::string& name);
    std::shared_ptr<ASTNode> FindNodeAtPosition(const std::string& filePath, size_t line, size_t column);
    std::vector<std::string> GetCachedFiles();
    ASTCacheStats GetStats();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
