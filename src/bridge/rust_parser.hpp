// rust_parser.hpp — Stub for build compatibility
#pragma once
#include <string>
#include <vector>

namespace rawrxd {
namespace parser {

struct Symbol {
    std::string name;
    std::string kind;
    size_t line = 0;
    size_t column = 0;
};

struct ParseResult {
    std::vector<Symbol> symbols;
    bool success = false;
};

inline ParseResult parseRust(const std::string& /*source*/) {
    return ParseResult{};
}

} // namespace parser

namespace ast {

// Forward declarations for range types
struct Position {
    size_t line = 0;
    size_t column = 0;
};

struct Range {
    Position start;
    Position end;
};

// Symbol metadata types - matching RawrXD::AST::NodeType
enum class NodeType {
    Unknown,
    FunctionDecl,
    VariableDecl,
    ClassDecl,
    StructDecl,
    EnumDecl,
    NamespaceDecl
};

// Legacy SymbolType alias for compatibility
using SymbolType = NodeType;

// Symbol metadata structure
struct SymbolMeta {
    std::string doc;           // Documentation string
    std::string documentation;  // Alternative name
    std::string signature;
    std::string visibility;     // "public", "private", "protected"
    bool is_public = true;
    bool is_static = false;
    bool is_const = false;
};

struct Symbol {
    std::string name;
    std::string kind;
    size_t line = 0;
    size_t column = 0;
    bool is_public = true;
    
    // Additional members required by symbol_index_bridge.cpp
    NodeType type = NodeType::Unknown;
    SymbolMeta meta;
    std::string file;
    Range range;
};

class SymbolTable {
public:
    std::vector<Symbol> symbols;
    void add(const Symbol& s) { symbols.push_back(s); }
    const std::vector<Symbol>& all() const { return symbols; }
};

namespace rust {

class RustParser {
public:
    struct ParseResult {
        bool success = false;
        std::string error;
    };
    
    ParseResult parse(const std::string& /*source*/, const std::string& /*file_path*/, SymbolTable* /*table*/) {
        ParseResult result;
        result.success = false;
        result.error = "RustParser stub - not implemented";
        return result;
    }
};

} // namespace rust
} // namespace ast
} // namespace rawrxd
