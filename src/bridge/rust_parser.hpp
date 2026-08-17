// rust_parser.hpp — Rust language parser (basic implementation)
#pragma once
#include <string>
#include <vector>
#include <sstream>
#include <cctype>

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
    std::string error;
};

// Basic Rust token scanner — extracts fn/struct/enum/impl declarations
inline ParseResult parseRust(const std::string& source) {
    ParseResult result;
    std::istringstream stream(source);
    std::string line;
    size_t line_num = 0;

    while (std::getline(stream, line)) {
        ++line_num;
        // Trim leading whitespace
        size_t pos = 0;
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;

        if (pos >= line.size()) continue;

        // Check for Rust declarations
        if (line.compare(pos, 3, "fn ") == 0) {
            size_t name_start = pos + 3;
            size_t name_end = line.find('(', name_start);
            if (name_end != std::string::npos) {
                Symbol sym;
                sym.name = line.substr(name_start, name_end - name_start);
                sym.kind = "function";
                sym.line = line_num;
                sym.column = name_start + 1;
                result.symbols.push_back(sym);
            }
        } else if (line.compare(pos, 7, "struct ") == 0) {
            size_t name_start = pos + 7;
            size_t name_end = line.find_first_of(" {{<;", name_start);
            if (name_end != std::string::npos) {
                Symbol sym;
                sym.name = line.substr(name_start, name_end - name_start);
                sym.kind = "struct";
                sym.line = line_num;
                sym.column = name_start + 1;
                result.symbols.push_back(sym);
            }
        } else if (line.compare(pos, 5, "enum ") == 0) {
            size_t name_start = pos + 5;
            size_t name_end = line.find_first_of(" {{<;", name_start);
            if (name_end != std::string::npos) {
                Symbol sym;
                sym.name = line.substr(name_start, name_end - name_start);
                sym.kind = "enum";
                sym.line = line_num;
                sym.column = name_start + 1;
                result.symbols.push_back(sym);
            }
        } else if (line.compare(pos, 5, "impl ") == 0) {
            size_t name_start = pos + 5;
            size_t name_end = line.find_first_of(" {{<;", name_start);
            if (name_end != std::string::npos) {
                Symbol sym;
                sym.name = line.substr(name_start, name_end - name_start);
                sym.kind = "impl";
                sym.line = line_num;
                sym.column = name_start + 1;
                result.symbols.push_back(sym);
            }
        }
    }

    result.success = true;
    return result;
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

    ParseResult parse(const std::string& source, const std::string& file_path, SymbolTable* table) {
        ParseResult result;
        auto rawrResult = rawrxd::parser::parseRust(source);
        if (rawrResult.success) {
            for (const auto& sym : rawrResult.symbols) {
                Symbol s;
                s.name = sym.name;
                s.kind = sym.kind;
                s.line = sym.line;
                s.column = sym.column;
                s.file = file_path;
                if (table) table->add(s);
            }
            result.success = true;
        } else {
            result.error = rawrResult.error.empty() ? "Rust parse failed" : rawrResult.error;
        }
        return result;
    }
};

} // namespace rust
} // namespace ast
} // namespace rawrxd
