#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

namespace rawrxd {

/**
 * @brief Symbol kinds for AST analysis
 */
enum class SymbolKind {
    UNKNOWN,
    FUNCTION,
    VARIABLE,
    CLASS,
    STRUCT,
    ENUM,
    TYPEDEF,
    NAMESPACE,
    MACRO,
    PARAMETER
};

/**
 * @brief Symbol context from AST analysis
 */
struct SymbolContext {
    std::string name;
    std::string type;
    std::string scope;           // e.g., "MyClass::myMethod"
    int line_number;
    int column;
    SymbolKind kind;
    bool is_static = false;
    bool is_const = false;
    std::string documentation;   // Doxygen/JSDoc comments
};

/**
 * @brief Cursor position in source code
 */
struct CursorPosition {
    int line;
    int column;
    std::string file_path;
};

/**
 * @brief Configuration for AST context provider
 */
struct ASTParserConfig {
    int max_parse_time_ms = 50;      // Target: <50ms for incremental parse
    size_t max_cache_size = 100;     // Number of cached ASTs
    bool enable_comments = true;     // Extract documentation
    bool enable_types = true;        // Resolve type information
    std::vector<std::string> language_filters = {".cpp", ".h", ".hpp", ".c"};
};

/**
 * @brief AST-based context provider for scope-aware completions
 * 
 * Phase 17: Advanced Intelligence - Workstream 2
 * Provides real-time AST analysis for context-sensitive suggestions
 */
class ASTContextProvider {
public:
    explicit ASTContextProvider(const ASTParserConfig& config = {});
    ~ASTContextProvider();
    
    // Disable copy, enable move
    ASTContextProvider(const ASTContextProvider&) = delete;
    ASTContextProvider& operator=(const ASTContextProvider&) = delete;
    ASTContextProvider(ASTContextProvider&&) noexcept;
    ASTContextProvider& operator=(ASTContextProvider&&) noexcept;

    /**
     * @brief Parse a file and build AST (incremental if possible)
     * @param file_path Path to source file
     * @param content Current file content (may differ from disk)
     * @return true if parse succeeded
     */
    bool parse_file(const std::string& file_path, const std::string& content);
    
    /**
     * @brief Get symbols visible at cursor position
     * @param cursor Current cursor position
     * @return Vector of accessible symbols
     */
    std::vector<SymbolContext> get_symbols_at_cursor(const CursorPosition& cursor);
    
    /**
     * @brief Get type information for a symbol
     * @param symbol_name Name to look up
     * @param cursor Current position for scope resolution
     * @return Type string or empty if not found
     */
    std::string get_symbol_type(const std::string& symbol_name, 
                                 const CursorPosition& cursor);
    
    /**
     * @brief Find all references to a symbol
     * @param symbol_name Name to search for
     * @return List of positions where symbol appears
     */
    std::vector<CursorPosition> find_references(const std::string& symbol_name);
    
    /**
     * @brief Get current scope at cursor (e.g., "ClassName::methodName")
     * @param cursor Current position
     * @return Scope string
     */
    std::string get_current_scope(const CursorPosition& cursor);
    
    /**
     * @brief Check if provider has parsed a file
     */
    bool has_file(const std::string& file_path) const;
    
    /**
     * @brief Invalidate cached AST for a file
     */
    void invalidate_file(const std::string& file_path);
    
    /**
     * @brief Clear all cached ASTs
     */
    void clear_cache();

private:
    struct Impl;
    std::unique_ptr<Impl> m_impl;
    ASTParserConfig m_config;
};

} // namespace rawrxd