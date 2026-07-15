#include "ASTContextProvider.h"

#include <chrono>
#include <algorithm>
#include <regex>

namespace rawrxd {

// Simple regex-based parser (stub - replace with tree-sitter in production)
class SimpleASTParser {
public:
    struct ParsedFile {
        std::string file_path;
        std::string content;
        std::vector<SymbolContext> symbols;
        std::chrono::steady_clock::time_point parse_time;
    };
    
    ParsedFile parse(const std::string& file_path, const std::string& content) {
        ParsedFile result;
        result.file_path = file_path;
        result.content = content;
        result.parse_time = std::chrono::steady_clock::now();
        
        // Simple regex-based symbol extraction
        extract_functions(content, result.symbols);
        extract_variables(content, result.symbols);
        extract_classes(content, result.symbols);
        
        return result;
    }
    
private:
    void extract_functions(const std::string& content, std::vector<SymbolContext>& symbols) {
        // Pattern: return_type function_name(params) {
        std::regex func_regex(R"((\w+[\s\*\&]+)(\w+)\s*\([^)]*\)\s*\{?)");
        std::smatch match;
        
        std::string::const_iterator search_start(content.cbegin());
        int line = 1;
        size_t last_pos = 0;
        
        while (std::regex_search(search_start, content.cend(), match, func_regex)) {
            // Calculate line number
            size_t pos = match.position();
            for (size_t i = last_pos; i < pos; ++i) {
                if (content[i] == '\n') ++line;
            }
            last_pos = pos;
            
            SymbolContext sym;
            sym.name = match[2].str();
            sym.type = match[1].str();
            sym.scope = "global";
            sym.line_number = line;
            sym.column = static_cast<int>(match.position());
            sym.kind = SymbolKind::FUNCTION;
            
            symbols.push_back(sym);
            search_start = match.suffix().first;
        }
    }
    
    void extract_variables(const std::string& content, std::vector<SymbolContext>& symbols) {
        // Pattern: type var_name;
        std::regex var_regex(R"((\w+[\s\*\*&]+)(\w+)\s*;)");
        std::smatch match;
        
        std::string::const_iterator search_start(content.cbegin());
        int line = 1;
        size_t last_pos = 0;
        
        while (std::regex_search(search_start, content.cend(), match, var_regex)) {
            size_t pos = match.position();
            for (size_t i = last_pos; i < pos; ++i) {
                if (content[i] == '\n') ++line;
            }
            last_pos = pos;
            
            SymbolContext sym;
            sym.name = match[2].str();
            sym.type = match[1].str();
            sym.scope = "global";
            sym.line_number = line;
            sym.column = static_cast<int>(match.position());
            sym.kind = SymbolKind::VARIABLE;
            
            symbols.push_back(sym);
            search_start = match.suffix().first;
        }
    }
    
    void extract_classes(const std::string& content, std::vector<SymbolContext>& symbols) {
        // Pattern: class ClassName {
        std::regex class_regex(R"(\b(class|struct)\s+(\w+)\s*\{?)");
        std::smatch match;
        
        std::string::const_iterator search_start(content.cbegin());
        int line = 1;
        size_t last_pos = 0;
        
        while (std::regex_search(search_start, content.cend(), match, class_regex)) {
            size_t pos = match.position();
            for (size_t i = last_pos; i < pos; ++i) {
                if (content[i] == '\n') ++line;
            }
            last_pos = pos;
            
            SymbolContext sym;
            sym.name = match[2].str();
            sym.type = match[1].str();
            sym.scope = "global";
            sym.line_number = line;
            sym.column = static_cast<int>(match.position());
            sym.kind = (match[1].str() == "class") ? SymbolKind::CLASS : SymbolKind::STRUCT;
            
            symbols.push_back(sym);
            search_start = match.suffix().first;
        }
    }
};

// PIMPL implementation
struct ASTContextProvider::Impl {
    ASTParserConfig config;
    SimpleASTParser parser;
    std::unordered_map<std::string, SimpleASTParser::ParsedFile> cache;
    
    explicit Impl(const ASTParserConfig& cfg) : config(cfg) {}
};

// Constructor
ASTContextProvider::ASTContextProvider(const ASTParserConfig& config)
    : m_impl(std::make_unique<Impl>(config))
    , m_config(config) {
}

// Destructor
ASTContextProvider::~ASTContextProvider() = default;

// Move constructor
ASTContextProvider::ASTContextProvider(ASTContextProvider&& other) noexcept
    : m_impl(std::move(other.m_impl))
    , m_config(other.m_config) {
}

// Move assignment
ASTContextProvider& ASTContextProvider::operator=(ASTContextProvider&& other) noexcept {
    if (this != &other) {
        m_impl = std::move(other.m_impl);
        m_config = other.m_config;
    }
    return *this;
}

bool ASTContextProvider::parse_file(const std::string& file_path, const std::string& content) {
    if (!m_impl) return false;
    
    auto start = std::chrono::steady_clock::now();
    auto parsed = m_impl->parser.parse(file_path, content);
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    // Check if parse time exceeded budget
    if (elapsed_ms > m_config.max_parse_time_ms) {
        // Log warning: parse took too long
    }
    
    // Cache the result
    m_impl->cache[file_path] = std::move(parsed);
    
    // Trim cache if too large
    if (m_impl->cache.size() > m_config.max_cache_size) {
        // Remove oldest entry
        auto oldest = m_impl->cache.begin();
        for (auto it = m_impl->cache.begin(); it != m_impl->cache.end(); ++it) {
            if (it->second.parse_time < oldest->second.parse_time) {
                oldest = it;
            }
        }
        m_impl->cache.erase(oldest);
    }
    
    return true;
}

std::vector<SymbolContext> ASTContextProvider::get_symbols_at_cursor(const CursorPosition& cursor) {
    std::vector<SymbolContext> results;
    
    if (!m_impl) return results;
    
    auto it = m_impl->cache.find(cursor.file_path);
    if (it == m_impl->cache.end()) {
        return results;
    }
    
    // Return symbols from the same file (simplified - real implementation would filter by scope)
    for (const auto& sym : it->second.symbols) {
        if (std::abs(sym.line_number - cursor.line) < 50) {  // Within 50 lines
            results.push_back(sym);
        }
    }
    
    return results;
}

std::string ASTContextProvider::get_symbol_type(const std::string& symbol_name, 
                                                 const CursorPosition& cursor) {
    if (!m_impl) return "";
    
    auto it = m_impl->cache.find(cursor.file_path);
    if (it == m_impl->cache.end()) {
        return "";
    }
    
    for (const auto& sym : it->second.symbols) {
        if (sym.name == symbol_name) {
            return sym.type;
        }
    }
    
    return "";
}

std::vector<CursorPosition> ASTContextProvider::find_references(const std::string& symbol_name) {
    std::vector<CursorPosition> results;
    
    if (!m_impl) return results;
    
    // Search in all cached files
    for (const auto& [file_path, parsed] : m_impl->cache) {
        // Simple text search for references
        size_t pos = 0;
        while ((pos = parsed.content.find(symbol_name, pos)) != std::string::npos) {
            // Calculate line number
            int line = 1;
            for (size_t i = 0; i < pos; ++i) {
                if (parsed.content[i] == '\n') ++line;
            }
            
            CursorPosition ref;
            ref.file_path = file_path;
            ref.line = line;
            ref.column = static_cast<int>(pos);
            results.push_back(ref);
            
            pos += symbol_name.length();
        }
    }
    
    return results;
}

std::string ASTContextProvider::get_current_scope(const CursorPosition& cursor) {
    if (!m_impl) return "";
    
    auto it = m_impl->cache.find(cursor.file_path);
    if (it == m_impl->cache.end()) {
        return "";
    }
    
    // Find the innermost scope containing the cursor
    std::string scope = "global";
    int closest_line = 0;
    
    for (const auto& sym : it->second.symbols) {
        if (sym.kind == SymbolKind::FUNCTION || sym.kind == SymbolKind::CLASS) {
            if (sym.line_number <= cursor.line && sym.line_number > closest_line) {
                scope = sym.name;
                closest_line = sym.line_number;
            }
        }
    }
    
    return scope;
}

bool ASTContextProvider::has_file(const std::string& file_path) const {
    if (!m_impl) return false;
    return m_impl->cache.find(file_path) != m_impl->cache.end();
}

void ASTContextProvider::invalidate_file(const std::string& file_path) {
    if (!m_impl) return;
    m_impl->cache.erase(file_path);
}

void ASTContextProvider::clear_cache() {
    if (!m_impl) return;
    m_impl->cache.clear();
}

} // namespace rawrxd