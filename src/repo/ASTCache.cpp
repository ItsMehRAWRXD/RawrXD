// ============================================================================
// ASTCache.cpp - Abstract Syntax Tree Caching
// WORKING IMPLEMENTATION
// ============================================================================

#include "ASTCache.hpp"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <functional>
#include <set>
#include <unordered_set>

namespace RawrXD {
namespace IDE {

// ============================================================================
// AST Node Implementation
// ============================================================================

ASTNode::ASTNode(NodeKind kind, const std::string& name, size_t line, size_t column)
    : kind(kind), name(name), line(line), column(column) {}

void ASTNode::AddChild(std::shared_ptr<ASTNode> child) {
    child->parent = shared_from_this();
    children.push_back(child);
}

void ASTNode::AddAttribute(const std::string& key, const std::string& value) {
    attributes[key] = value;
}

std::string ASTNode::GetAttribute(const std::string& key) const {
    auto it = attributes.find(key);
    return (it != attributes.end()) ? it->second : "";
}

// ============================================================================
// AST Cache Implementation
// ============================================================================

struct ASTCache::Impl {
    // File path -> AST root
    std::unordered_map<std::string, std::shared_ptr<ASTNode>> asts_;
    
    // Symbol name -> nodes (for quick lookup)
    std::unordered_map<std::string, std::vector<std::weak_ptr<ASTNode>>> symbolIndex_;
    
    // File modification times
    std::unordered_map<std::string, std::filesystem::file_time_type> timestamps_;
    
    // Statistics
    size_t cacheHits_ = 0;
    size_t cacheMisses_ = 0;
    
    mutable std::shared_mutex mutex_;
    
    // Simple C++ tokenizer for parsing
    std::vector<Token> Tokenize(const std::string& content);
    std::shared_ptr<ASTNode> ParseTokens(const std::vector<Token>& tokens, 
                                            const std::string& filePath);
};

ASTCache::ASTCache() : impl_(std::make_unique<Impl>()) {}
ASTCache::~ASTCache() = default;

std::vector<Token> ASTCache::Impl::Tokenize(const std::string& content) {
    std::vector<Token> tokens;
    size_t line = 1;
    size_t column = 1;
    size_t i = 0;
    
    static const std::unordered_set<std::string> keywords = {
        "class", "struct", "enum", "namespace", "template",
        "public", "private", "protected", "virtual", "static",
        "const", "constexpr", "inline", "void", "int", "float",
        "double", "bool", "char", "auto", "using", "typedef",
        "if", "else", "for", "while", "do", "switch", "case",
        "return", "new", "delete", "try", "catch", "throw"
    };
    
    while (i < content.size()) {
        char c = content[i];
        
        // Whitespace
        if (isspace(c)) {
            if (c == '\n') { line++; column = 1; }
            else { column++; }
            i++;
            continue;
        }
        
        // Comments
        if (c == '/' && i + 1 < content.size()) {
            if (content[i + 1] == '/') {
                // Line comment
                size_t start = i;
                while (i < content.size() && content[i] != '\n') i++;
                tokens.push_back({Token::Comment, content.substr(start, i - start), line, column});
                column += (i - start);
                continue;
            } else if (content[i + 1] == '*') {
                // Block comment
                size_t start = i;
                i += 2;
                while (i + 1 < content.size() && !(content[i] == '*' && content[i + 1] == '/')) {
                    if (content[i] == '\n') { line++; column = 1; }
                    else { column++; }
                    i++;
                }
                i += 2;
                tokens.push_back({Token::Comment, content.substr(start, i - start), line, column});
                continue;
            }
        }
        
        // Preprocessor
        if (c == '#') {
            size_t start = i;
            while (i < content.size() && content[i] != '\n') i++;
            tokens.push_back({Token::Preprocessor, content.substr(start, i - start), line, column});
            column = 1;
            continue;
        }
        
        // String literals
        if (c == '"' || c == '\'') {
            size_t start = i;
            char quote = c;
            i++;
            while (i < content.size() && content[i] != quote) {
                if (content[i] == '\\' && i + 1 < content.size()) i++;
                i++;
            }
            if (i < content.size()) i++;
            tokens.push_back({Token::String, content.substr(start, i - start), line, column});
            column += (i - start);
            continue;
        }
        
        // Numbers
        if (isdigit(c) || (c == '.' && i + 1 < content.size() && isdigit(content[i + 1]))) {
            size_t start = i;
            while (i < content.size() && (isdigit(content[i]) || content[i] == '.' || 
                   content[i] == 'e' || content[i] == 'E' || content[i] == 'f' ||
                   content[i] == 'x' || content[i] == 'X' || 
                   (content[i] >= 'a' && content[i] <= 'f') ||
                   (content[i] >= 'A' && content[i] <= 'F'))) {
                i++;
            }
            tokens.push_back({Token::Number, content.substr(start, i - start), line, column});
            column += (i - start);
            continue;
        }
        
        // Identifiers and keywords
        if (isalpha(c) || c == '_') {
            size_t start = i;
            while (i < content.size() && (isalnum(content[i]) || content[i] == '_')) i++;
            std::string text = content.substr(start, i - start);
            Token::Type type = keywords.count(text) ? Token::Keyword : Token::Identifier;
            tokens.push_back({type, text, line, column});
            column += (i - start);
            continue;
        }
        
        // Symbols (operators, punctuation)
        size_t start = i;
        i++;
        // Multi-character operators
        if (i < content.size()) {
            std::string twoChar = content.substr(start, 2);
            if (twoChar == "::" || twoChar == "->" || twoChar == "++" || 
                twoChar == "--" || twoChar == "<<" || twoChar == ">>" ||
                twoChar == "==" || twoChar == "!=" || twoChar == "<=" ||
                twoChar == ">=" || twoChar == "&&" || twoChar == "||" ||
                twoChar == "+=" || twoChar == "-=" || twoChar == "*=" ||
                twoChar == "/=" || twoChar == "&=" || twoChar == "|=") {
                i++;
            }
        }
        tokens.push_back({Token::Symbol, content.substr(start, i - start), line, column});
        column += (i - start);
    }
    
    tokens.push_back({Token::End, "", line, column});
    return tokens;
}

std::shared_ptr<ASTNode> ASTCache::Impl::ParseTokens(const std::vector<Token>& tokens,
                                                       const std::string& filePath) {
    auto root = std::make_shared<ASTNode>(ASTNode::TranslationUnit, filePath, 1, 1);
    
    size_t i = 0;
    std::vector<std::shared_ptr<ASTNode>> scopeStack;
    scopeStack.push_back(root);
    
    while (i < tokens.size() && tokens[i].type != Token::End) {
        const Token& tok = tokens[i];
        
        // Skip comments and whitespace
        if (tok.type == Token::Comment || tok.type == Token::Whitespace) {
            i++;
            continue;
        }
        
        // Namespace
        if (tok.type == Token::Keyword && tok.text == "namespace") {
            i++;
            if (i < tokens.size() && tokens[i].type == Token::Identifier) {
                auto ns = std::make_shared<ASTNode>(ASTNode::Namespace, tokens[i].text, 
                                                      tokens[i].line, tokens[i].column);
                scopeStack.back()->AddChild(ns);
                scopeStack.push_back(ns);
                i++;
                
                // Skip to opening brace
                while (i < tokens.size() && tokens[i].text != "{") i++;
                if (i < tokens.size()) i++; // Skip {
            }
        }
        // Class/Struct
        else if (tok.type == Token::Keyword && 
                 (tok.text == "class" || tok.text == "struct")) {
            i++;
            std::string className = "unnamed";
            
            // Skip template parameters
            if (i < tokens.size() && tokens[i].text == "<") {
                int depth = 1;
                i++;
                while (i < tokens.size() && depth > 0) {
                    if (tokens[i].text == "<") depth++;
                    if (tokens[i].text == ">") depth--;
                    i++;
                }
            }
            
            if (i < tokens.size() && tokens[i].type == Token::Identifier) {
                className = tokens[i].text;
                i++;
            }
            
            auto cls = std::make_shared<ASTNode>(ASTNode::Class, className,
                                                   tok.line, tok.column);
            scopeStack.back()->AddChild(cls);
            scopeStack.push_back(cls);
            
            // Skip inheritance
            if (i < tokens.size() && tokens[i].text == ":") {
                while (i < tokens.size() && tokens[i].text != "{") i++;
            }
            
            if (i < tokens.size() && tokens[i].text == "{") i++;
        }
        // Function
        else if (tok.type == Token::Identifier || tok.type == Token::Keyword) {
            // Look ahead for function pattern: type name(...)
            if (i + 1 < tokens.size() && tokens[i + 1].type == Token::Identifier) {
                size_t j = i + 2;
                // Skip template arguments
                if (j < tokens.size() && tokens[j].text == "<") {
                    int depth = 1;
                    j++;
                    while (j < tokens.size() && depth > 0) {
                        if (tokens[j].text == "<") depth++;
                        if (tokens[j].text == ">") depth--;
                        j++;
                    }
                }
                
                if (j < tokens.size() && tokens[j].text == "(") {
                    // It's a function
                    auto func = std::make_shared<ASTNode>(ASTNode::Function, tokens[i + 1].text,
                                                           tokens[i + 1].line, tokens[i + 1].column);
                    func->AddAttribute("returnType", tok.text);
                    scopeStack.back()->AddChild(func);
                    
                    // Skip to function body or semicolon
                    while (j < tokens.size() && tokens[j].text != "{" && tokens[j].text != ";") {
                        j++;
                    }
                    
                    if (j < tokens.size() && tokens[j].text == "{") {
                        scopeStack.push_back(func);
                    }
                    i = j + 1;
                    continue;
                }
            }
            i++;
        }
        // Close scope
        else if (tok.text == "}") {
            if (scopeStack.size() > 1) {
                scopeStack.pop_back();
            }
            i++;
        }
        else {
            i++;
        }
    }
    
    return root;
}

// ============================================================================
// Public API
// ============================================================================

std::shared_ptr<ASTNode> ASTCache::ParseFile(const std::string& filePath) {
    std::shared_lock<std::shared_mutex> readLock(impl_->mutex_);
    
    // Check cache
    auto it = impl_->asts_.find(filePath);
    if (it != impl_->asts_.end()) {
        // Check if file has been modified
        auto tsIt = impl_->timestamps_.find(filePath);
        if (tsIt != impl_->timestamps_.end()) {
            auto currentTime = std::filesystem::last_write_time(filePath);
            if (currentTime == tsIt->second) {
                impl_->cacheHits_++;
                return it->second;
            }
        }
    }
    
    readLock.unlock();
    impl_->cacheMisses_++;
    
    // Parse file
    std::ifstream file(filePath);
    if (!file.is_open()) return nullptr;
    
    std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
    
    auto tokens = impl_->Tokenize(content);
    auto ast = impl_->ParseTokens(tokens, filePath);
    
    // Update cache
    std::unique_lock<std::shared_mutex> writeLock(impl_->mutex_);
    impl_->asts_[filePath] = ast;
    impl_->timestamps_[filePath] = std::filesystem::last_write_time(filePath);
    
    // Index symbols
    std::function<void(std::shared_ptr<ASTNode>)> indexNode = [&](std::shared_ptr<ASTNode> node) {
        if (!node->name.empty()) {
            impl_->symbolIndex_[node->name].push_back(node);
        }
        for (auto& child : node->children) {
            indexNode(child);
        }
    };
    indexNode(ast);
    
    return ast;
}

std::shared_ptr<ASTNode> ASTCache::GetCachedAST(const std::string& filePath) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->asts_.find(filePath);
    if (it != impl_->asts_.end()) {
        impl_->cacheHits_++;
        return it->second;
    }
    
    impl_->cacheMisses_++;
    return nullptr;
}

void ASTCache::Invalidate(const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->asts_.find(filePath);
    if (it != impl_->asts_.end()) {
        // Remove from symbol index
        std::function<void(std::shared_ptr<ASTNode>)> unindexNode = [&](std::shared_ptr<ASTNode> node) {
            if (!node->name.empty()) {
                auto& refs = impl_->symbolIndex_[node->name];
                refs.erase(std::remove_if(refs.begin(), refs.end(),
                    [&](const std::weak_ptr<ASTNode>& wp) {
                        return wp.expired();
                    }), refs.end());
            }
            for (auto& child : node->children) {
                unindexNode(child);
            }
        };
        unindexNode(it->second);
        
        impl_->asts_.erase(it);
        impl_->timestamps_.erase(filePath);
    }
}

void ASTCache::InvalidateAll() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->asts_.clear();
    impl_->symbolIndex_.clear();
    impl_->timestamps_.clear();
}

std::vector<std::shared_ptr<ASTNode>> ASTCache::FindNodesByName(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<ASTNode>> result;
    auto it = impl_->symbolIndex_.find(name);
    if (it != impl_->symbolIndex_.end()) {
        for (auto& weak : it->second) {
            if (auto node = weak.lock()) {
                result.push_back(node);
            }
        }
    }
    return result;
}

std::shared_ptr<ASTNode> ASTCache::FindNodeAtPosition(const std::string& filePath,
                                                        size_t line, size_t column) {
    auto root = GetCachedAST(filePath);
    if (!root) return nullptr;
    
    std::shared_ptr<ASTNode> bestMatch = nullptr;
    size_t bestSize = 0;
    
    std::function<void(std::shared_ptr<ASTNode>)> search = [&](std::shared_ptr<ASTNode> node) {
        // Check if position is within this node's range
        // Simplified: just check if line is after start
        if (node->line <= line) {
            // Calculate rough size (for finding most specific match)
            size_t size = node->children.size();
            if (!bestMatch || size < bestSize) {
                bestMatch = node;
                bestSize = size;
            }
        }
        
        for (auto& child : node->children) {
            search(child);
        }
    };
    
    search(root);
    return bestMatch;
}

std::vector<std::string> ASTCache::GetCachedFiles() {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::string> files;
    for (const auto& [path, _] : impl_->asts_) {
        files.push_back(path);
    }
    return files;
}

ASTCacheStats ASTCache::GetStats() {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    ASTCacheStats stats;
    stats.totalFiles = impl_->asts_.size();
    stats.cacheHits = impl_->cacheHits_;
    stats.cacheMisses = impl_->cacheMisses_;
    
    size_t totalNodes = 0;
    for (const auto& [_, ast] : impl_->asts_) {
        std::function<size_t(std::shared_ptr<ASTNode>)> countNodes = [&](std::shared_ptr<ASTNode> node) -> size_t {
            size_t count = 1;
            for (auto& child : node->children) {
                count += countNodes(child);
            }
            return count;
        };
        totalNodes += countNodes(ast);
    }
    stats.totalNodes = totalNodes;
    
    return stats;
}

} // namespace IDE
} // namespace RawrXD
