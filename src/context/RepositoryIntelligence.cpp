// ============================================================================
// RepositoryIntelligence.cpp — Semantic context retrieval implementation
// Phase 15 — Unification Layer
// ============================================================================

#include "RepositoryIntelligence.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <filesystem>
#include <algorithm>
#include <math>

namespace fs = std::filesystem;

namespace RawrXD {

// ============================================================================
// SymbolGraph Implementation
// ============================================================================
void SymbolGraph::AddSymbol(const CodeSymbol& symbol) {
    symbols_[symbol.qualifiedName] = symbol;
}

void SymbolGraph::AddReference(const std::string& from, const std::string& to) {
    references_[from].push_back(to);
}

void SymbolGraph::AddDependency(const std::string& from, const std::string& to) {
    dependencies_[from].push_back(to);
}

std::vector<CodeSymbol> SymbolGraph::FindRelated(const std::string& symbolName, uint32_t maxDepth) {
    std::vector<CodeSymbol> related;
    std::unordered_set<std::string> visited;
    std::vector<std::string> toVisit = {symbolName};
    
    for (uint32_t depth = 0; depth < maxDepth && !toVisit.empty(); ++depth) {
        std::vector<std::string> nextLevel;
        
        for (const auto& name : toVisit) {
            if (visited.find(name) != visited.end()) continue;
            visited.insert(name);
            
            auto it = symbols_.find(name);
            if (it != symbols_.end()) {
                related.push_back(it->second);
            }
            
            // Add dependencies and references to next level
            auto depIt = dependencies_.find(name);
            if (depIt != dependencies_.end()) {
                nextLevel.insert(nextLevel.end(), depIt->second.begin(), depIt->second.end());
            }
            
            auto refIt = references_.find(name);
            if (refIt != references_.end()) {
                nextLevel.insert(nextLevel.end(), refIt->second.begin(), refIt->second.end());
            }
        }
        
        toVisit = std::move(nextLevel);
    }
    
    return related;
}

std::vector<CodeSymbol> SymbolGraph::FindDependents(const std::string& symbolName) {
    std::vector<CodeSymbol> dependents;
    
    for (const auto& [name, refs] : references_) {
        if (std::find(refs.begin(), refs.end(), symbolName) != refs.end()) {
            auto it = symbols_.find(name);
            if (it != symbols_.end()) {
                dependents.push_back(it->second);
            }
        }
    }
    
    return dependents;
}

std::vector<CodeSymbol> SymbolGraph::FindDependencies(const std::string& symbolName) {
    std::vector<CodeSymbol> deps;
    
    auto it = dependencies_.find(symbolName);
    if (it != dependencies_.end()) {
        for (const auto& depName : it->second) {
            auto symIt = symbols_.find(depName);
            if (symIt != symbols_.end()) {
                deps.push_back(symIt->second);
            }
        }
    }
    
    return deps;
}

std::vector<CodeSymbol> SymbolGraph::GetSymbolsInFile(const std::string& filePath) {
    std::vector<CodeSymbol> result;
    
    for (const auto& [name, symbol] : symbols_) {
        if (symbol.filePath == filePath) {
            result.push_back(symbol);
        }
    }
    
    return result;
}

std::vector<CodeSymbol> SymbolGraph::GetSymbolsInScope(const std::string& scope) {
    std::vector<CodeSymbol> result;
    
    for (const auto& [name, symbol] : symbols_) {
        if (symbol.parentScope == scope) {
            result.push_back(symbol);
        }
    }
    
    return result;
}

// ============================================================================
// SemanticIndex Implementation
// ============================================================================
void SemanticIndex::IndexSymbol(const CodeSymbol& symbol) {
    byQualifiedName_[symbol.qualifiedName] = symbol;
    byName_[symbol.name].push_back(&byQualifiedName_[symbol.qualifiedName]);
    byType_[symbol.type].push_back(&byQualifiedName_[symbol.qualifiedName]);
    byFile_[symbol.filePath].push_back(&byQualifiedName_[symbol.qualifiedName]);
}

void SemanticIndex::RemoveFile(const std::string& filePath) {
    auto it = byFile_.find(filePath);
    if (it == byFile_.end()) return;
    
    for (auto* symPtr : it->second) {
        byQualifiedName_.erase(symPtr->qualifiedName);
        // Note: byName_ and byType_ would need cleanup too — simplified
    }
    
    byFile_.erase(it);
}

void SemanticIndex::Clear() {
    byQualifiedName_.clear();
    byName_.clear();
    byType_.clear();
    byFile_.clear();
}

std::vector<CodeSymbol> SemanticIndex::SearchByName(const std::string& query, uint32_t maxResults) {
    std::vector<CodeSymbol> results;
    
    for (const auto& [name, symbols] : byName_) {
        if (name.find(query) != std::string::npos) {
            for (const auto* sym : symbols) {
                results.push_back(*sym);
                if (results.size() >= maxResults) break;
            }
        }
        if (results.size() >= maxResults) break;
    }
    
    return results;
}

std::vector<CodeSymbol> SemanticIndex::SearchByType(SymbolType type) {
    std::vector<CodeSymbol> results;
    
    auto it = byType_.find(type);
    if (it != byType_.end()) {
        for (const auto* sym : it->second) {
            results.push_back(*sym);
        }
    }
    
    return results;
}

std::vector<CodeSymbol> SemanticIndex::SearchInFile(const std::string& filePath) {
    std::vector<CodeSymbol> results;
    
    auto it = byFile_.find(filePath);
    if (it != byFile_.end()) {
        for (const auto* sym : it->second) {
            results.push_back(*sym);
        }
    }
    
    return results;
}

std::vector<CodeSymbol> SemanticIndex::SearchBySignature(const std::string& signature) {
    std::vector<CodeSymbol> results;
    
    for (const auto& [name, symbol] : byQualifiedName_) {
        if (symbol.signature.find(signature) != std::string::npos) {
            results.push_back(symbol);
        }
    }
    
    return results;
}

std::vector<CodeSymbol> SemanticIndex::FuzzySearch(const std::string& query, float threshold) {
    std::vector<CodeSymbol> results;
    
    for (const auto& [name, symbol] : byQualifiedName_) {
        float score = FuzzyMatchScore(query, name);
        if (score >= threshold) {
            results.push_back(symbol);
        }
    }
    
    // Sort by score
    std::sort(results.begin(), results.end(), [](const CodeSymbol& a, const CodeSymbol& b) {
        return a.relevanceScore > b.relevanceScore;
    });
    
    return results;
}

bool SemanticIndex::FindByQualifiedName(const std::string& qualifiedName, CodeSymbol& out) {
    auto it = byQualifiedName_.find(qualifiedName);
    if (it == byQualifiedName_.end()) return false;
    
    out = it->second;
    return true;
}

float SemanticIndex::FuzzyMatchScore(const std::string& query, const std::string& target) {
    // Simple fuzzy matching — could use Levenshtein or better
    if (target.find(query) != std::string::npos) return 1.0f;
    
    // Check if all chars in query appear in order in target
    size_t qIdx = 0;
    for (char c : target) {
        if (qIdx < query.length() && tolower(c) == tolower(query[qIdx])) {
            qIdx++;
        }
    }
    
    return (qIdx == query.length()) ? 0.5f : 0.0f;
}

// ============================================================================
// ContextRetriever Implementation
// ============================================================================
void ContextRetriever::Initialize(SemanticIndex* index, SymbolGraph* graph) {
    index_ = index;
    graph_ = graph;
}

ContextResult ContextRetriever::RetrieveContext(
    const std::string& query,
    const std::string& currentFile,
    uint32_t cursorLine,
    size_t maxTokens
) {
    ContextResult result;
    
    // Step 1: Find symbols matching query
    auto symbols = index_->SearchByName(query, 20);
    
    // Step 2: Add symbols from current file
    auto fileSymbols = index_->SearchInFile(currentFile);
    symbols.insert(symbols.end(), fileSymbols.begin(), fileSymbols.end());
    
    // Step 3: Rank by relevance
    auto ranked = RankByRelevance(symbols, query, currentFile);
    
    // Step 4: Format for prompt
    result.contextText = FormatSymbolsForPrompt(ranked, maxTokens);
    result.symbols = ranked;
    result.tokenCount = EstimateTokens(result.contextText);
    result.truncated = result.tokenCount > maxTokens;
    
    return result;
}

ContextResult ContextRetriever::RetrieveForCompletion(
    const std::string& prefix,
    const std::string& filePath,
    uint32_t line,
    size_t maxTokens
) {
    ContextResult result;
    
    // Extract identifiers from prefix
    std::vector<std::string> identifiers = ExtractIdentifiers(prefix);
    
    // Find symbols for each identifier
    std::vector<CodeSymbol> relevant;
    for (const auto& id : identifiers) {
        auto found = index_->SearchByName(id, 5);
        relevant.insert(relevant.end(), found.begin(), found.end());
    }
    
    // Add symbols from current scope
    auto scopeSymbols = index_->SearchInFile(filePath);
    relevant.insert(relevant.end(), scopeSymbols.begin(), scopeSymbols.end());
    
    // Deduplicate and rank
    auto ranked = RankByRelevance(relevant, prefix, filePath);
    
    // Build context
    std::stringstream ctx;
    ctx << "// Relevant symbols from codebase:\n";
    for (const auto& sym : ranked) {
        if (sym.type == SymbolType::Function || sym.type == SymbolType::Method) {
            ctx << "// " << sym.signature << "\n";
        } else if (sym.type == SymbolType::Class || sym.type == SymbolType::Struct) {
            ctx << "// class " << sym.name << "\n";
        }
    }
    ctx << "\n";
    
    result.contextText = ctx.str();
    result.symbols = ranked;
    result.tokenCount = EstimateTokens(result.contextText);
    
    return result;
}

ContextResult ContextRetriever::RetrieveForExplanation(
    const std::string& symbolName,
    size_t maxTokens
) {
    ContextResult result;
    
    CodeSymbol symbol;
    if (!index_->FindByQualifiedName(symbolName, symbol)) {
        // Try fuzzy search
        auto matches = index_->FuzzySearch(symbolName, 0.8f);
        if (!matches.empty()) {
            symbol = matches[0];
        }
    }
    
    if (symbol.name.empty()) {
        result.contextText = "Symbol not found: " + symbolName;
        return result;
    }
    
    // Get related symbols
    auto related = graph_->FindRelated(symbol.qualifiedName, 2);
    
    // Build explanation context
    std::stringstream ctx;
    ctx << "Symbol: " << symbol.qualifiedName << "\n";
    ctx << "Type: " <> static_cast<int>(symbol.type) << "\n";
    ctx << "Location: " << symbol.filePath << ":" << symbol.lineStart << "\n";
    if (!symbol.signature.empty()) {
        ctx << "Signature: " << symbol.signature << "\n";
    }
    if (!symbol.docComment.empty()) {
        ctx << "Documentation:\n" << symbol.docComment << "\n";
    }
    ctx << "\nRelated symbols:\n";
    for (const auto& rel : related) {
        ctx << "  - " << rel.qualifiedName << "\n";
    }
    
    result.contextText = ctx.str();
    result.symbols = related;
    result.tokenCount = EstimateTokens(result.contextText);
    
    return result;
}

ContextResult ContextRetriever::RetrieveForDebugging(
    const std::string& errorMessage,
    const std::string& filePath,
    uint32_t line,
    size_t maxTokens
) {
    ContextResult result;
    
    // Extract symbol names from error message
    std::vector<std::string> errorSymbols = ExtractIdentifiers(errorMessage);
    
    // Get symbols from error location
    auto locationSymbols = index_->SearchInFile(filePath);
    
    // Filter to symbols near error line
    std::vector<CodeSymbol> nearby;
    for (const auto& sym : locationSymbols) {
        if (std::abs(static_cast<int>(sym.lineStart) - static_cast<int>(line)) < 10) {
            nearby.push_back(sym);
        }
    }
    
    // Build debug context
    std::stringstream ctx;
    ctx << "Error: " << errorMessage << "\n";
    ctx << "Location: " << filePath << ":" << line << "\n\n";
    ctx << "Nearby symbols:\n";
    for (const auto& sym : nearby) {
        ctx << "  " << sym.name;
        if (!sym.signature.empty()) {
            ctx << " — " << sym.signature;
        }
        ctx << "\n";
    }
    
    result.contextText = ctx.str();
    result.symbols = nearby;
    result.tokenCount = EstimateTokens(result.contextText);
    
    return result;
}

std::vector<CodeSymbol> ContextRetriever::RankByRelevance(
    const std::vector<CodeSymbol>& symbols,
    const std::string& query,
    const std::string& currentFile
) {
    std::vector<CodeSymbol> ranked = symbols;
    
    // Score and sort
    for (auto& sym : ranked) {
        float score = 0.0f;
        
        // Same file bonus
        if (sym.filePath == currentFile) score += 2.0f;
        
        // Name match bonus
        if (sym.name.find(query) != std::string::npos) score += 1.0f;
        
        // Usage count bonus
        score += std::min(sym.usageCount / 100.0f, 1.0f);
        
        // Prefer functions and classes
        if (sym.type == SymbolType::Function || sym.type == SymbolType::Method) score += 0.5f;
        if (sym.type == SymbolType::Class) score += 0.3f;
        
        sym.relevanceScore = score;
    }
    
    std::sort(ranked.begin(), ranked.end(), [](const CodeSymbol& a, const CodeSymbol& b) {
        return a.relevanceScore > b.relevanceScore;
    });
    
    // Deduplicate
    std::vector<CodeSymbol> unique;
    std::unordered_set<std::string> seen;
    for (const auto& sym : ranked) {
        if (seen.find(sym.qualifiedName) == seen.end()) {
            seen.insert(sym.qualifiedName);
            unique.push_back(sym);
        }
    }
    
    return unique;
}

std::string ContextRetriever::FormatSymbolsForPrompt(
    const std::vector<CodeSymbol>& symbols,
    size_t maxTokens
) {
    std::stringstream prompt;
    size_t currentTokens = 0;
    
    for (const auto& sym : symbols) {
        std::string entry;
        
        switch (sym.type) {
            case SymbolType::Function:
            case SymbolType::Method:
                entry = sym.signature + ";\n";
                break;
            case SymbolType::Class:
            case SymbolType::Struct:
                entry = "class " + sym.name + ";\n";
                break;
            case SymbolType::Variable:
                entry = sym.returnType + " " + sym.name + ";\n";
                break;
            default:
                entry = "// " + sym.name + "\n";
        }
        
        size_t entryTokens = entry.length() / 4; // Rough estimate
        if (currentTokens + entryTokens > maxTokens) break;
        
        prompt << entry;
        currentTokens += entryTokens;
    }
    
    return prompt.str();
}

std::vector<std::string> ContextRetriever::ExtractIdentifiers(const std::string& text) {
    std::vector<std::string> identifiers;
    std::regex idRegex("[a-zA-Z_][a-zA-Z0-9_]*");
    
    auto wordsBegin = std::sregex_iterator(text.begin(), text.end(), idRegex);
    auto wordsEnd = std::sregex_iterator();
    
    for (auto it = wordsBegin; it != wordsEnd; ++it) {
        identifiers.push_back(it->str());
    }
    
    return identifiers;
}

size_t ContextRetriever::EstimateTokens(const std::string& text) {
    // Rough estimate: 1 token ≈ 4 characters
    return text.length() / 4;
}

// ============================================================================
// ASTIndexer Implementation
// ============================================================================
std::vector<CodeSymbol> ASTIndexer::IndexFile(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file) return {};
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    std::string ext = fs::path(filePath).extension().string();
    
    if (ext == ".cpp" || ext == ".cxx" || ext == ".cc" || ext == ".h" || ext == ".hpp") {
        return ParseCpp(content, filePath);
    } else if (ext == ".py") {
        return ParsePython(content, filePath);
    } else if (ext == ".js" || ext == ".ts") {
        return ParseJavaScript(content, filePath);
    } else if (ext == ".rs") {
        return ParseRust(content, filePath);
    } else {
        return ParseGeneric(content, filePath);
    }
}

void ASTIndexer::IndexDirectory(
    const std::string& dirPath,
    std::function<void(const std::string& file)> progress
) {
    for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
        if (entry.is_regular_file() && CanIndex(entry.path().string())) {
            if (progress) progress(entry.path().string());
            IndexFile(entry.path().string());
        }
    }
}

bool ASTIndexer::CanIndex(const std::string& filePath) {
    std::string ext = fs::path(filePath).extension().string();
    static const std::vector<std::string> supported = {
        ".cpp", ".cxx", ".cc", ".h", ".hpp",
        ".c",
        ".py",
        ".js", ".ts",
        ".rs",
        ".go",
        ".java",
        ".cs",
        ".swift",
        ".kt"
    };
    return std::find(supported.begin(), supported.end(), ext) != supported.end();
}

std::vector<std::string> ASTIndexer::GetSupportedLanguages() {
    return {"C++", "C", "Python", "JavaScript", "TypeScript", "Rust", "Go", "Java", "C#", "Swift", "Kotlin"};
}

std::vector<CodeSymbol> ASTIndexer::ParseCpp(const std::string& content, const std::string& filePath) {
    std::vector<CodeSymbol> symbols;
    
    // Regex-based parsing — real implementation would use libclang
    std::regex classRegex("class\\s+(\\w+)");
    std::regex funcRegex("(\\w+[\\s\\*]+)+(\\w+)\\s*\\(([^)]*)\\)");
    std::regex methodRegex("(\\w+)::(\\w+)\\s*\\(");
    
    std::istringstream stream(content);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        std::smatch match;
        if (std::regex_search(line, match, classRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.qualifiedName = match[1];
            sym.type = SymbolType::Class;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
        
        if (std::regex_search(line, match, funcRegex)) {
            CodeSymbol sym;
            sym.name = match[2];
            sym.qualifiedName = match[2];
            sym.type = SymbolType::Function;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            sym.signature = match[0];
            symbols.push_back(sym);
        }
    }
    
    return symbols;
}

std::vector<CodeSymbol> ASTIndexer::ParsePython(const std::string& content, const std::string& filePath) {
    std::vector<CodeSymbol> symbols;
    
    std::regex funcRegex("def\\s+(\\w+)\\s*\\(([^)]*)\\)");
    std::regex classRegex("class\\s+(\\w+)");
    std::regex importRegex("(import|from)\\s+(\\w+)");
    
    std::istringstream stream(content);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        std::smatch match;
        if (std::regex_search(line, match, funcRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.qualifiedName = match[1];
            sym.type = SymbolType::Function;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            sym.signature = "def " + match[1].str() + "(" + match[2].str() + ")";
            symbols.push_back(sym);
        }
        
        if (std::regex_search(line, match, classRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.qualifiedName = match[1];
            sym.type = SymbolType::Class;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
    }
    
    return symbols;
}

std::vector<CodeSymbol> ASTIndexer::ParseJavaScript(const std::string& content, const std::string& filePath) {
    std::vector<CodeSymbol> symbols;
    
    std::regex funcRegex("(?:function|const|let|var)\\s+(\\w+)\\s*[=\\(]");
    std::regex classRegex("class\\s+(\\w+)");
    std::regex methodRegex("(\\w+)\\s*\\(([^)]*)\\)\\s*{");
    
    std::istringstream stream(content);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        std::smatch match;
        if (std::regex_search(line, match, funcRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.type = SymbolType::Function;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
        
        if (std::regex_search(line, match, classRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.type = SymbolType::Class;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
    }
    
    return symbols;
}

std::vector<CodeSymbol> ASTIndexer::ParseRust(const std::string& content, const std::string& filePath) {
    std::vector<CodeSymbol> symbols;
    
    std::regex funcRegex("fn\\s+(\\w+)");
    std::regex structRegex("struct\\s+(\\w+)");
    std::regex implRegex("impl\\s+(?:<[^]>+>\\s+)?(\\w+)");
    
    std::istringstream stream(content);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        std::smatch match;
        if (std::regex_search(line, match, funcRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.type = SymbolType::Function;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
        
        if (std::regex_search(line, match, structRegex)) {
            CodeSymbol sym;
            sym.name = match[1];
            sym.type = SymbolType::Struct;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
    }
    
    return symbols;
}

std::vector<CodeSymbol> ASTIndexer::ParseGeneric(const std::string& content, const std::string& filePath) {
    // Fallback: extract words that look like identifiers
    std::vector<CodeSymbol> symbols;
    std::regex wordRegex("\\b[A-Z][a-zA-Z0-9]*\\b"); // Capitalized words (likely types)
    
    std::istringstream stream(content);
    std::string line;
    uint32_t lineNum = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        std::sregex_iterator iter(line.begin(), line.end(), wordRegex);
        std::sregex_iterator end;
        
        for (; iter != end; ++iter) {
            CodeSymbol sym;
            sym.name = iter->str();
            sym.type = SymbolType::Unknown;
            sym.filePath = filePath;
            sym.lineStart = lineNum;
            symbols.push_back(sym);
        }
    }
    
    return symbols;
}

// ============================================================================
// RepositoryIntelligence Implementation
// ============================================================================
RepositoryIntelligence::RepositoryIntelligence() = default;
RepositoryIntelligence::~RepositoryIntelligence() = default;

bool RepositoryIntelligence::Initialize(const std::string& repoPath) {
    repoPath_ = repoPath;
    
    // Initialize retriever
    retriever_.Initialize(&index_, &graph_);
    
    // Build index
    BuildIndex();
    
    ready_ = true;
    return true;
}

void RepositoryIntelligence::BuildIndex() {
    indexer_.IndexDirectory(repoPath_, [this](const std::string& file) {
        auto symbols = indexer_.IndexFile(file);
        for (const auto& sym : symbols) {
            index_.IndexSymbol(sym);
            graph_.AddSymbol(sym);
        }
    });
}

void RepositoryIntelligence::UpdateFile(const std::string& filePath) {
    index_.RemoveFile(filePath);
    auto symbols = indexer_.IndexFile(filePath);
    for (const auto& sym : symbols) {
        index_.IndexSymbol(sym);
        graph_.AddSymbol(sym);
    }
}

void RepositoryIntelligence::RemoveFile(const std::string& filePath) {
    index_.RemoveFile(filePath);
}

std::string RepositoryIntelligence::GetStatus() const {
    std::stringstream ss;
    ss << "RepositoryIntelligence: " << (ready_ ? "READY" : "NOT READY")
       << " | Symbols: " << GetIndexedSymbolCount()
       << " | Path: " << repoPath_;
    return ss.str();
}

size_t RepositoryIntelligence::GetIndexedSymbolCount() const {
    // Would need to expose this from index
    return 0; // Placeholder
}

void RepositoryIntelligence::SaveIndex(const std::string& path) {
    // Serialize index to file
    // Implementation would use JSON or binary format
}

bool RepositoryIntelligence::LoadIndex(const std::string& path) {
    // Deserialize index from file
    return false; // Placeholder
}

} // namespace RawrXD
