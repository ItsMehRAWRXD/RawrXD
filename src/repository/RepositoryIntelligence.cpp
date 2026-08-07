// ============================================================================
// RepositoryIntelligence.cpp — Deep Code Understanding Implementation
// ============================================================================
#include "RepositoryIntelligence.hpp"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <queue>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Repository {

// ============================================================================
// Constructor / Destructor
// ============================================================================
RepositoryIntelligence::RepositoryIntelligence() = default;

RepositoryIntelligence::~RepositoryIntelligence() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool RepositoryIntelligence::Initialize(const std::string& rootPath) {
    m_rootPath = rootPath;
    m_initialized = true;
    
    // Try to load existing index
    std::string indexPath = (fs::path(rootPath) / ".rawrxd" / "repo_index.json").string();
    if (fs::exists(indexPath)) {
        LoadIndex(indexPath);
    }
    
    return true;
}

void RepositoryIntelligence::Shutdown() {
    StopFileWatcher();
    
    // Save index
    if (!m_rootPath.empty()) {
        std::string indexPath = (fs::path(m_rootPath) / ".rawrxd" / "repo_index.json").string();
        SaveIndex(indexPath);
    }
    
    m_initialized = false;
}

// ============================================================================
// Indexing
// ============================================================================
bool RepositoryIntelligence::IndexRepository() {
    if (!m_initialized || m_indexing.exchange(true)) {
        return false;
    }
    
    // Clear existing data
    {
        std::lock_guard<std::mutex> lock(m_dataMutex);
        m_files.clear();
        m_symbols.clear();
    }
    
    // Collect all source files
    std::vector<std::string> sourceFiles;
    std::vector<std::string> extensions = {
        ".cpp", ".c", ".h", ".hpp", ".cc", ".cxx",
        ".py", ".js", ".ts", ".jsx", ".tsx",
        ".java", ".kt", ".scala",
        ".rs", ".go", ".cs", ".swift",
        ".rb", ".php",
        ".asm", ".S", ".s"
    };
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(m_rootPath)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                    // Skip build directories
                    std::string path = entry.path().string();
                    if (path.find("/build/") == std::string::npos &&
                        path.find("/node_modules/") == std::string::npos &&
                        path.find("/.git/") == std::string::npos) {
                        sourceFiles.push_back(path);
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        fprintf(stderr, "[RepoIntelligence] Index error: %s\n", e.what());
    }
    
    // Index each file
    int total = sourceFiles.size();
    int current = 0;
    
    for (const auto& filePath : sourceFiles) {
        current++;
        m_indexProgress = static_cast<float>(current) / total;
        
        if (m_indexCallback) {
            m_indexCallback(filePath, current, total);
        }
        
        IndexFile(filePath);
    }
    
    // Build dependency graph
    BuildDependencyGraph();
    
    m_indexing = false;
    m_indexProgress = 1.0f;
    m_lastIndexTime = std::chrono::system_clock::now();
    
    printf("[RepoIntelligence] Indexed %d files, %zu symbols\n", 
           total, m_symbols.size());
    
    // Start file watcher
    StartFileWatcher();
    
    return true;
}

bool RepositoryIntelligence::IndexFile(const std::string& filePath) {
    FileInfo info;
    if (!ParseFile(filePath, info)) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    // Remove old symbols from this file
    auto it = m_symbols.begin();
    while (it != m_symbols.end()) {
        if (it->second.location.filePath == filePath) {
            it = m_symbols.erase(it);
        } else {
            ++it;
        }
    }
    
    // Add new symbols
    for (const auto& symbol : info.symbols) {
        m_symbols[symbol.qualifiedName] = symbol;
    }
    
    m_files[filePath] = info;
    
    return true;
}

bool RepositoryIntelligence::UpdateFile(const std::string& filePath) {
    return IndexFile(filePath);
}

bool RepositoryIntelligence::RemoveFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    // Remove symbols
    auto it = m_symbols.begin();
    while (it != m_symbols.end()) {
        if (it->second.location.filePath == filePath) {
            it = m_symbols.erase(it);
        } else {
            ++it;
        }
    }
    
    // Remove file info
    m_files.erase(filePath);
    
    return true;
}

// ============================================================================
// Symbol Queries
// ============================================================================
std::vector<Symbol> RepositoryIntelligence::FindSymbol(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<Symbol> results;
    
    // Exact match
    auto it = m_symbols.find(name);
    if (it != m_symbols.end()) {
        results.push_back(it->second);
    }
    
    // Partial match
    for (const auto& [qualifiedName, symbol] : m_symbols) {
        if (symbol.name == name && qualifiedName != name) {
            results.push_back(symbol);
        }
    }
    
    return results;
}

std::vector<Symbol> RepositoryIntelligence::FindSymbolsByType(SymbolType type) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<Symbol> results;
    for (const auto& [name, symbol] : m_symbols) {
        if (symbol.type == type) {
            results.push_back(symbol);
        }
    }
    
    return results;
}

std::vector<Symbol> RepositoryIntelligence::FindSymbolsInFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<Symbol> results;
    for (const auto& [name, symbol] : m_symbols) {
        if (symbol.location.filePath == filePath) {
            results.push_back(symbol);
        }
    }
    
    return results;
}

Symbol RepositoryIntelligence::GetSymbolAtPosition(const std::string& filePath, 
                                                    int line, int column) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    for (const auto& [name, symbol] : m_symbols) {
        if (symbol.location.filePath == filePath &&
            symbol.location.startLine <= line &&
            symbol.location.endLine >= line) {
            return symbol;
        }
    }
    
    return Symbol{};
}

// ============================================================================
// Reference Queries
// ============================================================================
std::vector<SymbolLocation> RepositoryIntelligence::FindReferences(const std::string& symbolName) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<SymbolLocation> results;
    
    auto it = m_symbols.find(symbolName);
    if (it != m_symbols.end()) {
        for (const auto& ref : it->second.references) {
            // Parse reference string (format: "file:line:column")
            SymbolLocation loc;
            size_t pos1 = ref.find(':');
            size_t pos2 = ref.find(':', pos1 + 1);
            if (pos1 != std::string::npos && pos2 != std::string::npos) {
                loc.filePath = ref.substr(0, pos1);
                loc.startLine = std::stoi(ref.substr(pos1 + 1, pos2 - pos1 - 1));
                loc.startColumn = std::stoi(ref.substr(pos2 + 1));
                results.push_back(loc);
            }
        }
    }
    
    return results;
}

std::vector<Symbol> RepositoryIntelligence::FindCallers(const std::string& functionName) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<Symbol> results;
    
    auto it = m_symbols.find(functionName);
    if (it != m_symbols.end()) {
        for (const auto& caller : it->second.calledBy) {
            auto callerIt = m_symbols.find(caller);
            if (callerIt != m_symbols.end()) {
                results.push_back(callerIt->second);
            }
        }
    }
    
    return results;
}

std::vector<Symbol> RepositoryIntelligence::FindCallees(const std::string& functionName) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<Symbol> results;
    
    auto it = m_symbols.find(functionName);
    if (it != m_symbols.end()) {
        for (const auto& callee : it->second.calls) {
            auto calleeIt = m_symbols.find(callee);
            if (calleeIt != m_symbols.end()) {
                results.push_back(calleeIt->second);
            }
        }
    }
    
    return results;
}

// ============================================================================
// Search
// ============================================================================
std::vector<SearchResult> RepositoryIntelligence::Search(const std::string& query) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<SearchResult> results;
    std::string lowerQuery = query;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    
    for (const auto& [name, symbol] : m_symbols) {
        std::string lowerName = symbol.name;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        
        if (lowerName.find(lowerQuery) != std::string::npos) {
            SearchResult result;
            result.symbol = symbol;
            result.relevanceScore = 1.0f;
            result.matchedText = symbol.name;
            results.push_back(result);
        }
    }
    
    // Sort by relevance
    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) {
            return a.relevanceScore > b.relevanceScore;
        });
    
    return results;
}

std::vector<SearchResult> RepositoryIntelligence::SemanticSearch(const std::string& query) {
    // TODO: Implement semantic search using embeddings
    // For now, fall back to text search
    return Search(query);
}

std::vector<SearchResult> RepositoryIntelligence::FindSimilarCode(const std::string& codeSnippet) {
    // TODO: Implement code similarity search
    return {};
}

// ============================================================================
// Dependency Analysis
// ============================================================================
DependencyGraph RepositoryIntelligence::GetDependencyGraph() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return m_dependencies;
}

std::vector<std::string> RepositoryIntelligence::GetDependencies(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    auto it = m_files.find(filePath);
    if (it != m_files.end()) {
        return it->second.dependencies;
    }
    
    return {};
}

std::vector<std::string> RepositoryIntelligence::GetDependents(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::vector<std::string> dependents;
    for (const auto& [path, info] : m_files) {
        if (std::find(info.dependencies.begin(), info.dependencies.end(), filePath) 
            != info.dependencies.end()) {
            dependents.push_back(path);
        }
    }
    
    return dependents;
}

ChangeImpact RepositoryIntelligence::AnalyzeChangeImpact(const std::string& filePath) {
    ChangeImpact impact;
    impact.changedFile = filePath;
    
    // Direct dependencies
    impact.directlyAffectedFiles = GetDependents(filePath);
    
    // Transitive dependencies
    std::set<std::string> visited;
    std::queue<std::string> toVisit;
    
    for (const auto& dep : impact.directlyAffectedFiles) {
        toVisit.push(dep);
    }
    
    while (!toVisit.empty()) {
        std::string current = toVisit.front();
        toVisit.pop();
        
        if (visited.find(current) != visited.end()) continue;
        visited.insert(current);
        
        auto dependents = GetDependents(current);
        for (const auto& dep : dependents) {
            if (visited.find(dep) == visited.end()) {
                impact.transitivelyAffectedFiles.push_back(dep);
                toVisit.push(dep);
            }
        }
    }
    
    // Calculate risk
    impact.estimatedRisk = static_cast<int>(
        std::min(impact.transitivelyAffectedFiles.size() * 5, size_t(100)));
    
    return impact;
}

// ============================================================================
// Context Assembly
// ============================================================================
std::vector<Symbol> RepositoryIntelligence::GetRelevantSymbols(const std::string& query,
                                                                  const std::string& contextFile,
                                                                  int maxSymbols) {
    std::vector<Symbol> results;
    
    // Search for matching symbols
    auto matches = Search(query);
    
    // Score and rank
    for (auto& match : matches) {
        match.relevanceScore = CalculateRelevance(match.symbol, query);
        
        // Boost symbols from context file
        if (match.symbol.location.filePath == contextFile) {
            match.relevanceScore *= 1.5f;
        }
    }
    
    // Sort by relevance
    std::sort(matches.begin(), matches.end(),
        [](const SearchResult& a, const SearchResult& b) {
            return a.relevanceScore > b.relevanceScore;
        });
    
    // Return top N
    for (size_t i = 0; i < std::min(matches.size(), static_cast<size_t>(maxSymbols)); i++) {
        results.push_back(matches[i].symbol);
    }
    
    return results;
}

std::vector<FileInfo> RepositoryIntelligence::GetRelevantFiles(const std::string& query,
                                                               int maxFiles) {
    // TODO: Implement file relevance scoring
    return {};
}

json RepositoryIntelligence::BuildContextForQuery(const std::string& query,
                                                   const std::string& activeFile) {
    json context;
    context["query"] = query;
    context["active_file"] = activeFile;
    
    // Get relevant symbols
    auto symbols = GetRelevantSymbols(query, activeFile, 20);
    context["symbols"] = json::array();
    for (const auto& sym : symbols) {
        json s;
        s["name"] = sym.name;
        s["type"] = SymbolTypeToString(sym.type);
        s["file"] = sym.location.filePath;
        s["line"] = sym.location.startLine;
        s["signature"] = sym.signature;
        context["symbols"].push_back(s);
    }
    
    // Get dependencies of active file
    if (!activeFile.empty()) {
        auto deps = GetDependencies(activeFile);
        context["dependencies"] = deps;
    }
    
    return context;
}

// ============================================================================
// Statistics
// ============================================================================
json RepositoryIntelligence::GetRepositoryStats() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    json stats;
    stats["file_count"] = m_files.size();
    stats["symbol_count"] = m_symbols.size();
    stats["last_indexed"] = std::chrono::system_clock::to_time_t(m_lastIndexTime);
    
    // Language distribution
    std::map<std::string, int> langDist;
    for (const auto& [path, info] : m_files) {
        langDist[info.language]++;
    }
    stats["languages"] = langDist;
    
    return stats;
}

int RepositoryIntelligence::GetFileCount() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return static_cast<int>(m_files.size());
}

int RepositoryIntelligence::GetSymbolCount() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    return static_cast<int>(m_symbols.size());
}

std::map<std::string, int> RepositoryIntelligence::GetLanguageDistribution() const {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    std::map<std::string, int> dist;
    for (const auto& [path, info] : m_files) {
        dist[info.language]++;
    }
    
    return dist;
}

// ============================================================================
// Persistence
// ============================================================================
bool RepositoryIntelligence::SaveIndex(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    json data;
    data["root"] = m_rootPath;
    data["last_indexed"] = std::chrono::system_clock::to_time_t(m_lastIndexTime);
    
    // Save files
    data["files"] = json::array();
    for (const auto& [path, info] : m_files) {
        json file;
        file["path"] = path;
        file["language"] = info.language;
        file["line_count"] = info.lineCount;
        data["files"].push_back(file);
    }
    
    // Save symbols
    data["symbols"] = json::array();
    for (const auto& [name, sym] : m_symbols) {
        json symbol;
        symbol["name"] = sym.name;
        symbol["qualified_name"] = sym.qualifiedName;
        symbol["type"] = SymbolTypeToString(sym.type);
        symbol["file"] = sym.location.filePath;
        symbol["line"] = sym.location.startLine;
        data["symbols"].push_back(symbol);
    }
    
    std::ofstream file(path);
    if (!file) return false;
    
    file << data.dump(2);
    return true;
}

bool RepositoryIntelligence::LoadIndex(const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    
    json data;
    try {
        file >> data;
    } catch (...) {
        return false;
    }
    
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    if (data.contains("root")) {
        m_rootPath = data["root"];
    }
    
    if (data.contains("last_indexed")) {
        m_lastIndexTime = std::chrono::system_clock::from_time_t(
            data["last_indexed"].get<std::time_t>());
    }
    
    // Load symbols
    if (data.contains("symbols") && data["symbols"].is_array()) {
        for (const auto& s : data["symbols"]) {
            Symbol sym;
            sym.name = s.value("name", "");
            sym.qualifiedName = s.value("qualified_name", "");
            sym.type = StringToSymbolType(s.value("type", ""));
            sym.location.filePath = s.value("file", "");
            sym.location.startLine = s.value("line", 0);
            m_symbols[sym.qualifiedName] = sym;
        }
    }
    
    return true;
}

bool RepositoryIntelligence::IsIndexStale() const {
    auto now = std::chrono::system_clock::now();
    auto age = std::chrono::duration_cast<std::chrono::hours>(now - m_lastIndexTime).count();
    return age > 24; // Stale after 24 hours
}

// ============================================================================
// Internal Methods
// ============================================================================
bool RepositoryIntelligence::ParseFile(const std::string& path, FileInfo& info) {
    info.path = path;
    info.language = fs::path(path).extension().string();
    
    // Remove leading dot
    if (!info.language.empty() && info.language[0] == '.') {
        info.language = info.language.substr(1);
    }
    
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    info.lineCount = std::count(content.begin(), content.end(), '\n');
    
    // Extract imports/includes
    std::istringstream stream(content);
    std::string line;
    while (std::getline(stream, line)) {
        // C/C++ includes
        std::regex includeRegex(R"(#include\s*["<]([^">]+)[">])");
        std::smatch match;
        if (std::regex_search(line, match, includeRegex)) {
            info.imports.push_back(match[1]);
        }
        
        // Python imports
        std::regex importRegex(R"((?:from|import)\s+(\S+))");
        if (std::regex_search(line, match, importRegex)) {
            info.imports.push_back(match[1]);
        }
    }
    
    // Extract symbols (simplified)
    ExtractSymbols(info, info.symbols);
    
    return true;
}

bool RepositoryIntelligence::ExtractSymbols(const FileInfo& file, 
                                            std::vector<Symbol>& symbols) {
    std::ifstream f(file.path);
    if (!f) return false;
    
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    
    std::istringstream stream(content);
    std::string line;
    int lineNum = 0;
    
    // Simple regex-based extraction
    std::vector<std::pair<std::regex, SymbolType>> patterns;
    
    if (file.language == "cpp" || file.language == "hpp" || file.language == "h") {
        patterns = {
            {std::regex(R"((\w+)\s*\([^)]*\)\s*\{)"), SymbolType::Function},
            {std::regex(R"(class\s+(\w+))"), SymbolType::Class},
            {std::regex(R"(struct\s+(\w+))"), SymbolType::Struct},
            {std::regex(R"(namespace\s+(\w+))"), SymbolType::Namespace},
        };
    } else if (file.language == "py") {
        patterns = {
            {std::regex(R"(def\s+(\w+)\s*\()"), SymbolType::Function},
            {std::regex(R"(class\s+(\w+))"), SymbolType::Class},
        };
    }
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        for (const auto& [pattern, type] : patterns) {
            std::smatch match;
            if (std::regex_search(line, match, pattern)) {
                Symbol sym;
                sym.name = match[1];
                sym.qualifiedName = sym.name;
                sym.type = type;
                sym.location.filePath = file.path;
                sym.location.startLine = lineNum;
                sym.signature = line;
                symbols.push_back(sym);
            }
        }
    }
    
    return true;
}

bool RepositoryIntelligence::BuildDependencyGraph() {
    std::lock_guard<std::mutex> lock(m_dataMutex);
    
    m_dependencies.fileDependencies.clear();
    
    for (const auto& [path, info] : m_files) {
        for (const auto& imp : info.imports) {
            // Try to resolve import to file
            for (const auto& [otherPath, otherInfo] : m_files) {
                if (otherPath.find(imp) != std::string::npos ||
                    imp.find(fs::path(otherPath).filename().string()) != std::string::npos) {
                    m_dependencies.fileDependencies[path].insert(otherPath);
                }
            }
        }
    }
    
    return true;
}

float RepositoryIntelligence::CalculateRelevance(const Symbol& symbol, 
                                                const std::string& query) {
    float score = 0.0f;
    
    std::string lowerQuery = query;
    std::string lowerName = symbol.name;
    std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    
    // Exact match
    if (lowerName == lowerQuery) {
        score += 1.0f;
    }
    // Prefix match
    else if (lowerName.find(lowerQuery) == 0) {
        score += 0.8f;
    }
    // Contains
    else if (lowerName.find(lowerQuery) != std::string::npos) {
        score += 0.5f;
    }
    
    // Boost functions
    if (symbol.type == SymbolType::Function) {
        score += 0.1f;
    }
    
    return score;
}

std::string RepositoryIntelligence::SymbolTypeToString(SymbolType type) {
    switch (type) {
        case SymbolType::Function: return "function";
        case SymbolType::Method: return "method";
        case SymbolType::Class: return "class";
        case SymbolType::Struct: return "struct";
        case SymbolType::Interface: return "interface";
        case SymbolType::Enum: return "enum";
        case SymbolType::Variable: return "variable";
        case SymbolType::Constant: return "constant";
        case SymbolType::Namespace: return "namespace";
        case SymbolType::Module: return "module";
        case SymbolType::Import: return "import";
        case SymbolType::Macro: return "macro";
        case SymbolType::TypeAlias: return "typealias";
        default: return "unknown";
    }
}

SymbolType RepositoryIntelligence::StringToSymbolType(const std::string& str) {
    if (str == "function") return SymbolType::Function;
    if (str == "method") return SymbolType::Method;
    if (str == "class") return SymbolType::Class;
    if (str == "struct") return SymbolType::Struct;
    if (str == "interface") return SymbolType::Interface;
    if (str == "enum") return SymbolType::Enum;
    if (str == "variable") return SymbolType::Variable;
    if (str == "constant") return SymbolType::Constant;
    if (str == "namespace") return SymbolType::Namespace;
    if (str == "module") return SymbolType::Module;
    if (str == "import") return SymbolType::Import;
    if (str == "macro") return SymbolType::Macro;
    if (str == "typealias") return SymbolType::TypeAlias;
    return SymbolType::Unknown;
}

// ============================================================================
// File Watching
// ============================================================================
void RepositoryIntelligence::StartFileWatcher() {
    // TODO: Implement file system watcher
    // For now, this is a placeholder
}

void RepositoryIntelligence::StopFileWatcher() {
    m_watching = false;
    if (m_watcherThread && m_watcherThread->joinable()) {
        m_watcherThread->join();
    }
}

void RepositoryIntelligence::OnFileChanged(const std::string& path) {
    UpdateFile(path);
    
    if (m_changeCallback) {
        m_changeCallback(path);
    }
}

} // namespace Repository
} // namespace RawrXD
