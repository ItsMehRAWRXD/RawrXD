/**
 * @file cross_file_indexer.cpp
 * @brief Cross-File Symbol Resolution Implementation
 * @status PRODUCTION - Real multi-file indexing with dependency tracking
 */

#include "cross_file_indexer.h"
#include <windows.h>
#include <shlwapi.h>
#include <sstream>
#include <fstream>
#include <regex>
#include <queue>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

namespace RawrXD::LSP {

CrossFileIndexer::CrossFileIndexer() : m_indexing(false) {}

CrossFileIndexer::~CrossFileIndexer() {
    StopBackgroundIndexing();
}

void CrossFileIndexer::SetWorkspaceRoot(const std::string& root) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_workspaceRoot = root;
}

void CrossFileIndexer::AddFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    FileMetadata meta;
    meta.path = path;
    meta.needsReindex = true;
    
    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fileData)) {
        ULARGE_INTEGER ull;
        ull.LowPart = fileData.ftLastWriteTime.dwLowDateTime;
        ull.HighPart = fileData.ftLastWriteTime.dwHighDateTime;
        meta.lastModified = ull.QuadPart / 10000000ULL - 11644473600ULL;
    }
    
    m_fileMetadata[path] = meta;
    m_pendingFiles.push(path);
    m_indexCV.notify_one();
}

void CrossFileIndexer::RemoveFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Remove from metadata
    m_fileMetadata.erase(path);
    
    // Remove symbols from this file
    auto it = m_symbols.begin();
    while (it != m_symbols.end()) {
        if (it->second.definition.file == path) {
            it = m_symbols.erase(it);
        } else {
            // Remove references from this file
            auto& refs = it->second.references;
            refs.erase(std::remove_if(refs.begin(), refs.end(),
                [&path](const SymbolLocation& loc) { return loc.file == path; }),
                refs.end());
            ++it;
        }
    }
    
    // Remove include entries
    m_includes.erase(std::remove_if(m_includes.begin(), m_includes.end(),
        [&path](const IncludeDependency& inc) {
            return inc.sourceFile == path || inc.includedFile == path;
        }), m_includes.end());
}

void CrossFileIndexer::UpdateFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_fileMetadata.find(path);
    if (it != m_fileMetadata.end()) {
        WIN32_FILE_ATTRIBUTE_DATA fileData;
        if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fileData)) {
            ULARGE_INTEGER ull;
            ull.LowPart = fileData.ftLastWriteTime.dwLowDateTime;
            ull.HighPart = fileData.ftLastWriteTime.dwHighDateTime;
            std::time_t newTime = ull.QuadPart / 10000000ULL - 11644473600ULL;
            
            if (newTime > it->second.lastModified) {
                it->second.lastModified = newTime;
                it->second.needsReindex = true;
                m_pendingFiles.push(path);
                m_indexCV.notify_one();
            }
        }
    }
}

void CrossFileIndexer::StartBackgroundIndexing() {
    m_indexing = true;
    m_indexThread = std::thread(&CrossFileIndexer::IndexerThread, this);
}

void CrossFileIndexer::StopBackgroundIndexing() {
    m_indexing = false;
    m_indexCV.notify_all();
    if (m_indexThread.joinable()) {
        m_indexThread.join();
    }
}

void CrossFileIndexer::IndexFile(const std::string& path) {
    ParseFile(path);
}

void CrossFileIndexer::IndexerThread() {
    while (m_indexing) {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_indexCV.wait(lock, [this]() { return !m_pendingFiles.empty() || !m_indexing; });
        
        if (!m_indexing) break;
        
        if (!m_pendingFiles.empty()) {
            std::string file = m_pendingFiles.front();
            m_pendingFiles.pop();
            lock.unlock();
            
            if (m_progressCallback) {
                m_progressCallback("Indexing: " + file, 0);
            }
            
            ParseFile(file);
            
            if (m_completeCallback) {
                m_completeCallback(file);
            }
        }
    }
}

void CrossFileIndexer::ParseFile(const std::string& path) {
    // Read file content
    std::ifstream file(path);
    if (!file.is_open()) return;
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();
    
    std::string content = buffer.str();
    
    // Remove old symbols from this file
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_symbols.begin();
        while (it != m_symbols.end()) {
            if (it->second.definition.file == path) {
                it = m_symbols.erase(it);
            } else {
                ++it;
            }
        }
    }
    
    // Extract includes first
    ExtractIncludes(path, content);
    
    // Extract symbols
    ExtractSymbols(path, content);
    
    // Update metadata
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto& meta = m_fileMetadata[path];
        meta.lastIndexed = std::time(nullptr);
        meta.needsReindex = false;
        meta.symbolCount = 0;
        
        for (const auto& [name, sym] : m_symbols) {
            if (sym.definition.file == path) {
                meta.symbolCount++;
            }
        }
    }
}

void CrossFileIndexer::ExtractIncludes(const std::string& path, const std::string& content) {
    std::regex includeRegex(R"(#include\s+[<\"]([^\">]+)[\">])");
    std::smatch match;
    
    std::string::const_iterator searchStart(content.cbegin());
    while (std::regex_search(searchStart, content.cend(), match, includeRegex)) {
        IncludeDependency dep;
        dep.sourceFile = path;
        dep.includedFile = match[1];
        dep.isSystemInclude = (match[0].str().find('<') != std::string::npos);
        
        // Find line number
        size_t pos = match.position();
        dep.line = 1;
        for (size_t i = 0; i < pos; i++) {
            if (content[i] == '\n') dep.line++;
        }
        
        // Resolve full path
        std::string resolved = ResolveInclude(dep.includedFile, path);
        if (!resolved.empty()) {
            dep.includedFile = resolved;
            
            std::lock_guard<std::mutex> lock(m_mutex);
            m_includes.push_back(dep);
            
            // Update include graph
            m_fileMetadata[path].includes.insert(resolved);
            m_fileMetadata[resolved].includedBy.insert(path);
        }
        
        searchStart = match.suffix().first;
    }
}

void CrossFileIndexer::ExtractSymbols(const std::string& path, const std::string& content) {
    // Tokenize
    std::vector<std::string> tokens = Tokenize(content);
    
    std::vector<std::string> scopeStack;
    bool inPublic = true;
    
    for (size_t i = 0; i < tokens.size(); i++) {
        const std::string& token = tokens[i];
        
        // Track scope
        if (token == "class" || token == "struct" || token == "namespace") {
            if (i + 1 < tokens.size()) {
                scopeStack.push_back(tokens[i + 1]);
            }
        } else if (token == "{") {
            // Enter scope
        } else if (token == "}") {
            // Exit scope
            if (!scopeStack.empty()) {
                scopeStack.pop_back();
            }
        } else if (token == "public:") {
            inPublic = true;
        } else if (token == "private:" || token == "protected:") {
            inPublic = false;
        }
        
        // Detect function definitions
        if (i + 2 < tokens.size() && 
            tokens[i + 1] == "(" &&
            !scopeStack.empty()) {
            
            // Check if this looks like a function
            bool isFunction = true;
            
            // Skip if it's a control structure
            if (token == "if" || token == "for" || token == "while" ||
                token == "switch" || token == "catch") {
                isFunction = false;
            }
            
            if (isFunction) {
                CrossFileSymbol sym;
                sym.name = token;
                sym.kind = "function";
                sym.isPublic = inPublic;
                sym.parentScopes = scopeStack;
                
                // Build fully qualified name
                std::stringstream fq;
                for (size_t j = 0; j < scopeStack.size(); j++) {
                    if (j > 0) fq << "::";
                    fq << scopeStack[j];
                }
                if (!scopeStack.empty()) fq << "::";
                fq << token;
                sym.fullyQualifiedName = fq.str();
                
                // Find line number
                size_t tokenPos = content.find(token);
                sym.definition.file = path;
                sym.definition.line = 1;
                for (size_t j = 0; j < tokenPos && j < content.size(); j++) {
                    if (content[j] == '\n') sym.definition.line++;
                }
                
                // Extract context (line content)
                size_t lineStart = content.rfind('\n', tokenPos);
                size_t lineEnd = content.find('\n', tokenPos);
                if (lineStart == std::string::npos) lineStart = 0;
                else lineStart++;
                if (lineEnd == std::string::npos) lineEnd = content.size();
                sym.definition.context = content.substr(lineStart, lineEnd - lineStart);
                
                // Store symbol
                std::lock_guard<std::mutex> lock(m_mutex);
                m_symbols[sym.fullyQualifiedName] = sym;
            }
        }
        
        // Detect class/struct definitions
        if ((token == "class" || token == "struct") && i + 1 < tokens.size()) {
            CrossFileSymbol sym;
            sym.name = tokens[i + 1];
            sym.kind = token;
            sym.isPublic = true;
            sym.parentScopes = scopeStack;
            
            std::stringstream fq;
            for (size_t j = 0; j < scopeStack.size(); j++) {
                if (j > 0) fq << "::";
                fq << scopeStack[j];
            }
            if (!scopeStack.empty()) fq << "::";
            fq << sym.name;
            sym.fullyQualifiedName = fq.str();
            
            size_t tokenPos = content.find(sym.name);
            sym.definition.file = path;
            sym.definition.line = 1;
            for (size_t j = 0; j < tokenPos && j < content.size(); j++) {
                if (content[j] == '\n') sym.definition.line++;
            }
            
            std::lock_guard<std::mutex> lock(m_mutex);
            m_symbols[sym.fullyQualifiedName] = sym;
        }
    }
}

std::string CrossFileIndexer::ResolveInclude(const std::string& includePath, 
                                              const std::string& contextFile) {
    // Try relative to context file
    char contextDir[MAX_PATH];
    strcpy_s(contextDir, contextFile.c_str());
    PathRemoveFileSpecA(contextDir);
    
    char resolved[MAX_PATH];
    strcpy_s(resolved, contextDir);
    PathAppendA(resolved, includePath.c_str());
    
    if (GetFileAttributesA(resolved) != INVALID_FILE_ATTRIBUTES) {
        return resolved;
    }
    
    // Try workspace root
    if (!m_workspaceRoot.empty()) {
        strcpy_s(resolved, m_workspaceRoot.c_str());
        PathAppendA(resolved, includePath.c_str());
        
        if (GetFileAttributesA(resolved) != INVALID_FILE_ATTRIBUTES) {
            return resolved;
        }
    }
    
    // Try standard include paths
    const char* stdPaths[] = {
        "C:\\Program Files (x86)\\Windows Kits\\10\\Include",
        "C:\\VS2022Enterprise\\VC\\Tools\\MSVC"
    };
    
    for (const auto& stdPath : stdPaths) {
        strcpy_s(resolved, stdPath);
        PathAppendA(resolved, includePath.c_str());
        if (GetFileAttributesA(resolved) != INVALID_FILE_ATTRIBUTES) {
            return resolved;
        }
    }
    
    return "";
}

std::vector<std::string> CrossFileIndexer::Tokenize(const std::string& content) {
    std::vector<std::string> tokens;
    std::string current;
    bool inString = false;
    bool inComment = false;
    
    for (size_t i = 0; i < content.size(); i++) {
        char c = content[i];
        
        // Handle comments
        if (!inString && i + 1 < content.size()) {
            if (c == '/' && content[i + 1] == '/') {
                // Skip to end of line
                while (i < content.size() && content[i] != '\n') i++;
                continue;
            }
            if (c == '/' && content[i + 1] == '*') {
                inComment = true;
                i++;
                continue;
            }
            if (c == '*' && content[i + 1] == '/') {
                inComment = false;
                i++;
                continue;
            }
        }
        
        if (inComment) continue;
        
        // Handle strings
        if (c == '"' && (i == 0 || content[i - 1] != '\\')) {
            inString = !inString;
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            continue;
        }
        
        if (inString) {
            current += c;
            continue;
        }
        
        // Token delimiters
        if (std::isspace(c) || c == '(' || c == ')' || c == '{' || c == '}' ||
            c == ';' || c == ',' || c == ':' || c == '*' || c == '&' ||
            c == '+' || c == '-' || c == '=' || c == '<' || c == '>') {
            if (!current.empty()) {
                tokens.push_back(current);
                current.clear();
            }
            if (!std::isspace(c)) {
                tokens.push_back(std::string(1, c));
            }
        } else {
            current += c;
        }
    }
    
    if (!current.empty()) {
        tokens.push_back(current);
    }
    
    return tokens;
}

std::vector<CrossFileSymbol> CrossFileIndexer::FindSymbolsByName(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<CrossFileSymbol> results;
    for (const auto& [fqName, sym] : m_symbols) {
        if (sym.name == name) {
            results.push_back(sym);
        }
    }
    return results;
}

std::vector<CrossFileSymbol> CrossFileIndexer::FindSymbolsByPrefix(const std::string& prefix, size_t maxResults) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<CrossFileSymbol> results;
    for (const auto& [fqName, sym] : m_symbols) {
        if (sym.name.find(prefix) == 0) {
            results.push_back(sym);
            if (results.size() >= maxResults) break;
        }
    }
    return results;
}

CrossFileSymbol* CrossFileIndexer::FindDefinition(const std::string& name, 
                                                   const std::string& contextFile) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // First try exact match
    auto it = m_symbols.find(name);
    if (it != m_symbols.end()) {
        return &it->second;
    }
    
    // Try by simple name
    for (auto& [fqName, sym] : m_symbols) {
        if (sym.name == name) {
            return &sym;
        }
    }
    
    return nullptr;
}

std::vector<SymbolLocation> CrossFileIndexer::FindReferences(const std::string& name,
                                                             const std::string& contextFile) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_symbols.find(name);
    if (it != m_symbols.end()) {
        return it->second.references;
    }
    
    return {};
}

std::vector<std::string> CrossFileIndexer::GetFilesAffectedByChange(const std::string& changedFile) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::set<std::string> affected;
    std::queue<std::string> toProcess;
    toProcess.push(changedFile);
    
    while (!toProcess.empty()) {
        std::string current = toProcess.front();
        toProcess.pop();
        
        auto it = m_fileMetadata.find(current);
        if (it != m_fileMetadata.end()) {
            for (const auto& includer : it->second.includedBy) {
                if (affected.insert(includer).second) {
                    toProcess.push(includer);
                }
            }
        }
    }
    
    return std::vector<std::string>(affected.begin(), affected.end());
}

size_t CrossFileIndexer::GetIndexedFileCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_fileMetadata.size();
}

size_t CrossFileIndexer::GetSymbolCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_symbols.size();
}

void CrossFileIndexer::SetProgressCallback(std::function<void(const std::string&, int)> callback) {
    m_progressCallback = callback;
}

void CrossFileIndexer::SetIndexCompleteCallback(std::function<void(const std::string&)> callback) {
    m_completeCallback = callback;
}

} // namespace RawrXD::LSP
