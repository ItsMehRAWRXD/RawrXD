/**
 * RawrXD Sovereign Context Engine Implementation
 * Local semantic search for code
 */

#include "sovereign_context.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>

namespace rawrxd::rag {

// Code Chunker Implementation
std::vector<CodeChunker::Chunk> CodeChunker::chunkFile(const fs::path& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return {};
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    std::string ext = filePath.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == ".py") {
        return chunkPython(content, filePath);
    } else if (ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx") {
        return chunkJavaScript(content, filePath);
    } else if (ext == ".cpp" || ext == ".cc" || ext == ".h" || ext == ".hpp" || ext == ".c") {
        return chunkCpp(content, filePath);
    } else {
        return chunkGeneric(content, filePath);
    }
}

std::vector<CodeChunker::Chunk> CodeChunker::chunkPython(
    std::string_view content,
    const fs::path& path
) {
    std::vector<Chunk> chunks;
    std::istringstream stream(std::string(content));
    std::string line;
    size_t lineNum = 0;
    
    std::string currentChunk;
    size_t chunkStart = 0;
    std::string chunkType = "code";
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Function/class definition
        if (line.find("def ") == 0 || line.find("class ") == 0) {
            // Save previous chunk
            if (!currentChunk.empty()) {
                chunks.push_back({
                    currentChunk,
                    path.string(),
                    chunkStart,
                    lineNum - 1,
                    chunkType
                });
            }
            currentChunk = line + "\n";
            chunkStart = lineNum;
            chunkType = (line.find("def ") == 0) ? "function" : "class";
        }
        // Import statements
        else if (line.find("import ") == 0 || line.find("from ") == 0) {
            if (chunkType != "import") {
                if (!currentChunk.empty()) {
                    chunks.push_back({
                        currentChunk,
                        path.string(),
                        chunkStart,
                        lineNum - 1,
                        chunkType
                    });
                }
                currentChunk = line + "\n";
                chunkStart = lineNum;
                chunkType = "import";
            } else {
                currentChunk += line + "\n";
            }
        }
        // Comments/docstrings
        else if (line.find("#") == 0 || line.find("\"\"\"") != std::string::npos) {
            currentChunk += line + "\n";
        }
        // Regular code
        else {
            if (!line.empty()) {
                currentChunk += line + "\n";
            }
        }
        
        // Split large chunks
        if (currentChunk.size() > 2000) {
            chunks.push_back({
                currentChunk,
                path.string(),
                chunkStart,
                lineNum,
                chunkType
            });
            currentChunk.clear();
            chunkStart = lineNum + 1;
        }
    }
    
    // Add final chunk
    if (!currentChunk.empty()) {
        chunks.push_back({
            currentChunk,
            path.string(),
            chunkStart,
            lineNum,
            chunkType
        });
    }
    
    return chunks;
}

std::vector<CodeChunker::Chunk> CodeChunker::chunkJavaScript(
    std::string_view content,
    const fs::path& path
) {
    std::vector<Chunk> chunks;
    std::istringstream stream(std::string(content));
    std::string line;
    size_t lineNum = 0;
    
    std::string currentChunk;
    size_t chunkStart = 0;
    std::string chunkType = "code";
    
    // Regex patterns for JS/TS
    std::regex functionRegex(R"(^(?:export\s+)?(?:async\s+)?function\s+(\w+))");
    std::regex arrowRegex(R"(^(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\()");
    std::regex classRegex(R"(^(?:export\s+)?class\s+(\w+))");
    std::regex importRegex(R"(^(?:import|export)\s+)");
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Check for function/class boundaries
        if (std::regex_search(line, functionRegex) ||
            std::regex_search(line, arrowRegex) ||
            std::regex_search(line, classRegex)) {
            
            if (!currentChunk.empty()) {
                chunks.push_back({
                    currentChunk,
                    path.string(),
                    chunkStart,
                    lineNum - 1,
                    chunkType
                });
            }
            currentChunk = line + "\n";
            chunkStart = lineNum;
            chunkType = std::regex_search(line, classRegex) ? "class" : "function";
        }
        // Import/export
        else if (std::regex_search(line, importRegex)) {
            if (chunkType != "import") {
                if (!currentChunk.empty()) {
                    chunks.push_back({
                        currentChunk,
                        path.string(),
                        chunkStart,
                        lineNum - 1,
                        chunkType
                    });
                }
                currentChunk = line + "\n";
                chunkStart = lineNum;
                chunkType = "import";
            } else {
                currentChunk += line + "\n";
            }
        }
        else {
            currentChunk += line + "\n";
        }
        
        // Split large chunks
        if (currentChunk.size() > 2000) {
            chunks.push_back({
                currentChunk,
                path.string(),
                chunkStart,
                lineNum,
                chunkType
            });
            currentChunk.clear();
            chunkStart = lineNum + 1;
        }
    }
    
    if (!currentChunk.empty()) {
        chunks.push_back({
            currentChunk,
            path.string(),
            chunkStart,
            lineNum,
            chunkType
        });
    }
    
    return chunks;
}

std::vector<CodeChunker::Chunk> CodeChunker::chunkCpp(
    std::string_view content,
    const fs::path& path
) {
    std::vector<Chunk> chunks;
    std::istringstream stream(std::string(content));
    std::string line;
    size_t lineNum = 0;
    
    std::string currentChunk;
    size_t chunkStart = 0;
    std::string chunkType = "code";
    int braceDepth = 0;
    
    std::regex functionRegex(R"((\w+)\s*\([^)]*\)\s*\{)");
    std::regex classRegex(R"((?:class|struct)\s+(\w+))");
    std::regex includeRegex(R"(#include\s+["<][^">]+[">])");
    
    while (std::getline(stream, line)) {
        lineNum++;
        
        // Track brace depth
        for (char c : line) {
            if (c == '{') braceDepth++;
            if (c == '}') braceDepth--;
        }
        
        // Function/class start
        if (std::regex_search(line, functionRegex) ||
            std::regex_search(line, classRegex)) {
            
            if (!currentChunk.empty() && braceDepth == 0) {
                chunks.push_back({
                    currentChunk,
                    path.string(),
                    chunkStart,
                    lineNum - 1,
                    chunkType
                });
            }
            currentChunk = line + "\n";
            chunkStart = lineNum;
            chunkType = std::regex_search(line, classRegex) ? "class" : "function";
        }
        // Includes
        else if (std::regex_search(line, includeRegex)) {
            if (chunkType != "import") {
                if (!currentChunk.empty()) {
                    chunks.push_back({
                        currentChunk,
                        path.string(),
                        chunkStart,
                        lineNum - 1,
                        chunkType
                    });
                }
                currentChunk = line + "\n";
                chunkStart = lineNum;
                chunkType = "import";
            } else {
                currentChunk += line + "\n";
            }
        }
        else {
            currentChunk += line + "\n";
        }
        
        // End of function/class
        if (braceDepth == 0 && !currentChunk.empty() && currentChunk.size() > 500) {
            chunks.push_back({
                currentChunk,
                path.string(),
                chunkStart,
                lineNum,
                chunkType
            });
            currentChunk.clear();
            chunkStart = lineNum + 1;
        }
    }
    
    if (!currentChunk.empty()) {
        chunks.push_back({
            currentChunk,
            path.string(),
            chunkStart,
            lineNum,
            chunkType
        });
    }
    
    return chunks;
}

std::vector<CodeChunker::Chunk> CodeChunker::chunkGeneric(
    std::string_view content,
    const fs::path& path
) {
    // Simple line-based chunking for unknown file types
    std::vector<Chunk> chunks;
    std::istringstream stream(std::string(content));
    std::string line;
    size_t lineNum = 0;
    
    std::string currentChunk;
    size_t chunkStart = 0;
    
    while (std::getline(stream, line)) {
        lineNum++;
        currentChunk += line + "\n";
        
        // Chunk every 50 lines
        if (lineNum % 50 == 0) {
            chunks.push_back({
                currentChunk,
                path.string(),
                chunkStart,
                lineNum,
                "code"
            });
            currentChunk.clear();
            chunkStart = lineNum + 1;
        }
    }
    
    if (!currentChunk.empty()) {
        chunks.push_back({
            currentChunk,
            path.string(),
            chunkStart,
            lineNum,
            "code"
        });
    }
    
    return chunks;
}

// Sovereign Context Engine Implementation
SovereignContextEngine::SovereignContextEngine(const fs::path& dataDir)
    : m_dataDir(dataDir) {
    m_indexPath = dataDir / "index.json";
    m_modelPath = dataDir / "model.onnx";
}

SovereignContextEngine::~SovereignContextEngine() = default;

bool SovereignContextEngine::initialize() {
    std::cout << "[RawrXD RAG] Initializing Sovereign Context Engine..." << std::endl;
    
    // Create data directory if needed
    if (!fs::exists(m_dataDir)) {
        fs::create_directories(m_dataDir);
    }
    
    // Initialize HNSW index
    m_index = std::make_unique<HNSWIndex>();
    
    // Load existing index
    if (fs::exists(m_indexPath)) {
        std::cout << "[RawrXD RAG] Loading existing index..." << std::endl;
        m_index->load(m_indexPath);
        std::cout << "[RawrXD RAG] Loaded " << m_index->size() << " documents" << std::endl;
    }
    
    // Load embedding model
    if (!loadModel()) {
        std::cerr << "[RawrXD RAG] Failed to load embedding model" << std::endl;
        // Continue without model - will use placeholder embeddings
    }
    
    return true;
}

bool SovereignContextEngine::loadModel() {
    // For now, use a simple placeholder
    // In production, this would load an ONNX model
    std::cout << "[RawrXD RAG] Embedding model: Placeholder (384-dim)" << std::endl;
    return true;
}

void SovereignContextEngine::indexPath(const fs::path& path) {
    std::cout << "[RawrXD RAG] Indexing: " << path << std::endl;
    
    if (fs::is_regular_file(path)) {
        // Index single file
        auto chunks = m_chunker.chunkFile(path);
        for (const auto& chunk : chunks) {
            Document doc;
            doc.id = generateId(chunk.filePath, chunk.lineStart);
            doc.content = chunk.content;
            doc.filePath = chunk.filePath;
            doc.lineStart = chunk.lineStart;
            doc.lineEnd = chunk.lineEnd;
            
            // Generate placeholder embedding
            // In production, this would use the ONNX model
            doc.embedding.resize(EMBEDDING_DIM);
            std::hash<std::string> hasher;
            size_t seed = hasher(doc.content);
            for (size_t i = 0; i < EMBEDDING_DIM; ++i) {
                seed = seed * 1103515245 + 12345;
                doc.embedding[i] = static_cast<float>(seed % 1000) / 1000.0f;
            }
            
            m_index->addDocument(doc);
        }
    } else if (fs::is_directory(path)) {
        // Index directory
        for (const auto& entry : fs::recursive_directory_iterator(path)) {
            if (entry.is_regular_file()) {
                auto ext = entry.path().extension().string();
                if (ext == ".py" || ext == ".js" || ext == ".ts" ||
                    ext == ".cpp" || ext == ".h" || ext == ".hpp" ||
                    ext == ".c" || ext == ".java" || ext == ".go" ||
                    ext == ".rs" || ext == ".rb") {
                    indexPath(entry.path());
                }
            }
        }
    }
}

std::vector<SearchResult> SovereignContextEngine::search(
    std::string_view query,
    size_t k
) {
    // Generate query embedding (placeholder)
    std::vector<float> queryEmbedding(EMBEDDING_DIM);
    std::hash<std::string> hasher;
    size_t seed = hasher(std::string(query));
    for (size_t i = 0; i < EMBEDDING_DIM; ++i) {
        seed = seed * 1103515245 + 12345;
        queryEmbedding[i] = static_cast<float>(seed % 1000) / 1000.0f;
    }
    
    return m_index->search(queryEmbedding, k);
}

std::vector<SearchResult> SovereignContextEngine::searchWithContext(
    std::string_view query,
    std::string_view currentFile,
    size_t currentLine,
    size_t k
) {
    // Search and boost results from same file
    auto results = search(query, k * 2);
    
    // Boost scores for same file
    for (auto& result : results) {
        if (result.document.filePath == currentFile) {
            result.score *= 1.5f; // 50% boost for same file
        }
        
        // Boost for proximity to current line
        size_t lineDist = (result.document.lineStart > currentLine) ?
            (result.document.lineStart - currentLine) :
            (currentLine - result.document.lineStart);
        
        if (lineDist < 50) {
            result.score *= 1.3f; // 30% boost for nearby code
        }
    }
    
    // Re-sort by boosted scores
    std::sort(results.begin(), results.end(),
        [](const SearchResult& a, const SearchResult& b) {
            return a.score > b.score;
        });
    
    // Return top k
    if (results.size() > k) {
        results.resize(k);
    }
    
    return results;
}

std::string SovereignContextEngine::getRelevantContext(
    std::string_view query,
    std::string_view currentFile,
    size_t maxTokens
) {
    auto results = searchWithContext(query, currentFile, 0, 10);
    
    std::string context;
    size_t estimatedTokens = 0;
    
    for (const auto& result : results) {
        // Rough token estimation: 1 token ≈ 4 characters
        size_t tokens = result.document.content.size() / 4;
        
        if (estimatedTokens + tokens > maxTokens) {
            break;
        }
        
        context += "\n// File: " + result.document.filePath + 
                  " (lines " + std::to_string(result.document.lineStart) + 
                  "-" + std::to_string(result.document.lineEnd) + ")\n";
        context += result.document.content;
        context += "\n";
        
        estimatedTokens += tokens;
    }
    
    return context;
}

void SovereignContextEngine::saveIndex() {
    if (m_index) {
        m_index->save(m_indexPath);
        std::cout << "[RawrXD RAG] Index saved: " << m_index->size() << " documents" << std::endl;
    }
}

SovereignContextEngine::Stats SovereignContextEngine::getStats() const {
    Stats stats{};
    stats.documentCount = m_index ? m_index->size() : 0;
    stats.modelName = "MiniLM (placeholder)";
    stats.modelLoaded = m_model ? m_model->isLoaded() : false;
    
    if (fs::exists(m_indexPath)) {
        stats.indexSizeMB = fs::file_size(m_indexPath) / (1024 * 1024);
    }
    
    return stats;
}

std::string SovereignContextEngine::generateId(const fs::path& path, size_t line) {
    return path.string() + ":" + std::to_string(line);
}

} // namespace rawrxd::rag
