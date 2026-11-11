/**
 * RawrXD Sovereign Context Engine
 * Local HNSW Vector Store for semantic code search
 * 
 * Zero cloud dependency. Runs entirely on local hardware.
 */

#pragma once

#include <vector>
#include <string>
#include <string_view>
#include <unordered_map>
#include <queue>
#include <random>
#include <math>
#include <filesystem>
#include <fstream>
#include <json/json.hpp>

namespace rawrxd::rag {

using json = nlohmann::json;
namespace fs = std::filesystem;

// Embedding dimension (384 for MiniLM, 768 for BERT-base)
constexpr size_t EMBEDDING_DIM = 384;
constexpr size_t MAX_LAYERS = 16;
constexpr size_t EF_CONSTRUCTION = 200;
constexpr size_t M = 16; // Max neighbors per layer

// Document with embedding
struct Document {
    std::string id;
    std::string content;
    std::string filePath;
    size_t lineStart;
    size_t lineEnd;
    std::vector<float> embedding;
    
    json toJson() const {
        return json{
            {"id", id},
            {"content", content},
            {"filePath", filePath},
            {"lineStart", lineStart},
            {"lineEnd", lineEnd}
        };
    }
};

// Search result
struct SearchResult {
    std::string docId;
    float score;
    Document document;
};

// HNSW Node
struct HNSWNode {
    std::string id;
    std::vector<float> embedding;
    std::vector<std::vector<std::string>> neighbors; // Layer -> neighbor IDs
    
    HNSWNode() = default;
    explicit HNSWNode(std::string_view docId, const std::vector<float>& emb) 
        : id(docId), embedding(emb) {}
};

// HNSW Index for approximate nearest neighbor search
class HNSWIndex {
public:
    HNSWIndex(size_t dim = EMBEDDING_DIM, size_t m = M, size_t ef = EF_CONSTRUCTION);
    ~HNSWIndex() = default;
    
    // Non-copyable
    HNSWIndex(const HNSWIndex&) = delete;
    HNSWIndex& operator=(const HNSWIndex&) = delete;
    
    // Movable
    HNSWIndex(HNSWIndex&&) noexcept = default;
    HNSWIndex& operator=(HNSWIndex&&) noexcept = default;
    
    // Add document to index
    void addDocument(const Document& doc);
    
    // Search for nearest neighbors
    std::vector<SearchResult> search(
        const std::vector<float>& queryEmbedding, 
        size_t k = 10
    ) const;
    
    // Delete document
    void deleteDocument(std::string_view docId);
    
    // Persist to disk
    void save(const fs::path& path) const;
    
    // Load from disk
    void load(const fs::path& path);
    
    // Get stats
    size_t size() const { return m_nodes.size(); }
    size_t dimension() const { return m_dim; }
    
private:
    size_t m_dim;
    size_t m_M;
    size_t m_efConstruction;
    size_t m_maxLayer{0};
    double m_levelMult;
    
    std::unordered_map<std::string, HNSWNode> m_nodes;
    std::unordered_map<std::string, Document> m_documents;
    std::string m_entryPoint;
    
    mutable std::mt19937 m_rng{std::random_device{}()};
    
    // Internal methods
    size_t getRandomLevel();
    std::vector<std::string> searchLayer(
        const std::vector<float>& query,
        const std::vector<std::string>& entryPoints,
        size_t ef,
        size_t layer
    ) const;
    
    std::vector<std::string> selectNeighbors(
        const std::vector<float>& query,
        const std::vector<std::string>& candidates,
        size_t m
    ) const;
    
    float cosineSimilarity(
        const std::vector<float>& a, 
        const std::vector<float>& b
    ) const;
    
    void normalize(std::vector<float>& vec) const;
};

// Embedding model interface
class EmbeddingModel {
public:
    virtual ~EmbeddingModel() = default;
    
    // Generate embedding for text
    virtual std::vector<float> embed(std::string_view text) = 0;
    
    // Batch embedding
    virtual std::vector<std::vector<float>> embedBatch(
        const std::vector<std::string>& texts
    ) = 0;
    
    // Get embedding dimension
    virtual size_t dimension() const = 0;
    
    // Check if model is loaded
    virtual bool isLoaded() const = 0;
};

// Local ONNX Runtime embedding model
class LocalEmbeddingModel : public EmbeddingModel {
public:
    explicit LocalEmbeddingModel(const fs::path& modelPath);
    ~LocalEmbeddingModel() override;
    
    std::vector<float> embed(std::string_view text) override;
    std::vector<std::vector<float>> embedBatch(
        const std::vector<std::string>& texts
    ) override;
    size_t dimension() const override { return m_dim; }
    bool isLoaded() const override { return m_loaded; }
    
private:
    fs::path m_modelPath;
    size_t m_dim{EMBEDDING_DIM};
    bool m_loaded{false};
    
    // ONNX Runtime session (forward declared to avoid header dependency)
    struct OrtSession;
    std::unique_ptr<OrtSession> m_session;
    
    bool loadModel();
    std::vector<float> runInference(const std::vector<int64_t>& input);
};

// Code chunker - splits code into semantic chunks
class CodeChunker {
public:
    struct Chunk {
        std::string content;
        std::string filePath;
        size_t lineStart;
        size_t lineEnd;
        std::string type; // "function", "class", "comment", "import", etc.
    };
    
    std::vector<Chunk> chunkFile(const fs::path& filePath);
    
private:
    std::vector<Chunk> chunkPython(std::string_view content, const fs::path& path);
    std::vector<Chunk> chunkJavaScript(std::string_view content, const fs::path& path);
    std::vector<Chunk> chunkCpp(std::string_view content, const fs::path& path);
    std::vector<Chunk> chunkGeneric(std::string_view content, const fs::path& path);
};

// Sovereign Context Engine - Main interface
class SovereignContextEngine {
public:
    explicit SovereignContextEngine(const fs::path& dataDir);
    ~SovereignContextEngine();
    
    // Initialize - load index and model
    bool initialize();
    
    // Index a file or directory
    void indexPath(const fs::path& path);
    
    // Semantic search
    std::vector<SearchResult> search(
        std::string_view query, 
        size_t k = 10
    );
    
    // Search with code context
    std::vector<SearchResult> searchWithContext(
        std::string_view query,
        std::string_view currentFile,
        size_t currentLine,
        size_t k = 10
    );
    
    // Get relevant context for agent
    std::string getRelevantContext(
        std::string_view query,
        std::string_view currentFile,
        size_t maxTokens = 2048
    );
    
    // Save index
    void saveIndex();
    
    // Stats
    struct Stats {
        size_t documentCount;
        size_t indexSizeMB;
        std::string modelName;
        bool modelLoaded;
    };
    Stats getStats() const;
    
private:
    fs::path m_dataDir;
    fs::path m_indexPath;
    fs::path m_modelPath;
    
    std::unique_ptr<HNSWIndex> m_index;
    std::unique_ptr<EmbeddingModel> m_model;
    CodeChunker m_chunker;
    
    bool loadModel();
    std::string generateId(const fs::path& path, size_t line);
};

} // namespace rawrxd::rag
