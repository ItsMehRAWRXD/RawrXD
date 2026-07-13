/**
 * VectorDatabase.hpp
 *
 * Phase L Batch 3/5: Vector Database & Embeddings
 *
 * High-performance vector database for similarity search,
 * embeddings storage, and semantic retrieval.
 */

#pragma once

#include <cstring>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <queue>
#include <chrono>

namespace AI_ML {

// ============================================================================
// Forward Declarations
// ============================================================================

class Vector;
class Embedding;
class VectorIndex;
class VectorDatabase;
class SimilaritySearch;

// ============================================================================
// Vector
// ============================================================================

/**
 * Dense vector representation.
 */
class Vector {
public:
    using ValueType = float;
    
    Vector() = default;
    explicit Vector(size_t dimension);
    Vector(const std::vector<ValueType>& data);
    Vector(std::vector<ValueType>&& data);
    
    // Element access
    ValueType& operator[](size_t index);
    const ValueType& operator[](size_t index) const;
    
    // Properties
    size_t Dimension() const { return data_.size(); }
    size_t Size() const { return data_.size(); }
    bool Empty() const { return data_.empty(); }
    
    // Data access
    const std::vector<ValueType>& Data() const { return data_; }
    std::vector<ValueType>& Data() { return data_; }
    const ValueType* RawData() const { return data_.data(); }
    ValueType* RawData() { return data_.data(); }
    
    // Vector operations
    Vector operator+(const Vector& other) const;
    Vector operator-(const Vector& other) const;
    Vector operator*(ValueType scalar) const;
    Vector operator/(ValueType scalar) const;
    
    Vector& operator+=(const Vector& other);
    Vector& operator-=(const Vector& other);
    Vector& operator*=(ValueType scalar);
    Vector& operator/=(ValueType scalar);
    
    // Dot product
    ValueType Dot(const Vector& other) const;
    
    // Norms
    ValueType L2Norm() const;
    ValueType L1Norm() const;
    ValueType LInfNorm() const;
    
    // Normalization
    Vector Normalize() const;
    void NormalizeInPlace();
    
    // Distance metrics
    ValueType EuclideanDistance(const Vector& other) const;
    ValueType ManhattanDistance(const Vector& other) const;
    ValueType CosineDistance(const Vector& other) const;
    ValueType CosineSimilarity(const Vector& other) const;
    ValueType InnerProduct(const Vector& other) const;
    
    // Comparison
    bool operator==(const Vector& other) const;
    bool operator!=(const Vector& other) const;
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static Vector Deserialize(const std::vector<uint8_t>& data);
    std::string ToString() const;
    
    // Factory methods
    static Vector Zeros(size_t dimension);
    static Vector Ones(size_t dimension);
    static Vector Random(size_t dimension, ValueType min = -1.0f, ValueType max = 1.0f);
    static Vector RandomNormal(size_t dimension, ValueType mean = 0.0f, ValueType std = 1.0f);
    
private:
    std::vector<ValueType> data_;
};

// ============================================================================
// Embedding
// ============================================================================

/**
 * Embedding with metadata.
 */
class Embedding {
public:
    struct Config {
        std::string id;
        Vector vector;
        std::map<std::string, std::string> metadata;
        std::optional<std::string> text;
        std::optional<std::string> source;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> expiresAt;
    };
    
    explicit Embedding(const Config& config);
    
    // Accessors
    const std::string& GetId() const { return config_.id; }
    const Vector& GetVector() const { return config_.vector; }
    Vector& GetVector() { return config_.vector; }
    const std::map<std::string, std::string>& GetMetadata() const { return config_.metadata; }
    
    // Metadata
    void SetMetadata(const std::string& key, const std::string& value);
    std::optional<std::string> GetMetadata(const std::string& key) const;
    bool HasMetadata(const std::string& key) const;
    
    // Text
    bool HasText() const { return config_.text.has_value(); }
    std::optional<std::string> GetText() const { return config_.text; }
    void SetText(const std::string& text);
    
    // Expiration
    bool IsExpired() const;
    void SetExpiration(std::chrono::system_clock::time_point expiresAt);
    
    // Serialization
    std::vector<uint8_t> Serialize() const;
    static Embedding Deserialize(const std::vector<uint8_t>& data);
    std::string ToJson() const;
    
private:
    Config config_;
};

// ============================================================================
// Distance Metric
// ============================================================================

enum class DistanceMetric {
    EUCLIDEAN,      // L2 distance
    COSINE,         // Cosine distance (1 - cosine similarity)
    MANHATTAN,      // L1 distance
    DOT_PRODUCT,    // Negative dot product
    HAMMING,        // Hamming distance
    JACCARD         // Jaccard distance
};

float ComputeDistance(const Vector& a, const Vector& b, DistanceMetric metric);

// ============================================================================
// Vector Index
// ============================================================================

/**
 * Index for fast vector similarity search.
 */
class VectorIndex {
public:
    enum class IndexType {
        FLAT,           // Brute force
        IVF_FLAT,       // Inverted file index
        IVF_PQ,         // Product quantization
        HNSW,           // Hierarchical navigable small world
        ANNOY,          // Approximate nearest neighbors oh yeah
        FAISS_IVFFLAT,  // FAISS IVF flat
        FAISS_IVFPQ,    // FAISS IVF PQ
        FAISS_GPU       // FAISS GPU index
    };
    
    struct Config {
        IndexType type;
        size_t dimension;
        DistanceMetric metric;
        
        // IVF parameters
        size_t nlist;           // Number of clusters
        
        // PQ parameters
        size_t nsubquantizers;  // Number of subquantizers
        size_t nbits;           // Bits per subquantizer
        
        // HNSW parameters
        size_t M;               // Number of neighbors
        size_t efConstruction;    // Construction time search depth
        size_t efSearch;        // Search time depth
        
        // GPU parameters
        int32_t gpuDeviceId;
        size_t gpuMemoryLimit;
    };
    
    explicit VectorIndex(const Config& config);
    ~VectorIndex();
    
    // Lifecycle
    bool Build();
    bool IsBuilt() const;
    void Clear();
    
    // Insertion
    bool Add(const std::string& id, const Vector& vector);
    bool AddBatch(const std::vector<std::pair<std::string, Vector>>& items);
    bool Remove(const std::string& id);
    bool Update(const std::string& id, const Vector& vector);
    
    // Search
    struct SearchResult {
        std::string id;
        float distance;
        float score;
    };
    
    std::vector<SearchResult> Search(const Vector& query, size_t k) const;
    std::vector<SearchResult> SearchWithFilter(
        const Vector& query, size_t k,
        const std::function<bool(const std::string&)>& filter) const;
    
    // Range search
    std::vector<SearchResult> RangeSearch(const Vector& query, float radius) const;
    
    // Batch search
    std::vector<std::vector<SearchResult>> SearchBatch(
        const std::vector<Vector>& queries, size_t k) const;
    
    // Statistics
    struct IndexStats {
        size_t numVectors;
        size_t dimension;
        size_t memoryUsageBytes;
        double buildTimeSeconds;
        double averageSearchTimeMs;
        IndexType type;
    };
    IndexStats GetStats() const;
    
    // Persistence
    bool Save(const std::string& path) const;
    bool Load(const std::string& path);
    
    // Optimization
    bool Optimize();
    bool Rebuild();
    
private:
    Config config_;
    bool built_;
    mutable std::mutex mutex_;
    
    // Index data structures
    std::map<std::string, Vector> vectors_;
    void* nativeIndex_;  // Framework-specific index handle
    
    void BuildFlatIndex();
    void BuildIVFIndex();
    void BuildHNSWIndex();
    void BuildFAISSIndex();
};

// ============================================================================
// Vector Database
// ============================================================================

/**
 * Production-ready vector database.
 */
class VectorDatabase {
public:
    struct Config {
        std::string dataDir;
        size_t maxMemoryBytes;
        size_t maxVectorsPerCollection;
        bool enablePersistence;
        std::chrono::seconds autoSaveInterval;
        bool enableCompression;
    };
    
    struct CollectionConfig {
        std::string name;
        size_t dimension;
        DistanceMetric metric;
        VectorIndex::IndexType indexType;
        VectorIndex::Config indexConfig;
        std::map<std::string, std::string> metadata;
    };
    
    explicit VectorDatabase(const Config& config);
    ~VectorDatabase();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Collections
    bool CreateCollection(const CollectionConfig& config);
    bool DeleteCollection(const std::string& name);
    bool CollectionExists(const std::string& name) const;
    std::vector<std::string> ListCollections() const;
    CollectionConfig GetCollectionConfig(const std::string& name) const;
    
    // CRUD operations
    bool Insert(const std::string& collection, const Embedding& embedding);
    bool InsertBatch(const std::string& collection,
                     const std::vector<Embedding>& embeddings);
    std::optional<Embedding> Get(const std::string& collection,
                                    const std::string& id) const;
    bool Update(const std::string& collection, const Embedding& embedding);
    bool Delete(const std::string& collection, const std::string& id);
    bool DeleteBatch(const std::string& collection,
                     const std::vector<std::string>& ids);
    
    // Search
    std::vector<VectorIndex::SearchResult> Search(
        const std::string& collection,
        const Vector& query,
        size_t k) const;
    
    std::vector<VectorIndex::SearchResult> SearchWithFilter(
        const std::string& collection,
        const Vector& query,
        size_t k,
        const std::map<std::string, std::string>& filter) const;
    
    // Hybrid search (vector + metadata)
    std::vector<VectorIndex::SearchResult> HybridSearch(
        const std::string& collection,
        const Vector& query,
        const std::map<std::string, std::string>& metadataFilter,
        size_t k,
        float vectorWeight = 0.7f) const;
    
    // Statistics
    struct CollectionStats {
        std::string name;
        size_t vectorCount;
        size_t dimension;
        size_t memoryUsageBytes;
        DistanceMetric metric;
        VectorIndex::IndexStats indexStats;
    };
    CollectionStats GetCollectionStats(const std::string& name) const;
    
    struct DatabaseStats {
        size_t totalCollections;
        size_t totalVectors;
        size_t totalMemoryBytes;
        size_t diskUsageBytes;
    };
    DatabaseStats GetStats() const;
    
    // Persistence
    bool Save(const std::string& path);
    bool Load(const std::string& path);
    bool ExportToHDF5(const std::string& path) const;
    bool ImportFromHDF5(const std::string& path);
    
    // Backup
    bool Backup(const std::string& backupPath);
    bool Restore(const std::string& backupPath);
    
    // Maintenance
    bool Compact(const std::string& collection);
    bool RebuildIndex(const std::string& collection);
    bool Vacuum();
    
private:
    Config config_;
    bool initialized_;
    mutable std::mutex mutex_;
    
    struct Collection {
        CollectionConfig config;
        std::unique_ptr<VectorIndex> index;
        std::map<std::string, Embedding> embeddings;
        mutable std::mutex mutex;
    };
    
    std::map<std::string, std::unique_ptr<Collection>> collections_;
    
    void AutoSaveLoop();
    std::thread autoSaveThread_;
    std::atomic<bool> stopAutoSave_;
};

// ============================================================================
// Embedding Model
// ============================================================================

/**
 * Embedding model for text encoding.
 */
class EmbeddingModel {
public:
    enum class ModelType {
        SENTENCE_TRANSFORMERS,
        OPENAI,
        HUGGINGFACE,
        CUSTOM
    };
    
    struct Config {
        ModelType type;
        std::string modelName;
        std::string modelPath;
        size_t maxSequenceLength;
        std::string poolingStrategy;  // mean, cls, max
        bool normalizeEmbeddings;
        std::string device;  // cpu, cuda, mps
        int32_t batchSize;
    };
    
    explicit EmbeddingModel(const Config& config);
    ~EmbeddingModel();
    
    // Lifecycle
    bool Load();
    bool IsLoaded() const;
    void Unload();
    
    // Encoding
    Vector Encode(const std::string& text);
    std::vector<Vector> EncodeBatch(const std::vector<std::string>& texts);
    
    // Properties
    size_t GetDimension() const;
    size_t GetMaxSequenceLength() const;
    
    // Similarity helpers
    float Similarity(const std::string& text1, const std::string& text2);
    std::vector<std::pair<std::string, float>> FindSimilar(
        const std::string& query,
        const std::vector<std::string>& candidates,
        size_t topK = 5);
    
private:
    Config config_;
    bool loaded_;
    size_t dimension_;
    void* modelHandle_;
};

// ============================================================================
// Similarity Search
// ============================================================================

/**
 * High-level similarity search API.
 */
class SimilaritySearch {
public:
    struct SearchRequest {
        std::string query;
        std::string collection;
        size_t topK;
        float minScore;
        std::optional<std::map<std::string, std::string>> filter;
    };
    
    struct SearchResponse {
        std::vector<VectorIndex::SearchResult> results;
        std::chrono::milliseconds searchTime;
        bool success;
        std::optional<std::string> error;
    };
    
    explicit SimilaritySearch(std::shared_ptr<VectorDatabase> database,
                               std::shared_ptr<EmbeddingModel> model);
    
    // Search
    SearchResponse Search(const SearchRequest& request);
    
    // Semantic search
    std::vector<std::string> SemanticSearch(const std::string& query,
                                             const std::string& collection,
                                             size_t topK = 5);
    
    // Similar documents
    std::vector<std::string> FindSimilarDocuments(const std::string& documentId,
                                                  const std::string& collection,
                                                  size_t topK = 5);
    
    // Clustering
    std::vector<std::vector<std::string>> Cluster(const std::string& collection,
                                                  size_t numClusters);
    
    // Deduplication
    std::vector<std::string> FindDuplicates(const std::string& collection,
                                            float threshold = 0.95f);
    
private:
    std::shared_ptr<VectorDatabase> database_;
    std::shared_ptr<EmbeddingModel> model_;
};

// ============================================================================
// RAG (Retrieval Augmented Generation)
// ============================================================================

/**
 * RAG pipeline for LLM augmentation.
 */
class RAGPipeline {
public:
    struct Config {
        std::string vectorCollection;
        size_t retrievalTopK;
        float relevanceThreshold;
        std::string contextTemplate;
        size_t maxContextLength;
        bool rerankResults;
    };
    
    struct RetrievedContext {
        std::string documentId;
        std::string text;
        float relevanceScore;
        std::map<std::string, std::string> metadata;
    };
    
    struct RAGResponse {
        std::string augmentedQuery;
        std::vector<RetrievedContext> contexts;
        std::chrono::milliseconds retrievalTime;
    };
    
    explicit RAGPipeline(const Config& config,
                         std::shared_ptr<VectorDatabase> database,
                         std::shared_ptr<EmbeddingModel> model);
    
    // Retrieval
    std::vector<RetrievedContext> Retrieve(const std::string& query);
    
    // Augmentation
    RAGResponse Augment(const std::string& query);
    std::string BuildPrompt(const std::string& query,
                            const std::vector<RetrievedContext>& contexts);
    
    // Full pipeline
    RAGResponse Process(const std::string& query);
    
    // Document management
    void AddDocument(const std::string& id, const std::string& text,
                     const std::map<std::string, std::string>& metadata = {});
    void AddDocuments(const std::vector<std::pair<std::string, std::string>>& documents);
    void RemoveDocument(const std::string& id);
    
private:
    Config config_;
    std::shared_ptr<VectorDatabase> database_;
    std::shared_ptr<EmbeddingModel> model_;
    
    std::vector<RetrievedContext> Rerank(const std::vector<RetrievedContext>& contexts,
                                          const std::string& query);
};

} // namespace AI_ML
