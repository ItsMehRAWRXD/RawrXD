#include "SemanticCodeIndex.h"
#include "CodeEmbedder.h"

#include <chrono>
#include <algorithm>
#include <random>
#include <cmath>
#include <queue>

// Backend selection based on CMake configuration
#if defined(RAWR_HAS_FAISS) && RAWR_HAS_FAISS
    #define USE_FAISS_BACKEND 1
    #include <faiss/IndexIVFPQ.h>
    #include <faiss/IndexFlat.h>
    #include <faiss/utils/distances.h>
#else
    #define USE_FAISS_BACKEND 0
    // HNSW header-only library (fallback when FAISS not available)
    #include "hnswlib/hnswlib.h"
#endif

namespace rawrxd {

// Legacy SimpleEmbedder - kept for backward compatibility
// New code should use CodeEmbedder for ONNX Runtime support
class SimpleEmbedder {
public:
    explicit SimpleEmbedder(int dim) : dimension(dim), rng(42) {}
    
    std::vector<float> embed(const std::string& text) {
        // Stub: Generate deterministic pseudo-embeddings based on text hash
        // In production, this should call ONNX Runtime with CodeBERT model
        std::vector<float> vec(dimension);
        
        // Simple hash-based embedding for testing
        size_t hash = std::hash<std::string>{}(text);
        std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
        
        for (int i = 0; i < dimension; ++i) {
            hash = hash * 31 + i;
            rng.seed(static_cast<unsigned>(hash));
            vec[i] = dist(rng);
        }
        
        // Normalize
        float norm = 0.0f;
        for (float v : vec) norm += v * v;
        norm = std::sqrt(norm);
        if (norm > 0) {
            for (float& v : vec) v /= norm;
        }
        
        return vec;
    }
    
private:
    int dimension;
    std::mt19937 rng;
};

// Training buffer for IVFPQ - accumulate vectors before training
struct TrainingBuffer {
    std::vector<float> vectors;
    size_t count = 0;
    static constexpr size_t TRAINING_THRESHOLD = 1000;  // Train after 1000 snippets
    
    void add(const float* vec, int dim) {
        vectors.insert(vectors.end(), vec, vec + dim);
        count++;
    }
    
    bool should_train() const { return count >= TRAINING_THRESHOLD; }
    void clear() { vectors.clear(); count = 0; }
};

// PIMPL implementation structure with dual-backend support
class SemanticCodeIndex::Impl {
public:
    explicit Impl(const SemanticIndexConfig& cfg);
    ~Impl();  // Phase 17D.3: Explicit destructor for native cleanup
    
    // Delete copy/move to ensure proper backend cleanup
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = default;
    Impl& operator=(Impl&&) = default;
    
    SemanticIndexConfig config;
    SimpleEmbedder embedder;
    
    // ID mapping: FAISS uses sequential IDs (0,1,2...), we map to our snippet IDs
    std::vector<int64_t> faiss_to_snippet_id;  // faiss_idx -> snippet_id
    std::unordered_map<int64_t, size_t> snippet_to_faiss_idx;  // snippet_id -> faiss_idx
    
    // Metadata storage (backend agnostic)
    std::unordered_map<int64_t, ScoredSnippet> snippets;
    std::unordered_map<int64_t, std::vector<float>> embeddings;
    
    int64_t next_id = 1;
    bool initialized = false;
    bool is_trained = false;
    
#if USE_FAISS_BACKEND
    // FAISS IVFPQ backend
    std::unique_ptr<faiss::IndexFlatL2> quantizer;
    std::unique_ptr<faiss::IndexIVFPQ> faiss_index;
    TrainingBuffer training_buffer;
    
    void initialize_faiss();
    void train_if_needed();
    void add_to_faiss(const float* embedding, int64_t snippet_id);
    std::vector<ScoredSnippet> search_faiss(const float* query_vec, int top_k, float min_score);
#else
    // HNSW fallback backend
    std::unique_ptr<hnswlib::L2Space> space;
    std::unique_ptr<hnswlib::HierarchicalNSW<float>> hnsw_index;
    
    void initialize_hnsw();
    void add_to_hnsw(const float* embedding, int64_t snippet_id);
    std::vector<ScoredSnippet> search_hnsw(const float* query_vec, int top_k, float min_score);
#endif
};

#if USE_FAISS_BACKEND
// FAISS IVFPQ Implementation
SemanticCodeIndex::Impl::Impl(const SemanticIndexConfig& cfg) 
    : config(cfg), embedder(cfg.vector_dimension) {
    initialize_faiss();
}

// Phase 17D.3: Explicit destructor for native FAISS cleanup
SemanticCodeIndex::Impl::~Impl() {
#if USE_FAISS_BACKEND
    // Explicit cleanup order: index -> quantizer
    // This ensures FAISS internal memory is properly released
    if (faiss_index) {
        // Reset any internal state before destruction
        faiss_index.reset();
    }
    if (quantizer) {
        quantizer.reset();
    }
    // Clear training buffer
    training_buffer.clear();
#else
    // HNSW cleanup
    if (hnsw_index) {
        hnsw_index.reset();
    }
    if (space) {
        space.reset();
    }
#endif
    
    // Clear all containers to release memory
    faiss_to_snippet_id.clear();
    faiss_to_snippet_id.shrink_to_fit();
    snippet_to_faiss_idx.clear();
    snippets.clear();
    embeddings.clear();
}

void SemanticCodeIndex::Impl::initialize_faiss() {
    // IVFPQ Configuration:
    // - dimension: 384 (MiniLM-compatible)
    // - nlist: 100 (Voronoi cells for coarse quantization)
    // - m: 8 (sub-vectors for product quantization)
    // - nbits: 8 (bits per sub-vector code)
    // Memory: ~140MB for 100k vectors (vs ~1.5GB for flat)
    
    quantizer = std::make_unique<faiss::IndexFlatL2>(config.vector_dimension);
    faiss_index = std::make_unique<faiss::IndexIVFPQ>(
        quantizer.get(),           // Coarse quantizer
        config.vector_dimension,   // Vector dimension
        config.index_nlist,        // nlist (Voronoi cells)
        8,                         // m (sub-vectors)
        8                          // nbits (bits per code)
    );
    
    // Set nprobe for search (number of cells to visit)
    faiss_index->nprobe = config.nprobe;
    
    is_trained = false;
    initialized = true;
}

void SemanticCodeIndex::Impl::train_if_needed() {
    if (is_trained || !training_buffer.should_train()) {
        return;
    }
    
    // Train IVFPQ on accumulated vectors
    // This determines the Voronoi centroids and PQ codebooks
    if (training_buffer.count >= TrainingBuffer::TRAINING_THRESHOLD) {
        faiss_index->train(training_buffer.count, training_buffer.vectors.data());
        is_trained = true;
        training_buffer.clear();
    }
}

void SemanticCodeIndex::Impl::add_to_faiss(const float* embedding, int64_t snippet_id) {
    if (!is_trained) {
        // Buffer for training
        training_buffer.add(embedding, config.vector_dimension);
        train_if_needed();
        
        if (!is_trained) {
            // Still not trained, can't add yet
            return;
        }
    }
    
    // Add to FAISS index
    faiss_idx_t faiss_idx = faiss_index->ntotal;
    faiss_index->add(1, embedding);
    
    // Map FAISS index to our snippet ID
    if (faiss_idx >= static_cast<faiss_idx_t>(faiss_to_snippet_id.size())) {
        faiss_to_snippet_id.resize(faiss_idx + 1);
    }
    faiss_to_snippet_id[faiss_idx] = snippet_id;
    snippet_to_faiss_idx[snippet_id] = faiss_idx;
}

std::vector<ScoredSnippet> SemanticCodeIndex::Impl::search_faiss(
    const float* query_vec, int top_k, float min_score) {
    
    std::vector<ScoredSnippet> results;
    
    if (!is_trained || faiss_index->ntotal == 0) {
        return results;  // Not ready for search
    }
    
    // Search FAISS index
    std::vector<faiss_idx_t> indices(top_k);
    std::vector<float> distances(top_k);
    
    faiss_index->search(1, query_vec, top_k, distances.data(), indices.data());
    
    // Convert to ScoredSnippet results
    for (int i = 0; i < top_k; ++i) {
        if (indices[i] < 0) continue;  // FAISS returns -1 for empty slots
        
        // Convert L2 distance to similarity score (cosine-like 0-1 range)
        // Using exponential decay: similarity = exp(-distance^2 / 2)
        float similarity = std::exp(-distances[i] * distances[i] / 2.0f);
        
        if (similarity >= min_score) {
            int64_t snippet_id = faiss_to_snippet_id[indices[i]];
            auto it = snippets.find(snippet_id);
            if (it != snippets.end()) {
                ScoredSnippet scored = it->second;
                scored.similarity_score = similarity;
                results.push_back(scored);
            }
        }
    }
    
    return results;
}

#else
// HNSW Fallback Implementation
SemanticCodeIndex::Impl::Impl(const SemanticIndexConfig& cfg) 
    : config(cfg), embedder(cfg.vector_dimension) {
    initialize_hnsw();
}

void SemanticCodeIndex::Impl::initialize_hnsw() {
    space = std::make_unique<hnswlib::L2Space>(config.vector_dimension);
    hnsw_index = std::make_unique<hnswlib::HierarchicalNSW<float>>(
        space.get(),
        100000,     // max_elements (increased for production)
        16,         // M: number of bi-directional links
        200         // ef_construction
    );
    is_trained = true;  // HNSW doesn't require explicit training
    initialized = true;
}

void SemanticCodeIndex::Impl::add_to_hnsw(const float* embedding, int64_t snippet_id) {
    hnsw_index->addPoint(embedding, snippet_id);
}

std::vector<ScoredSnippet> SemanticCodeIndex::Impl::search_hnsw(
    const float* query_vec, int top_k, float min_score) {
    
    std::vector<ScoredSnippet> results;
    
    if (hnsw_index->cur_element_count == 0) {
        return results;
    }
    
    // Search HNSW index
    auto search_results = hnsw_index->searchKnn(query_vec, top_k);
    
    // Convert to ScoredSnippet results
    while (!search_results.empty()) {
        auto result = search_results.top();
        search_results.pop();
        
        float distance = result.first;
        int64_t id = result.second;
        
        // Convert L2 distance to similarity score
        float similarity = std::exp(-distance * distance / 2.0f);
        
        if (similarity >= min_score) {
            auto it = snippets.find(id);
            if (it != snippets.end()) {
                ScoredSnippet scored = it->second;
                scored.similarity_score = similarity;
                results.push_back(scored);
            }
        }
    }
    
    // Reverse to get highest similarity first
    std::reverse(results.begin(), results.end());
    
    return results;
}
#endif

// Constructor
SemanticCodeIndex::SemanticCodeIndex(const SemanticIndexConfig& config)
    : m_impl(std::make_unique<Impl>(config))
    , m_config(config)
    , m_initialized(false) {
}

// Destructor
SemanticCodeIndex::~SemanticCodeIndex() = default;

// Move constructor
SemanticCodeIndex::SemanticCodeIndex(SemanticCodeIndex&& other) noexcept
    : m_impl(std::move(other.m_impl))
    , m_config(other.m_config)
    , m_initialized(other.m_initialized) {
    other.m_initialized = false;
}

// Move assignment
SemanticCodeIndex& SemanticCodeIndex::operator=(SemanticCodeIndex&& other) noexcept {
    if (this != &other) {
        m_impl = std::move(other.m_impl);
        m_config = other.m_config;
        m_initialized = other.m_initialized;
        other.m_initialized = false;
    }
    return *this;
}

bool SemanticCodeIndex::initialize() {
    if (m_impl) {
        m_impl->initialized = true;
        m_initialized = true;
    }
    return m_initialized;
}

bool SemanticCodeIndex::is_initialized() const {
    return m_initialized;
}

int64_t SemanticCodeIndex::add_snippet(const std::string& snippet, 
                                        const std::string& metadata) {
    if (!m_initialized || !m_impl) {
        return -1;
    }
    
    // Generate embedding vector
    auto embedding = m_impl->embedder.embed(snippet);
    
    int64_t id = m_impl->next_id++;
    
    // Add to appropriate backend
#if USE_FAISS_BACKEND
    m_impl->add_to_faiss(embedding.data(), id);
#else
    m_impl->add_to_hnsw(embedding.data(), id);
#endif
    
    // Store snippet metadata
    ScoredSnippet ss;
    ss.code = snippet;
    ss.file_path = metadata;
    ss.line_number = 0;
    ss.similarity_score = 0.0f;
    
    m_impl->snippets[id] = std::move(ss);
    m_impl->embeddings[id] = std::move(embedding);
    
    return id;
}

std::vector<ScoredSnippet> SemanticCodeIndex::semantic_search(
    const std::string& intent_query,
    int top_k,
    float min_score) {
    
    std::vector<ScoredSnippet> results;
    
    if (!m_initialized || !m_impl) {
        return results;
    }
    
    float threshold = (min_score >= 0.0f) ? min_score : m_config.min_score_threshold;
    
    // Generate query embedding
    auto query_embedding = m_impl->embedder.embed(intent_query);
    
    // Search appropriate backend
#if USE_FAISS_BACKEND
    results = m_impl->search_faiss(query_embedding.data(), top_k, threshold);
#else
    results = m_impl->search_hnsw(query_embedding.data(), top_k, threshold);
#endif
    
    return results;
}

std::vector<ScoredSnippet> SemanticCodeIndex::search_with_budget(
    const std::string& query,
    int budget_ms,
    int top_k) {
    
    auto start = std::chrono::steady_clock::now();
    
    // Start with low nprobe for speed
    int original_nprobe = m_config.nprobe;
    m_config.nprobe = 4;
    
    auto results = semantic_search(query, top_k);
    
    auto elapsed = std::chrono::steady_clock::now() - start;
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    
    // If time permits and no results, increase nprobe
    if (elapsed_ms < budget_ms / 2 && results.empty()) {
        m_config.nprobe = 16;
        results = semantic_search(query, top_k);
    }
    
    m_config.nprobe = original_nprobe;
    return results;
}

bool SemanticCodeIndex::remove_snippet(int64_t snippet_id) {
    if (!m_impl) return false;
    
    // TODO: Phase 17 - Remove from FAISS/HNSW index
    
    auto it = m_impl->snippets.find(snippet_id);
    if (it != m_impl->snippets.end()) {
        m_impl->snippets.erase(it);
        return true;
    }
    return false;
}

size_t SemanticCodeIndex::memory_usage() const {
    if (!m_impl) return 0;
    
    size_t usage = sizeof(*this);
    usage += m_impl->snippets.size() * sizeof(ScoredSnippet);
    usage += m_impl->embeddings.size() * (m_config.vector_dimension * sizeof(float) + sizeof(std::vector<float>));
    
#if USE_FAISS_BACKEND
    // FAISS IVFPQ memory estimate
    if (m_impl->faiss_index) {
        // IVFPQ: nlist * dimension * sizeof(float) for centroids
        // + ntotal * (m * nbits / 8) for codes
        size_t centroid_memory = m_config.index_nlist * m_config.vector_dimension * sizeof(float);
        size_t code_memory = m_impl->faiss_index->ntotal * (8 * 8 / 8);  // m=8, nbits=8
        usage += centroid_memory + code_memory;
    }
#else
    // HNSW memory estimate (rough approximation)
    if (m_impl->hnsw_index) {
        usage += m_impl->hnsw_index->cur_element_count * (16 * 2 + sizeof(float) * m_config.vector_dimension);
    }
#endif
    
    return usage;
}

size_t SemanticCodeIndex::snippet_count() const {
    if (!m_impl) return 0;
    return m_impl->snippets.size();
}

bool SemanticCodeIndex::save(const std::string& path) {
    if (!m_initialized || !m_impl) return false;
    
    // TODO: Phase 17 - Serialize FAISS index to disk
    // TODO: Serialize snippet metadata
    
    (void)path;
    return true;
}

bool SemanticCodeIndex::load(const std::string& path) {
    if (!m_impl) return false;
    
    // TODO: Phase 17 - Load FAISS index from disk
    // TODO: Load snippet metadata
    
    (void)path;
    return true;
}

bool SemanticCodeIndex::is_trained() const {
    if (!m_impl) return false;
#if USE_FAISS_BACKEND
    return m_impl->is_trained;
#else
    return true; // HNSW doesn't require training
#endif
}

size_t SemanticCodeIndex::training_buffer_size() const {
    if (!m_impl) return 0;
#if USE_FAISS_BACKEND
    return m_impl->training_buffer.count;
#else
    return 0; // HNSW doesn't have a training buffer
#endif
}

} // namespace rawrxd
