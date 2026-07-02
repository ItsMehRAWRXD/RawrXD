/**
 * RawrXD HNSW Index Implementation
 * Approximate nearest neighbor search for code embeddings
 */

#include "sovereign_context.hpp"
#include <algorithm>
#include <queue>
#include <iomanip>

namespace rawrxd::rag {

// Priority queue element for search
struct Neighbor {
    std::string id;
    float distance;
    
    bool operator>(const Neighbor& other) const {
        return distance > other.distance;
    }
};

HNSWIndex::HNSWIndex(size_t dim, size_t m, size_t ef)
    : m_dim(dim), m_M(m), m_efConstruction(ef) {
    m_levelMult = 1.0 / std::log(1.0 * m);
}

size_t HNSWIndex::getRandomLevel() {
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double r = -std::log(dist(m_rng)) * m_levelMult;
    return static_cast<size_t>(r);
}

void HNSWIndex::addDocument(const Document& doc) {
    if (doc.embedding.size() != m_dim) {
        throw std::invalid_argument("Embedding dimension mismatch");
    }
    
    // Normalize embedding
    std::vector<float> normalized = doc.embedding;
    normalize(normalized);
    
    // Create node
    HNSWNode node(doc.id, normalized);
    size_t level = getRandomLevel();
    node.neighbors.resize(level + 1);
    
    // Store document
    m_documents[doc.id] = doc;
    
    // If first node, set as entry point
    if (m_nodes.empty()) {
        m_entryPoint = doc.id;
        m_maxLayer = level;
        m_nodes[doc.id] = std::move(node);
        return;
    }
    
    // Find entry point for insertion
    std::string curNode = m_entryPoint;
    size_t curLevel = m_maxLayer;
    
    // Search from top layer down
    for (size_t lc = curLevel; lc > level; --lc) {
        auto candidates = searchLayer(normalized, {curNode}, 1, lc);
        if (!candidates.empty()) {
            curNode = candidates[0];
        }
    }
    
    // Insert at each layer from min(level, maxLayer) down to 0
    size_t maxLayerInsert = std::min(level, m_maxLayer);
    std::vector<std::string> neighborsAtLayer;
    
    for (size_t lc = 0; lc <= maxLayerInsert; ++lc) {
        auto candidates = searchLayer(normalized, {curNode}, m_efConstruction, lc);
        auto selected = selectNeighbors(normalized, candidates, m_M);
        node.neighbors[lc] = selected;
        
        // Bidirectional connections
        for (const auto& neighborId : selected) {
            auto it = m_nodes.find(neighborId);
            if (it != m_nodes.end()) {
                auto& neighborNode = it->second;
                if (lc < neighborNode.neighbors.size()) {
                    neighborNode.neighbors[lc].push_back(doc.id);
                    
                    // Trim if too many neighbors
                    if (neighborNode.neighbors[lc].size() > m_M) {
                        // Keep only top M by similarity
                        std::vector<std::pair<std::string, float>> scored;
                        for (const auto& nid : neighborNode.neighbors[lc]) {
                            auto nit = m_nodes.find(nid);
                            if (nit != m_nodes.end()) {
                                float sim = cosineSimilarity(
                                    neighborNode.embedding,
                                    nit->second.embedding
                                );
                                scored.push_back({nid, sim});
                            }
                        }
                        
                        std::partial_sort(
                            scored.begin(),
                            scored.begin() + m_M,
                            scored.end(),
                            [](const auto& a, const auto& b) {
                                return a.second > b.second;
                            }
                        );
                        
                        neighborNode.neighbors[lc].clear();
                        for (size_t i = 0; i < std::min(m_M, scored.size()); ++i) {
                            neighborNode.neighbors[lc].push_back(scored[i].first);
                        }
                    }
                }
            }
        }
    }
    
    // Update entry point if needed
    if (level > m_maxLayer) {
        m_maxLayer = level;
        m_entryPoint = doc.id;
    }
    
    m_nodes[doc.id] = std::move(node);
}

std::vector<std::string> HNSWIndex::searchLayer(
    const std::vector<float>& query,
    const std::vector<std::string>& entryPoints,
    size_t ef,
    size_t layer
) const {
    std::priority_queue<Neighbor, std::vector<Neighbor>, std::greater<>> candidates;
    std::priority_queue<Neighbor> best;
    std::unordered_set<std::string> visited;
    
    // Initialize with entry points
    for (const auto& ep : entryPoints) {
        auto it = m_nodes.find(ep);
        if (it != m_nodes.end()) {
            float dist = 1.0f - cosineSimilarity(query, it->second.embedding);
            candidates.push({ep, dist});
            best.push({ep, dist});
            visited.insert(ep);
        }
    }
    
    // Greedy search
    while (!candidates.empty()) {
        auto cur = candidates.top();
        candidates.pop();
        
        if (cur.distance > best.top().distance) {
            break;
        }
        
        auto it = m_nodes.find(cur.id);
        if (it == m_nodes.end() || layer >= it->second.neighbors.size()) {
            continue;
        }
        
        for (const auto& neighborId : it->second.neighbors[layer]) {
            if (visited.count(neighborId)) continue;
            
            auto nit = m_nodes.find(neighborId);
            if (nit == m_nodes.end()) continue;
            
            float dist = 1.0f - cosineSimilarity(query, nit->second.embedding);
            
            if (best.size() < ef || dist < best.top().distance) {
                candidates.push({neighborId, dist});
                best.push({neighborId, dist});
                visited.insert(neighborId);
                
                if (best.size() > ef) {
                    best.pop();
                }
            }
        }
    }
    
    // Extract results
    std::vector<std::string> results;
    while (!best.empty()) {
        results.push_back(best.top().id);
        best.pop();
    }
    std::reverse(results.begin(), results.end());
    
    return results;
}

std::vector<std::string> HNSWIndex::selectNeighbors(
    const std::vector<float>& query,
    const std::vector<std::string>& candidates,
    size_t m
) const {
    std::vector<std::pair<std::string, float>> scored;
    
    for (const auto& id : candidates) {
        auto it = m_nodes.find(id);
        if (it != m_nodes.end()) {
            float sim = cosineSimilarity(query, it->second.embedding);
            scored.push_back({id, sim});
        }
    }
    
    // Sort by similarity (descending)
    std::partial_sort(
        scored.begin(),
        scored.begin() + std::min(m, scored.size()),
        scored.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        }
    );
    
    std::vector<std::string> selected;
    for (size_t i = 0; i < std::min(m, scored.size()); ++i) {
        selected.push_back(scored[i].first);
    }
    
    return selected;
}

std::vector<SearchResult> HNSWIndex::search(
    const std::vector<float>& queryEmbedding,
    size_t k
) const {
    if (m_nodes.empty()) {
        return {};
    }
    
    // Normalize query
    std::vector<float> normalized = queryEmbedding;
    normalize(normalized);
    
    // Search from top layer
    std::string curNode = m_entryPoint;
    
    for (size_t lc = m_maxLayer; lc > 0; --lc) {
        auto candidates = searchLayer(normalized, {curNode}, 1, lc);
        if (!candidates.empty()) {
            curNode = candidates[0];
        }
    }
    
    // Final search at layer 0
    auto results = searchLayer(normalized, {curNode}, k, 0);
    
    // Build search results
    std::vector<SearchResult> searchResults;
    for (const auto& id : results) {
        auto it = m_documents.find(id);
        auto nit = m_nodes.find(id);
        if (it != m_documents.end() && nit != m_nodes.end()) {
            float score = cosineSimilarity(normalized, nit->second.embedding);
            searchResults.push_back({id, score, it->second});
        }
    }
    
    return searchResults;
}

void HNSWIndex::deleteDocument(std::string_view docId) {
    std::string id(docId);
    
    // Remove from nodes
    auto it = m_nodes.find(id);
    if (it != m_nodes.end()) {
        // Remove from neighbor lists
        for (size_t layer = 0; layer < it->second.neighbors.size(); ++layer) {
            for (const auto& neighborId : it->second.neighbors[layer]) {
                auto nit = m_nodes.find(neighborId);
                if (nit != m_nodes.end() && layer < nit->second.neighbors.size()) {
                    auto& neighbors = nit->second.neighbors[layer];
                    neighbors.erase(
                        std::remove(neighbors.begin(), neighbors.end(), id),
                        neighbors.end()
                    );
                }
            }
        }
        
        m_nodes.erase(it);
    }
    
    // Remove from documents
    m_documents.erase(id);
}

void HNSWIndex::save(const fs::path& path) const {
    json j;
    j["dimension"] = m_dim;
    j["M"] = m_M;
    j["efConstruction"] = m_efConstruction;
    j["maxLayer"] = m_maxLayer;
    j["entryPoint"] = m_entryPoint;
    
    // Save documents
    j["documents"] = json::array();
    for (const auto& [id, doc] : m_documents) {
        j["documents"].push_back(doc.toJson());
    }
    
    // Save nodes (just IDs and neighbors, embeddings are in documents)
    j["nodes"] = json::object();
    for (const auto& [id, node] : m_nodes) {
        json nodeJson;
        nodeJson["neighbors"] = node.neighbors;
        j["nodes"][id] = nodeJson;
    }
    
    std::ofstream file(path);
    file << std::setw(2) << j << std::endl;
}

void HNSWIndex::load(const fs::path& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        return;
    }
    
    json j;
    file >> j;
    
    m_dim = j.value("dimension", EMBEDDING_DIM);
    m_M = j.value("M", M);
    m_efConstruction = j.value("efConstruction", EF_CONSTRUCTION);
    m_maxLayer = j.value("maxLayer", 0);
    m_entryPoint = j.value("entryPoint", "");
    
    // Load documents
    if (j.contains("documents")) {
        for (const auto& docJson : j["documents"]) {
            Document doc;
            doc.id = docJson.value("id", "");
            doc.content = docJson.value("content", "");
            doc.filePath = docJson.value("filePath", "");
            doc.lineStart = docJson.value("lineStart", 0);
            doc.lineEnd = docJson.value("lineEnd", 0);
            m_documents[doc.id] = doc;
        }
    }
    
    // Load nodes
    if (j.contains("nodes")) {
        for (const auto& [id, nodeJson] : j["nodes"].items()) {
            HNSWNode node;
            node.id = id;
            
            // Get embedding from document
            auto docIt = m_documents.find(id);
            if (docIt != m_documents.end()) {
                node.embedding = docIt->second.embedding;
            }
            
            if (nodeJson.contains("neighbors")) {
                node.neighbors = nodeJson["neighbors"].get<std::vector<std::vector<std::string>>>>();
            }
            
            m_nodes[id] = std::move(node);
        }
    }
}

float HNSWIndex::cosineSimilarity(
    const std::vector<float>& a,
    const std::vector<float>& b
) const {
    if (a.size() != b.size()) {
        return 0.0f;
    }
    
    float dot = 0.0f;
    for (size_t i = 0; i < a.size(); ++i) {
        dot += a[i] * b[i];
    }
    
    return dot; // Already normalized
}

void HNSWIndex::normalize(std::vector<float>& vec) const {
    float norm = 0.0f;
    for (float v : vec) {
        norm += v * v;
    }
    norm = std::sqrt(norm);
    
    if (norm > 0.0f) {
        for (float& v : vec) {
            v /= norm;
        }
    }
}

} // namespace rawrxd::rag
