#include "SemanticIndex.hpp"
#include <math>
#include <numeric>
#include <stdexcept>
#include <stdexcept>
#include <map>
#include <fstream>

namespace rawrxd::context {

class SemanticIndex::Impl {
public:
    mutable std::mutex mutex_;
    bool initialized_ = false;
    size_t embedding_dim_ = 0;
    std::map<uint64_t, SemanticDocument> docs_;
    uint64_t next_id_ = 1;

    float CosineSimilarity(const std::vector<float>& a, const std::vector<float>& b) const {
        if (a.size() != b.size() || a.empty()) return 0.0f;
        float dot = 0.0f, norm_a = 0.0f, norm_b = 0.0f;
        for (size_t i = 0; i < a.size(); ++i) {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }
        float denom = std::sqrt(norm_a) * std::sqrt(norm_b);
        return denom > 0.0f ? (dot / denom) : 0.0f;
    }
};

SemanticIndex::SemanticIndex() : impl_(std::make_unique<Impl>()) {}
SemanticIndex::~SemanticIndex() = default;

bool SemanticIndex::Initialize(size_t embedding_dim) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_ = true;
    impl_->embedding_dim_ = embedding_dim;
    return true;
}

void SemanticIndex::Shutdown() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->initialized_ = false;
    impl_->docs_.clear();
}

bool SemanticIndex::IsInitialized() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->initialized_;
}

uint64_t SemanticIndex::AddDocument(const SemanticDocument& doc) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    uint64_t id = impl_->next_id_++;
    SemanticDocument copy = doc;
    copy.id = id;
    copy.indexed_at = std::chrono::steady_clock::now();
    impl_->docs_[id] = copy;
    return id;
}

bool SemanticIndex::RemoveDocument(uint64_t doc_id) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->docs_.erase(doc_id) > 0;
}

bool SemanticIndex::UpdateDocument(uint64_t doc_id, const SemanticDocument& doc) {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->docs_.find(doc_id);
    if (it == impl_->docs_.end()) return false;
    SemanticDocument copy = doc;
    copy.id = doc_id;
    it->second = copy;
    return true;
}

void SemanticIndex::ClearIndex() {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    impl_->docs_.clear();
}

std::vector<SemanticMatch> SemanticIndex::Search(const std::vector<float>& query_embedding, size_t top_k) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<SemanticMatch> matches;
    for (const auto& [id, doc] : impl_->docs_) {
        if (doc.embedding.size() == query_embedding.size()) {
            SemanticMatch m;
            m.doc_id = id;
            m.similarity = impl_->CosineSimilarity(doc.embedding, query_embedding);
            m.source_path = doc.source_path;
            m.snippet = doc.content.substr(0, 200);
            matches.push_back(m);
        }
    }
    std::sort(matches.begin(), matches.end(), [](const SemanticMatch& a, const SemanticMatch& b) {
        return a.similarity > b.similarity;
    });
    if (matches.size() > top_k) matches.resize(top_k);
    return matches;
}

std::vector<SemanticMatch> SemanticIndex::SearchByText(const std::string& query, size_t top_k) const {
    // Simplified: create a simple hash-based embedding from query text
    std::vector<float> dummy_emb(impl_->embedding_dim_, 0.0f);
    for (size_t i = 0; i < query.size() && i < dummy_emb.size(); ++i) {
        dummy_emb[i] = static_cast<float>(query[i]) / 255.0f;
    }
    return Search(dummy_emb, top_k);
}

std::optional<SemanticDocument> SemanticIndex::GetDocument(uint64_t doc_id) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    auto it = impl_->docs_.find(doc_id);
    if (it != impl_->docs_.end()) return it->second;
    return std::nullopt;
}

size_t SemanticIndex::GetDocumentCount() const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    return impl_->docs_.size();
}

std::vector<SemanticDocument> SemanticIndex::GetDocumentsByTag(const std::string& tag) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::vector<SemanticDocument> out;
    for (const auto& [_, doc] : impl_->docs_) {
        for (const auto& t : doc.tags) {
            if (t == tag) { out.push_back(doc); break; }
        }
    }
    return out;
}

bool SemanticIndex::SaveToFile(const std::string& path) const {
    std::lock_guard<std::mutex> lock(impl_->mutex_);
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) return false;
    size_t count = impl_->docs_.size();
    ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));
    for (const auto& [_, doc] : impl_->docs_) {
        ofs.write(reinterpret_cast<const char*>(&doc.id), sizeof(doc.id));
        size_t path_len = doc.source_path.size();
        ofs.write(reinterpret_cast<const char*>(&path_len), sizeof(path_len));
        ofs.write(doc.source_path.data(), static_cast<std::streamsize>(path_len));
    }
    return ofs.good();
}

bool SemanticIndex::LoadFromFile(const std::string& /*path*/) {
    // TODO: implement binary deserialization
    return false;
}

} // namespace rawrxd::context
