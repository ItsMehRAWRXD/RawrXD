// =============================================================================
// codebase_index.h — A3 codebase RAG index (TOP50 A3), dependency-free.
// =============================================================================
// Chunks source files and builds a BM25 term index for lexical retrieval
// (local model embeddings can be added behind the same interface later; no
// network, no new dependencies). Query -> ranked chunks with file/line spans.
// =============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawrxd::rag {

struct Chunk {
    std::string file;
    int start_line = 0;
    int end_line = 0;
    std::string text;
};

struct Hit {
    std::string file;
    int start_line = 0;
    int end_line = 0;
    double score = 0.0;
    std::string snippet;
};

class CodebaseIndex {
public:
    // Index a file or directory tree (bounded; skips build/VCS noise).
    void IndexPath(const std::string& path, int max_files = 20000);

    // BM25-ranked retrieval. Returns up to topK hits.
    std::vector<Hit> Query(const std::string& query, int topK = 8) const;

    size_t ChunkCount() const { return chunks_.size(); }
    size_t TermCount() const { return vocab_.size(); }
    const std::vector<Chunk>& Chunks() const { return chunks_; }

    static std::string ToJson(const std::vector<Hit>& hits);

private:
    struct DocLen { size_t chunk; size_t length; };
    std::vector<Chunk> chunks_;
    std::vector<DocLen> doc_lens_;
    std::unordered_map<std::string, std::vector<std::pair<size_t, int>>> postings_;
    std::unordered_map<std::string, int> vocab_;
    double avgdl_ = 1.0;
};

// Tokenize: lowercase alnum runs (identifiers split on non-alnum).
std::vector<std::string> Tokenize(const std::string& text);

}  // namespace rawrxd::rag