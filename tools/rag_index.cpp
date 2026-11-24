// =============================================================================
// rag_index.cpp — A3 CLI: index a tree, query it, emit JSON hits.
// usage: rag_index <path> "query" [topK]
// =============================================================================
#include <cstdio>
#include <string>

#include "rag/codebase_index.h"

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: rag_index <file-or-dir> \"query\" [topK]\n");
        return 2;
    }
    rawrxd::rag::CodebaseIndex index;
    index.IndexPath(argv[1]);
    const int topK = argc > 3 ? std::atoi(argv[3]) : 8;
    const auto hits = index.Query(argv[2], topK);
    std::fputs(rawrxd::rag::CodebaseIndex::ToJson(hits).c_str(), stdout);
    std::fprintf(stderr, "rag: %zu chunks, %zu terms, %zu hits\n",
                 index.ChunkCount(), index.TermCount(), hits.size());
    return hits.empty() ? 1 : 0;
}