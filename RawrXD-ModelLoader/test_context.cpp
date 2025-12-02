#define NOMINMAX
#include "context/indexer.h"
#include "context/semantic_store.h"
#include "backend/ollama_client.h"
#include <iostream>
#include <vector>

using namespace RawrXD::Context;
using RawrXD::Backend::OllamaClient;

int main() {
    std::cout << "Phase 3 Context System Test\n";

    // Index current workspace root (project root)
    Indexer indexer(".");
    auto stats = indexer.build(true);
    std::cout << "files indexed: " << stats.files_indexed << ", symbols: " << stats.symbols_found << "\n";

    // Create snippets and embeddings (requires Ollama running)
    SemanticStore store;
    OllamaClient client("http://localhost:11434");

    size_t count = 0;
    for (const auto& s : indexer.getAll()) {
        if (count >= 5) break; // limit for test
        std::string snippet = s.name + " (" + s.kind + ") in " + s.file;
        auto vec = client.embeddings("llama2", snippet); // adjust model name as available
        if (!vec.empty()) {
            store.upsert({s.file+":"+std::to_string(s.line), snippet, vec});
            ++count;
        }
    }
    std::cout << "embedded snippets: " << count << "\n";

    if (count > 0) {
        auto qvec = client.embeddings("llama2", "function parse json");
        if (!qvec.empty()) {
            auto results = store.search(qvec, 3);
            std::cout << "top results:" << "\n";
            for (const auto& r : results) {
                std::cout << " - (" << r.score << ") " << r.text << "\n";
            }
        } else {
            std::cout << "embedding for query failed (server off?)\n";
        }
    }

    std::cout << "Phase 3 Context System Test Complete\n";
    return 0;
}
