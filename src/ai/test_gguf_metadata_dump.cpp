// test_gguf_metadata_dump.cpp
// Diagnostic: dump all metadata keys from a GGUF file

#include "streaming_gguf_loader.h"
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";

    printf("=== GGUF Metadata Dump ===\n");
    printf("File: %s\n\n", path);

    RawrXD::StreamingGGUFLoader loader;
    if (!loader.Open(path)) {
        fprintf(stderr, "FATAL: Failed to open %s\n", path);
        return 1;
    }

    RawrXD::GGUFMetadata meta = loader.GetMetadata();
    printf("Metadata KV pairs: %zu\n", meta.kv_pairs.size());
    for (const auto& kv : meta.kv_pairs) {
        printf("  [%s] = %s\n", kv.first.c_str(), kv.second.c_str());
    }

    const std::vector<std::string>& vocab = loader.GetVocabulary();
    printf("\nVocabulary size: %zu\n", vocab.size());
    if (!vocab.empty()) {
        printf("First 5 tokens:\n");
        for (size_t i = 0; i < std::min(vocab.size(), size_t(5)); ++i) {
            printf("  [%zu] = '%s'\n", i, vocab[i].c_str());
        }
    }

    loader.Close();
    return 0;
}
