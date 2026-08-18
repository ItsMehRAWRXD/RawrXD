// dump_k2_tensors.cpp — Quick tool to list tensor names from first K2 shard
#include <cstdio>
#include <cstring>
#include "../src/deep2/GGUFLoader.hpp"

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "F:/OllamaModels/Kimi-K2-Instruct-0905-GGUF/Q4_K_M/Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf";
    
    printf("Loading metadata from: %s\n", path);
    Deep2::GGUFLoadResult result = Deep2::GGUFLoader::LoadMetadata(path);
    if (!result.success) {
        printf("FAILED: %s\n", result.error);
        return 1;
    }
    
    printf("\nTotal tensors: %zu\n", result.tensors.size());
    printf("Data offset: %llu\n\n", (unsigned long long)result.dataOffset);
    
    // Print first 80 tensor names
    size_t count = result.tensors.size() < 80 ? result.tensors.size() : 80;
    for (size_t i = 0; i < count; ++i) {
        const auto& t = result.tensors[i];
        printf("  %-50s  type=%-3u  dims=%u  [", t.name.c_str(), (unsigned)t.type, (unsigned)t.dimensions.size());
        for (size_t d = 0; d < t.dimensions.size(); ++d) {
            if (d > 0) printf(", ");
            printf("%llu", (unsigned long long)t.dimensions[d]);
        }
        printf("]\n");
    }
    
    // Also search for attn-related tensors
    printf("\n--- All 'attn_' tensors ---\n");
    for (const auto& t : result.tensors) {
        if (t.name.find("attn_") != std::string::npos) {
            printf("  %s\n", t.name.c_str());
        }
    }
    
    return 0;
}
