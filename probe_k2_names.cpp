#include "src/deep2/GGUFLoader.hpp"
#include <cstdio>

int main() {
    auto result = Deep2::GGUFLoader::LoadMetadata(
        "F:\\OllamaModels\\Kimi-K2-Instruct-0905-GGUF\\Q4_K_M\\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf");
    if (!result.success) {
        printf("FAIL: %s\n", result.error);
        return 1;
    }
    printf("Tensors in shard 1: %zu\n", result.tensors.size());
    for (const auto& t : result.tensors) {
        printf("%s\n", t.name.c_str());
    }
    return 0;
}
