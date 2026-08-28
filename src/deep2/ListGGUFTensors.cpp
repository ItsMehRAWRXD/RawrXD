// ============================================================================
// ListGGUFTensors.cpp - Minimal utility to list all tensor names in a GGUF
// ============================================================================

#include "GGUFLoader.hpp"
#include <cstdio>
#include <string>

using namespace Deep2;

int main(int argc, char** argv) {
    const char* modelPath = argc > 1 ? argv[1]
        : "G:\\OllamaModels\\blobs\\sha256-9be227448d319e6a7acca8056b71bf7d9a2c6b2811986e6658a9dedc208d0ada";

    printf("=================================================================\n");
    printf(" GGUF Tensor Name Lister\n");
    printf("=================================================================\n");
    printf("Model: %s\n\n", modelPath);

    GGUFLoadOptions options;
    options.loadTensors = false;  // Metadata only

    GGUFLoadResult result = GGUFLoader::Load(modelPath, options);
    if (!result.success) {
        printf("[FAIL] GGUF load failed: %s\n", result.error);
        return 1;
    }

    printf("Total tensors: %zu\n\n", result.tensors.size());
    printf("Tensor names:\n");
    for (const auto& t : result.tensors) {
        printf("  %s  type=%s  dims=", t.name.c_str(), GGUFLoader::GetTypeName(t.type));
        for (size_t i = 0; i < t.dimensions.size(); ++i) {
            if (i > 0) printf("x");
            printf("%llu", (unsigned long long)t.dimensions[i]);
        }
        printf("  size=%zu\n", t.size);
    }

    return 0;
}
