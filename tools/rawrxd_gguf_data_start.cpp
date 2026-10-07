// Minimal GGUF data-start verifier using repo ggml API.
#include <cstdio>
#include <cstdlib>

// Pull in the gguf API header
#include "gguf.h"

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "Usage: %s <model.gguf>\n", argv[0]);
        return 1;
    }

    struct gguf_init_params params = {0};
    // No context allocation - we only need metadata
    params.no_alloc = true;

    struct gguf_context* ctx = gguf_init_from_file(argv[1], params);
    if (!ctx)
    {
        std::fprintf(stderr, "Failed to open GGUF file: %s\n", argv[1]);
        return 1;
    }

    std::printf("GGUF data offset: %llu\n", (unsigned long long)gguf_get_data_offset(ctx));
    std::printf("GGUF alignment: %llu\n", (unsigned long long)gguf_get_alignment(ctx));
    std::printf("GGUF tensors: %llu\n", (unsigned long long)gguf_get_n_tensors(ctx));
    std::printf("GGUF KV pairs: %llu\n", (unsigned long long)gguf_get_n_kv(ctx));

    // Find general.alignment if present
    int64_t alignment_key = gguf_find_key(ctx, "general.alignment");
    if (alignment_key >= 0)
    {
        uint32_t alignment = gguf_get_val_u32(ctx, alignment_key);
        std::printf("general.alignment: %u\n", alignment);
    }
    else
    {
        std::printf("general.alignment: not found (using default 32)\n");
    }

    gguf_free(ctx);
    return 0;
}
