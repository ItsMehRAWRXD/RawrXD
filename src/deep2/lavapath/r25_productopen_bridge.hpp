#pragma once
#include <cstdint>

extern "C" {
struct R25_GGUF_PROOF {
    uint64_t status;
    uint64_t version;
    uint64_t tensor_count;
    uint64_t kv_count;
    uint64_t tensors_scanned;
    uint64_t token_embed_found;
    uint64_t lm_head_found;
    uint64_t product_open;
    uint64_t file_size;
    uint64_t tensor_info_off;
};

uint64_t R25_ProductOpenGguf(const wchar_t* path, R25_GGUF_PROOF* outProof);
void     R25_CloseLastMapping(void);
}

#define R25_PRODUCTOPEN_OK              0ull
#define R25_PRODUCTOPEN_ERR_ARG         1ull
#define R25_PRODUCTOPEN_ERR_OPEN        2ull
#define R25_PRODUCTOPEN_ERR_MAP         3ull
#define R25_PRODUCTOPEN_ERR_MAGIC       4ull
#define R25_PRODUCTOPEN_ERR_VERSION     5ull
#define R25_PRODUCTOPEN_ERR_BOUNDS      6ull
#define R25_PRODUCTOPEN_ERR_UNSUPPORTED 7ull
#define R25_PRODUCTOPEN_ERR_TENSORS0    8ull
#define R25_PRODUCTOPEN_ERR_EMBED0      9ull
#define R25_PRODUCTOPEN_ERR_HEAD0       10ull
