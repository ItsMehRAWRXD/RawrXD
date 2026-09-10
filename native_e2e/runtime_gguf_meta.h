#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawrNativeGgufMeta {
    uint32_t ok;
    uint32_t block_count;
    uint32_t context_length;
    uint32_t file_type;
    char architecture[64];
} RawrNativeGgufMeta;

/* Header-only GGUF KV probe (no tensor load). Returns 0 on success. */
uint32_t RawrNative_ReadGgufMeta(const char* path, RawrNativeGgufMeta* out);

#ifdef __cplusplus
}
#endif
