/* ds671_gguf_scan.h — no-dep GGUF shard scanner (Win64) */
#ifndef DS671_GGUF_SCAN_H
#define DS671_GGUF_SCAN_H
#include <stdint.h>
#include <stddef.h>
enum { GGUF_OK=0, GGUF_E_IO=1, GGUF_E_MAGIC=2, GGUF_E_VER=3, GGUF_E_FMT=4, GGUF_E_BOUND=5 };
typedef struct {
    uint32_t version;
    uint64_t n_tensor;
    uint64_t n_kv;
    uint64_t file_bytes;
    uint64_t data_start;
    char architecture[64];
    uint32_t block_count, expert_count, expert_used, expert_shared;
    uint32_t leading_dense, embedding_length, vocab_size;
    uint32_t q_lora_rank, kv_lora_rank;
    uint32_t unresolved_kv;
    uint32_t quant_hist[40];
    uint32_t tensor_ok;
    uint32_t tensor_bad;
} GgufShardInfo;
int gguf_scan_shard(const char *path, GgufShardInfo *out);
#endif
