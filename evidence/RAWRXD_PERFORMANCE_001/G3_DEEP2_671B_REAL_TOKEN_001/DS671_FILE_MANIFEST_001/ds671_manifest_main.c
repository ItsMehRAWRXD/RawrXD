/* ds671_manifest_main.c — audit all 11 DeepSeek shards */
#include "ds671_gguf_scan.h"
#include <stdio.h>
#include <string.h>

static const char *DIR = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\";
static const char *NAMES[11] = {
    "DeepSeek-R1-Q4_K_M-00001-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00002-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00003-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00004-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00005-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00006-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00007-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00008-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00009-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00010-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00011-of-00011.gguf"
};

int main(void) {
    GgufShardInfo s[11];
    uint64_t total_bytes = 0, total_tensors = 0;
    uint32_t qhist[40];
    int i, fail = 0;
    char path[512];
    memset(qhist, 0, sizeof qhist);
    printf("DS671_FILE_MANIFEST begin\n");
    for (i = 0; i < 11; i++) {
        int rc;
        snprintf(path, sizeof path, "%s%s", DIR, NAMES[i]);
        rc = gguf_scan_shard(path, &s[i]);
        printf("SHARD=%02d RC=%d BYTES=%llu N_TENSOR=%llu N_KV=%llu ARCH=%s\n",
               i + 1, rc, (unsigned long long)s[i].file_bytes,
               (unsigned long long)s[i].n_tensor, (unsigned long long)s[i].n_kv,
               s[i].architecture[0] ? s[i].architecture : "-");
        if (rc) { fail = 1; continue; }
        total_bytes += s[i].file_bytes;
        total_tensors += s[i].n_tensor;
        { int t; for (t = 0; t < 40; t++) qhist[t] += s[i].quant_hist[t]; }
        if (s[i].tensor_bad) fail = 1;
    }
    /* shard1 must carry architecture metadata */
    if (strcmp(s[0].architecture, "deepseek2")) fail = 1;
    if (s[0].block_count != 61 || s[0].expert_count != 256) fail = 1;
    if (s[0].expert_used != 8 || s[0].leading_dense != 3) fail = 1;
    printf("TOTAL_BYTES=%llu TOTAL_TENSORS=%llu\n",
           (unsigned long long)total_bytes, (unsigned long long)total_tensors);
    printf("META block=%u experts=%u used=%u shared=%u dense=%u emb=%u vocab=%u\n",
           s[0].block_count, s[0].expert_count, s[0].expert_used,
           s[0].expert_shared, s[0].leading_dense, s[0].embedding_length,
           s[0].vocab_size);
    for (i = 0; i < 40; i++) if (qhist[i]) printf("QUANT_TYPE_%d_COUNT=%u\n", i, qhist[i]);
    printf("DS671_FILE_MANIFEST_PASS=%s\n", fail ? "0" : "1");
    return fail ? 1 : 0;
}
