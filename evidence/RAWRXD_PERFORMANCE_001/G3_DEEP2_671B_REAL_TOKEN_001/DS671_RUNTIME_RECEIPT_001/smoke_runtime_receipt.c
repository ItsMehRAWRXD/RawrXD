/* smoke_runtime_receipt.c — fill OBSERVED from disk; prove PROMOTE stays 0 */
#include "ds671_runtime_receipt.h"
#include "../DS671_FILE_MANIFEST_001/ds671_gguf_scan.h"
#include <stdio.h>
#include <string.h>

extern int gguf_classify_names(const char *path, uint32_t *cls, uint32_t *unres);

static const char *DIR = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\";
static const char *NAMES[11] = {
    "DeepSeek-R1-Q4_K_M-00001-of-00011.gguf","DeepSeek-R1-Q4_K_M-00002-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00003-of-00011.gguf","DeepSeek-R1-Q4_K_M-00004-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00005-of-00011.gguf","DeepSeek-R1-Q4_K_M-00006-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00007-of-00011.gguf","DeepSeek-R1-Q4_K_M-00008-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00009-of-00011.gguf","DeepSeek-R1-Q4_K_M-00010-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00011-of-00011.gguf"
};

int main(void)
{
    Ds671RunState s; Ds671Receipt r; char path[512]; int i, rc;
    uint32_t cls[8] = {0}, unres = 0;
    memset(&s, 0, sizeof s);
    s.expected_shards = 11; s.expected_tensors = 1025;
    s.expected_blocks = 61; s.expected_experts = 256; s.expected_used = 8;
    s.expected_shared = 1; s.expected_emb = 7168; s.expected_vocab = 129280;
    s.promote_requested = 1; /* DECLARED — must not mint promote */

    for (i = 0; i < 11; i++) {
        GgufShardInfo sh; uint32_t c2[8] = {0}; uint32_t u = 0;
        snprintf(path, sizeof path, "%s%s", DIR, NAMES[i]);
        if (gguf_scan_shard(path, &sh) != GGUF_OK) continue;
        s.opened_shards++;
        s.total_bytes += sh.file_bytes;
        s.tensor_total += (uint32_t)sh.n_tensor;
        if (i == 0) {
            s.meta_blocks = sh.block_count; s.meta_experts = sh.expert_count;
            s.meta_used = sh.expert_used; s.meta_shared = sh.expert_shared;
            s.meta_emb = sh.embedding_length; s.meta_vocab = sh.vocab_size;
        }
        if (gguf_classify_names(path, c2, &u) == 0) {
            int k; for (k = 0; k < 8; k++) cls[k] += c2[k];
            unres += u;
        }
    }
    s.unresolved_tensors = unres;
    s.class_emb = cls[0]; s.class_out = cls[1]; s.class_attn = cls[2];
    s.class_mla = cls[3]; s.class_dense = cls[4]; s.class_exp = cls[5];
    s.class_norm = cls[6]; s.class_other = cls[7];
    /* no-stream full load of 376GiB not proven — OBSERVED false */
    s.full_load_no_stream = 0;
    /* decode / policy live not observed */
    s.stream_used = 0; s.fallback_used = 0; s.stub_used = 0; s.synthetic_weight_used = 0;

    rc = ds671_emit_receipt(&s, &r);
    printf("OPENED_SHARDS=%u TOTAL_BYTES=%llu TENSORS=%u UNRES=%u\n",
           s.opened_shards, (unsigned long long)s.total_bytes, s.tensor_total, s.unresolved_tensors);
    printf("NORM=%u OTHER=%u SEMANTIC=%u META=%u MANIFEST=%u\n",
           s.class_norm, s.class_other, r.semantic_map_pass, r.metadata_pass, r.manifest_pass);
    printf("DECODE=%u POLICY=%u NO_FAKE=%u PROMOTE=%u PROMOTE_REQUESTED=%u\n",
           r.decode_pass, r.policy_pass, r.no_fake_path, r.promote, s.promote_requested);
    printf("DS671_RUNTIME_RECEIPT_SMOKE=%s\n",
           (rc == 1 && r.promote == 0 && s.promote_requested == 1) ? "PASS" : "FAIL");
    return (rc == 1 && r.promote == 0) ? 0 : 2;
}
