/* ds671_tensor_map_main.c — name-class inventory across 11 shards */
#include "ds671_gguf_scan.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Re-open path: lightweight name walk via duplicated open in scan — extend API */
extern int gguf_scan_shard(const char *path, GgufShardInfo *out);

/* We need name classification: add gguf_walk_names in tensors — for now second tool */
int gguf_classify_names(const char *path, uint32_t *cls /*8 bins*/, uint32_t *unres);

enum {
    C_TOKEN_EMB=0, C_OUTPUT, C_ATTN, C_MLA, C_FFN_DENSE, C_EXPERT, C_NORM, C_OTHER
};

static const char *DIR = "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\";
static const char *NAMES[11] = {
    "DeepSeek-R1-Q4_K_M-00001-of-00011.gguf","DeepSeek-R1-Q4_K_M-00002-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00003-of-00011.gguf","DeepSeek-R1-Q4_K_M-00004-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00005-of-00011.gguf","DeepSeek-R1-Q4_K_M-00006-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00007-of-00011.gguf","DeepSeek-R1-Q4_K_M-00008-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00009-of-00011.gguf","DeepSeek-R1-Q4_K_M-00010-of-00011.gguf",
    "DeepSeek-R1-Q4_K_M-00011-of-00011.gguf"
};

int main(void) {
    uint32_t cls[8]={0}, unres=0, i;
    char path[512];
    int fail=0;
    for (i=0;i<11;i++) {
        uint32_t c2[8]={0}, u=0;
        snprintf(path,sizeof path,"%s%s",DIR,NAMES[i]);
        if (gguf_classify_names(path,c2,&u)) { fail=1; printf("SHARD=%u CLASSIFY_FAIL\n",i+1); continue; }
        { int k; for(k=0;k<8;k++) cls[k]+=c2[k]; }
        unres+=u;
        printf("SHARD=%02u emb=%u out=%u attn=%u mla=%u dense=%u exp=%u norm=%u other=%u\n",
               i+1,c2[0],c2[1],c2[2],c2[3],c2[4],c2[5],c2[6],c2[7]);
    }
    printf("TOTAL emb=%u out=%u attn=%u mla=%u dense=%u exp=%u norm=%u other=%u UNRES=%u\n",
           cls[0],cls[1],cls[2],cls[3],cls[4],cls[5],cls[6],cls[7],unres);
    /* Require core classes present */
    if (!cls[C_TOKEN_EMB] || !cls[C_OUTPUT] || !cls[C_MLA] || !cls[C_EXPERT] || !cls[C_NORM])
        fail=1;
    if (unres) fail=1;
    printf("DS_TENSOR_MAP_PASS=%s UNRESOLVED_TENSORS=%u\n", fail?"0":"1", unres);
    return fail?1:0;
}
