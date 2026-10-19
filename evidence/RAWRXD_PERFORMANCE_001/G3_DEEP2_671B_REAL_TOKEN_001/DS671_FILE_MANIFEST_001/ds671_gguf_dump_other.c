/* ds671_gguf_dump_other.c — print class-7 names from shard1 */
#include "ds671_gguf_scan_priv.h"
#include <stdio.h>
#include <string.h>
int main(void) {
    const char *path =
        "F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
    GgufR r; char magic[4]; uint32_t ver=0; uint64_t nt=0,nk=0,i;
    if (gr_open(&r,path)||gr_read(&r,magic,4)||gr_u32(&r,&ver)||gr_u64(&r,&nt)||gr_u64(&r,&nk))
        return 1;
    for (i=0;i<nk;i++){ char k[160]; uint32_t t; gr_str(&r,k,sizeof k); gr_u32(&r,&t); gr_skip_val(&r,t); }
    for (i=0;i<nt;i++){
        char name[256]; uint32_t nd=0,ty=0,d; uint64_t off=0;
        gr_str(&r,name,sizeof name); gr_u32(&r,&nd);
        for(d=0;d<nd;d++){ uint64_t dim; gr_u64(&r,&dim);} gr_u32(&r,&ty); gr_u64(&r,&off);
        if (!strstr(name,"token_embd") && !strstr(name,"output") && !strstr(name,"norm") &&
            !strstr(name,"attn_") && !strstr(name,"ffn_"))
            printf("OTHER %s type=%u\n", name, ty);
    }
    gr_close(&r); return 0;
}
