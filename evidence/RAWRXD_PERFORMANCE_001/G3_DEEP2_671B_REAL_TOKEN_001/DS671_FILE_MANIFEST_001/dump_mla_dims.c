#include "../DS671_FILE_MANIFEST_001/ds671_gguf_scan_priv.h"
#include <stdio.h>
#include <string.h>
int main(void){
  const char*path="F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf";
  GgufR r; char magic[4]; uint32_t ver; uint64_t nt,nk,i;
  if(gr_open(&r,path)||gr_read(&r,magic,4)||gr_u32(&r,&ver)||gr_u64(&r,&nt)||gr_u64(&r,&nk)) return 1;
  for(i=0;i<nk;i++){ char k[160]; uint32_t t; gr_str(&r,k,sizeof k); gr_u32(&r,&t); gr_skip_val(&r,t); }
  for(i=0;i<nt;i++){
    char name[256]; uint32_t nd,ty,d; uint64_t off,dims[4]={0};
    gr_str(&r,name,sizeof name); gr_u32(&r,&nd);
    for(d=0;d<nd&&d<4;d++) gr_u64(&r,&dims[d]);
    gr_u32(&r,&ty); gr_u64(&r,&off);
    if(strstr(name,"attn_k_b")||strstr(name,"attn_v_b")||strstr(name,"attn_q_b")||strstr(name,"attn_kv_a"))
      printf("%s nd=%u dims=%llu,%llu,%llu,%llu type=%u\n",name,nd,
        (unsigned long long)dims[0],(unsigned long long)dims[1],
        (unsigned long long)dims[2],(unsigned long long)dims[3],ty);
  }
  gr_close(&r); return 0;
}
