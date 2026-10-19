#include "ss_model_plan_io.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
  FILE *f; char arch[64]; uint32_t align=32,nd,ty; uint64_t nt,i,j,elems,off,dims[4],maxrel=0; SsModelPlan tmp; SsPlanEnt *e;
  const char *path="F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00002-of-00011.gguf";
  memset(&tmp,0,sizeof tmp); f=fopen(path,"rb"); ss_mp_read_meta(f,&tmp,arch,&align,&nt,0);
  e=calloc((size_t)nt,sizeof(SsPlanEnt));
  for(i=0;i<nt;i++){ elems=1; ss_mp_rstr(f,e[i].name,sizeof e[i].name); ss_mp_rd(f,&nd,4);
    for(j=0;j<nd;j++){ss_mp_rd(f,&dims[j],8);elems*=dims[j];} ss_mp_rd(f,&ty,4); ss_mp_rd(f,&off,8);
    e[i].rel=off; e[i].ty=ty; e[i].elems=elems; e[i].nd=nd; if(off>maxrel)maxrel=off; }
  _fseeki64(f,0,SEEK_END); printf("file_size=%llu nt=%llu maxrel=%llu\n",(unsigned long long)_ftelli64(f),(unsigned long long)nt,(unsigned long long)maxrel);
  for(i=0;i<nt;i++) if(e[i].rel==maxrel) printf("LAST %s ty=%u elems=%llu\n",e[i].name,e[i].ty,(unsigned long long)e[i].elems);
  free(e); fclose(f); return 0;
}
