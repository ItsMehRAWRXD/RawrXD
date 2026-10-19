#include "ss_model_plan.h"
#include <stdio.h>
#include <string.h>
int main(void){
  SsModelPlan p; uint32_t i, miss=0;
  memset(&p,0,sizeof p);
  ss_model_plan_build_split("F:\\OllamaModels\\DeepSeek-R1-Q4_K_M-COMPLETE\\DeepSeek-R1-Q4_K_M-00001-of-00011.gguf",&p);
  for(i=0;i<p.blockCount;i++){
    const SsBlockPlan *b=&p.blocks[i];
    if(!b->ffnNorm.present){ printf("MISS_FFN_NORM blk=%u roles=%u moe=%u\n",i,b->rolesBound,b->isMoe); miss++; }
    if(!b->attnNorm.present) printf("MISS_ATTN_NORM blk=%u\n",i);
    if(b->isMoe && (!b->router.present||!b->expertGate.present||!b->expertUp.present||!b->expertDown.present||!b->sharedGate.present))
      printf("MISS_MOE_PARTS blk=%u r=%d g=%d u=%d d=%d sh=%d\n",i,b->router.present,b->expertGate.present,b->expertUp.present,b->expertDown.present,b->sharedGate.present);
  }
  printf("MISS_FFN_NORM_COUNT=%u\n",miss);
  return 0;
}
