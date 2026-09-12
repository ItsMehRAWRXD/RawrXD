#include "deep2_endurance.h"
#include <stdio.h>
#include <string.h>
#define CHECK(x) do{int _r=(x);if(_r!=D2_OK){printf("FAIL line=%d rc=%d\n",__LINE__,_r);return 1;}}while(0)
int main(void){
  unsigned char arena_mem[4096]; D2Arena a; CHECK(d2_arena_init(&a,arena_mem,sizeof arena_mem)); if(!d2_arena_alloc(&a,128,64))return 2; CHECK(d2_arena_freeze(&a)); CHECK(d2_arena_check(&a));
  uint64_t kvmem[8]; D2KvGuard kv; CHECK(d2_kv_init(&kv,4,64,1,kvmem,8)); CHECK(d2_kv_mark_write(&kv,2,5,1)); CHECK(d2_kv_require_read(&kv,2,5,1));
  D2DecodeInvariant inv; CHECK(d2_inv_init(&inv,16)); for(uint64_t p=0;p<16;p++){CHECK(d2_inv_forward(&inv,p,1,0));CHECK(d2_inv_commit(&inv,p));CHECK(d2_inv_advance(&inv,p+1));} CHECK(d2_inv_finalize(&inv));
  D2ResidencyEntry ents[8]; D2Residency res; CHECK(d2_res_init(&res,ents,8,1024,1024)); CHECK(d2_res_admit(&res,1,256,1,D2_HOT)); CHECK(d2_res_pin(&res,1,1)); CHECK(d2_res_unpin(&res,1,1)); CHECK(d2_res_check(&res)); CHECK(d2_res_evict_unpinned(&res,D2_HOT,256));
  D2FenceSlot fs[2]; D2FenceRing fr; size_t sl; uint64_t ser; CHECK(d2_fence_init(&fr,fs,2)); CHECK(d2_fence_acquire(&fr,&sl,&ser)); CHECK(d2_fence_signal(&fr,sl,ser)); CHECK(d2_fence_recycle(&fr,sl,ser));
  D2Lifetime life; d2_life_init(&life); CHECK(d2_life_create(&life)); CHECK(d2_life_destroy(&life)); CHECK(d2_life_finalize(&life));
  D2LongStats st; d2_stats_init(&st); d2_stats_add(&st,100); d2_stats_add(&st,200); if(d2_stats_mean(&st)!=150)return 3;
  D2Journal j; CHECK(d2_journal_open(&j,"smoke_receipt.txt")); CHECK(d2_journal_record(&j,"DEEP2_ENDURANCE_SMOKE","PASS")); CHECK(d2_journal_record_u64(&j,"GENERATED",16)); CHECK(d2_journal_close(&j));
  printf("DEEP2_ENDURANCE_NODEP_SMOKE=PASS\n");
  printf("SEALED_LOGITS_REUSE_COUNT=%llu\n",(unsigned long long)inv.sealed_logits_reuse_count);
  printf("COUNTER_PARITY=%d\n", inv.forward_calls==inv.full_block_forward_calls && inv.forward_calls==inv.commit_calls && inv.forward_calls==inv.advance_calls && inv.forward_calls==inv.generated_tokens);
  return 0;
}
