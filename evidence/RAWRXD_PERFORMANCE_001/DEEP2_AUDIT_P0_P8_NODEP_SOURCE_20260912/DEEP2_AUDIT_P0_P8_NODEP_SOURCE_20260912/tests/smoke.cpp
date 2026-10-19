#include "deep2_audit_nodep.h"
#include <stdio.h>
#include <string.h>

struct MockEngine { uint64_t cookie; };
static int me_open(void* c,const char*,uint64_t* out){ MockEngine* m=(MockEngine*)c; m->cookie=0xD2; *out=m->cookie; return 1; }
static int me_gen(void*,uint64_t,const char*,uint32_t n,volatile uint32_t* cancel,
                  int (*cb)(void*,const char*,uint32_t),void* u,uint64_t* out){
    *out=0; for(uint32_t i=0;i<n;i++){ if(*cancel) return 0; if(!cb(u,"x",1)) return 0; (*out)++; } return 1;
}
static int me_reset(void*,uint64_t){ return 1; }
static int me_close(void*,uint64_t){ return 1; }
static int tok(void*,const char*,uint32_t){ return 1; }

struct MockVk{};
static int vk_load(void*,const D2DeviceRange*){ return 1; }
static int vk_enq(void*,const D2DeviceRange* r,uint64_t,D2SubmitTicket* t){ t->opaque[0]=r->gpu; return 1; }
static int vk_col(void*,const D2SubmitTicket* t,D2LaneReceipt* r){
    memset(r,0,sizeof(*r)); r->start_ns=t->opaque[0]?120:100; r->end_ns=t->opaque[0]?300:290;
    r->local_weight_bytes=64ull<<20; r->real_forwards=1; return 1;
}
static int vk_red(void*,const D2SubmitTicket*,const D2SubmitTicket*,D2MergeReceipt* r){ memset(r,0,sizeof(*r)); r->reduce_ns=10; r->compact_merge_real=1; return 1; }

int main(){
    D2AuthorityState st{}; d2_apply_external_full_tps_authority(&st,1);
    MockEngine me{}; D2EngineOps eo{&me,me_open,me_gen,me_reset,me_close}; D2DailySession ds{};
    if(!d2_daily_bind(&ds,&eo,"model.gguf")) return 10;
    uint64_t n=0; if(!d2_daily_generate(&ds,"a",2,tok,0,&n)) return 11;
    if(!d2_daily_generate(&ds,"b",2,tok,0,&n)) return 12;
    if(!d2_daily_ready(&ds)) return 13;
    d2_daily_close(&ds);

    MockVk mv{}; D2SsVkOps vo{&mv,vk_load,vk_enq,vk_col,vk_red};
    D2DeviceRange a{0,0,64ull<<20,0,4148}, b{1,64ull<<20,64ull<<20,4148,4044}; D2AggregateMetrics m{};
    if(!d2_dual_submit(&vo,&a,&b,1,&m)) return 20;
    if(d2_aggregate_authoritative(&m,0,0,0)) return 21; /* mock must fail authority */

    D2Missing15Bits bits{}; for(int i=0;i<15;i++) bits.bit[i]=1;
    D2Next4State n4{1,1,1,1,0,0};
    st.daily_streamer_ready=1; st.stage_timing_authority=0; st.packed_q2k_ready=0; st.deviceio_ssvk_ready=0;
    st.aggregate_bw_authority=0; st.missing15_ready=d2_missing15_all(&bits); st.model_size_next4_ready=d2_next4_ready(&n4); st.ide_sse_cancel_ready=0;
    st.promote=d2_compute_promotion(&st,1);
    printf("FULL_MODEL_TPS_AUTHORITY=%u\n",st.full_model_tps_authority);
    printf("DAILY_STREAMER_READY=%u\n",st.daily_streamer_ready);
    printf("MOCK_AGGREGATE_AUTHORITY=%d\n",d2_aggregate_authoritative(&m,0,0,0));
    printf("PROMOTE=%u\n",st.promote);
    return (st.full_model_tps_authority==1 && st.promote==0) ? 0 : 30;
}
