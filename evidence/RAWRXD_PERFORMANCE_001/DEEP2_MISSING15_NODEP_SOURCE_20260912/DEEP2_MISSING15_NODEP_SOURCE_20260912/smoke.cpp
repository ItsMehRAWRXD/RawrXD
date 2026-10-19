#include "src/d2_nodep.h"
#include <cstdio>

struct Mock { D2LaneReceipt rec[2]; };
static int enq(void*, const D2FabricSlice* s, uint64_t token, D2FabricTicket* t){ t->opaque[0]=s->gpu_index; t->opaque[1]=token; return 1; }
static int collect(void* c, const D2FabricTicket* t, D2LaneReceipt* r){ *r=((Mock*)c)->rec[t->opaque[0]]; return 1; }
static int reduce(void*, const D2FabricTicket*, const D2FabricTicket*, D2ReduceReceipt* r){ r->reduce_ns=200000; r->inter_gpu_bytes=0; r->compact_merge_real=1; return 1; }
int main(){
    D2FabricPlan p{}; if(!d2_plan_rows_bw(8192,640,624,16384,&p)) return 2;
    std::printf("ROWS=%u/%u\\n",p.lane[0].row_count,p.lane[1].row_count);
    Mock m{}; m.rec[0]={1000000,48000000,p.lane[0].local_weight_bytes,1,0,1}; m.rec[1]={1200000,47900000,p.lane[1].local_weight_bytes,1,0,1};
    D2SsVkBinding b{&m,enq,collect,reduce}; if(!d2_bind_ssvk(&b)) return 3;
    D2FabricMetrics f{}; if(!d2_submit_same_token(&p,7,&f)) return 4;
    D2AuthorityInput a{0,0,0,0,f};
    std::printf("OVERLAP_NS=%llu\\n",(unsigned long long)f.overlap_ns);
    std::printf("AGGREGATE_EFFECTIVE_BPS=%llu\\n",(unsigned long long)f.aggregate_effective_bps);
    std::printf("AUTHORITY_FAIL_CLOSED=%s\\n", d2_authority_gate(&a)?"FAIL":"PASS");
    std::printf("NOTE=MOCK_ONLY_NO_PRODUCT_AUTHORITY\\n");
    return 0;
}
