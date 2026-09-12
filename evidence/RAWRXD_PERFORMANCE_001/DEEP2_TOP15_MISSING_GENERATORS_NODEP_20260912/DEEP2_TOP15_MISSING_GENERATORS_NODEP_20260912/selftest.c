#include <stdio.h>
#include <string.h>
#include "d2_generators.h"
#define CHECK(x) do{ if(!(x)){ printf("FAIL line=%d\n",__LINE__); return __LINE__; } }while(0)
int main(void){
 D2GTokenTxn t; D2GDualPlan d; D2GPersistentPlan p; D2GDescriptorPlan db; D2GKvPlan kv; D2GResidencyReq rr,c[2]; D2GPrefetchPlan pf; D2GExpertPlan ex; D2GQuantPlan q; D2GLmHeadPlan lm; D2GReducePlan red; D2GSamplerCommit sc; D2GStreamChunk ch; D2GResetPlan rs; D2GAuthorityInput ai; D2GAuthorityReceipt ar;
 uint32_t experts[4]={7,3,11,2}; const uint8_t utf8[]={0x41,0xE2,0x82,0xAC,0x42};
 CHECK(d2g_token_transaction(9,&t)==0 && t.count==8 && t.ops[3]==D2G_OP_KV_ADVANCE);
 CHECK(d2g_dual_finish_plan(8192,65536,131072,100000,64,&d)==0 && d.work0+d.work1==8192 && d.work0%d.alignment==0);
 CHECK(d2g_persistent_commands(5,5,2,64,&p)==0 && p.rebuild==0 && p.epoch==2);
 CHECK(d2g_descriptor_bind(8,7,3,4,&db)==0 && db.rebind==1 && db.descriptor_epoch==4);
 CHECK(d2g_kv_advance(4096,4096,1024,&kv)==0 && kv.slot==0 && kv.wrap==1);
 CHECK(d2g_residency_request(4096,1024,10,2048,512,1,&rr)==0 && rr.preferred_tier==D2G_TIER_VRAM0); c[0]=rr;c[1]=rr;
 CHECK(d2g_prefetch_nplus1(c,2,11,&pf)==0 && pf.count==2 && pf.req[0].deadline_token==11);
 CHECK(d2g_moe_expert_locality(experts,4,49152,&ex)==0 && ex.count==4);
 CHECK(d2g_quant_dispatch(D2G_Q2_K,&q)==0 && q.packed_native && q.executor_id==2);
 CHECK(d2g_lm_head_tiles(129280,256,43690,&lm)==0 && lm.row0_end==lm.row1_begin && lm.row1_end==129280);
 CHECK(d2g_compact_reduce(2,8192,4,&red)==0 && red.bytes_out==32768);
 CHECK(d2g_sampler_commit(123,77,5,&sc)==0 && sc.commit_epoch==6);
 CHECK(d2g_utf8_chunk(utf8,sizeof(utf8),0,4,&ch)==0 && ch.bytes==4 && ch.valid_utf8_boundary);
 CHECK(d2g_cancel_reset(12,1,1,&rs)==0 && rs.new_epoch==13 && rs.reusable);
 memset(&ai,0,sizeof(ai)); ai.product_linked=ai.packed_live=ai.material_overlap=ai.full_forward=1;ai.final_norm=ai.lm_head=ai.sampler_commit=ai.kv_advance=ai.output_parity=1;ai.gpu0_forwards=ai.gpu1_forwards=1;
 CHECK(d2g_authority_receipt(&ai,&ar)==0 && ar.pass==1);
 ai.critical_nvme_reads=1; CHECK(d2g_authority_receipt(&ai,&ar)==D2G_EAUTH && ar.pass==0);
 puts("DEEP2_TOP15_GENERATORS_SELFTEST=PASS"); puts("GENERATORS=15/15"); puts("LIVE_PRODUCT_RUN=NOT_RUN"); puts("PROMOTE=0"); return 0;
}
