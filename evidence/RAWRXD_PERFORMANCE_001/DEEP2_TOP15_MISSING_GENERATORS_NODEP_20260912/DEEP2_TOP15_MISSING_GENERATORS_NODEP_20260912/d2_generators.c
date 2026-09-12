#include "d2_generators.h"

static uint64_t d2g_align_down(uint64_t v, uint32_t a){ return a ? (v / a) * a : v; }
static uint64_t d2g_abs_i64(int64_t x){ return (uint64_t)(x < 0 ? -x : x); }

int d2g_token_transaction(uint64_t token_index, D2GTokenTxn* o){
    static const uint32_t seq[8]={D2G_OP_EMBED,D2G_OP_FORWARD,D2G_OP_FINAL_NORM,D2G_OP_KV_ADVANCE,D2G_OP_LM_HEAD,D2G_OP_SAMPLE,D2G_OP_COMMIT,D2G_OP_PREFETCH};
    uint32_t i; if(!o) return D2G_EINVAL; o->token_index=token_index; o->count=8; for(i=0;i<8;i++) o->ops[i]=seq[i]; return D2G_OK;
}

int d2g_dual_finish_plan(uint64_t W,uint64_t c0,uint64_t c1,int64_t ds,uint32_t a,D2GDualPlan* o){
    uint64_t num,den,w0,w1,s0=0,s1; if(!o||!W||!c0||!c1||!a) return D2G_EINVAL;
    den=c0+c1; s1=ds>0?(uint64_t)ds:0; s0=ds<0?d2g_abs_i64(ds):0;
    /* Q16 costs. w0=(c1*W + (S1-S0)<<16)/(c0+c1). Saturate signed skew. */
    if(ds>=0) num=c1*W + (((uint64_t)ds)<<16); else { uint64_t sub=d2g_abs_i64(ds)<<16; uint64_t base=c1*W; num=base>sub?base-sub:0; }
    w0=num/den; if(w0>W) w0=W; w0=d2g_align_down(w0,a); if(w0==0&&W>=a)w0=a; if(w0>W)w0=W;
    w1=W-w0; if(w1 && (w1%a)){ uint64_t r=w1%a; if(w0>=a){w0+=r; w1-=r;} }
    o->work0=w0;o->work1=w1;o->alignment=a;
    o->pred_end0_ns=s0+((c0*w0)>>16); o->pred_end1_ns=s1+((c1*w1)>>16); return D2G_OK;
}

int d2g_persistent_commands(uint64_t sig,uint64_t old,uint64_t ep,uint32_t n,D2GPersistentPlan* o){ if(!o||!n)return D2G_EINVAL;o->signature=sig;o->command_count=n;o->rebuild=(sig!=old);o->epoch=ep+(o->rebuild?1:0);return D2G_OK; }
int d2g_descriptor_bind(uint64_t sig,uint64_t old,uint64_t ep,uint32_t n,D2GDescriptorPlan* o){ if(!o||!n)return D2G_EINVAL;o->resource_signature=sig;o->set_count=n;o->rebind=(sig!=old);o->descriptor_epoch=ep+(o->rebind?1:0);return D2G_OK; }
int d2g_kv_advance(uint64_t pos,uint64_t cap,uint64_t bpt,D2GKvPlan* o){ if(!o||!cap||!bpt)return D2G_EINVAL;o->token_pos=pos;o->slot=pos%cap;o->byte_offset=o->slot*bpt;o->bytes=bpt;o->wrap=(pos>=cap && o->slot==0);return D2G_OK; }
int d2g_residency_request(uint64_t off,uint64_t bytes,uint64_t dl,uint64_t f0,uint64_t f1,uint32_t pin,D2GResidencyReq* o){ if(!o||!bytes)return D2G_EINVAL;o->file_offset=off;o->bytes=bytes;o->deadline_token=dl;o->pin=pin?1u:0u;if(bytes<=f0)o->preferred_tier=D2G_TIER_VRAM0;else if(bytes<=f1)o->preferred_tier=D2G_TIER_VRAM1;else o->preferred_tier=D2G_TIER_RAM;return D2G_OK; }
int d2g_prefetch_nplus1(const D2GResidencyReq* c,uint32_t n,uint64_t tok,D2GPrefetchPlan* o){ uint32_t i;if(!o||(!c&&n))return D2G_EINVAL;if(n>8)n=8;o->count=n;o->for_token=tok;for(i=0;i<n;i++){o->req[i]=c[i];o->req[i].deadline_token=tok;}return D2G_OK; }
int d2g_moe_expert_locality(const uint32_t* e,uint32_t k,uint32_t bias,D2GExpertPlan* o){uint32_t i;if(!o||!e||!k)return D2G_EINVAL;if(k>8)k=8;if(bias>65536)bias=65536;o->count=k;for(i=0;i<k;i++){o->expert[i]=e[i];o->lane[i]=((uint64_t)i*65536u < (uint64_t)k*bias)?0u:1u;}return D2G_OK;}
int d2g_quant_dispatch(uint32_t q,D2GQuantPlan* o){ if(!o)return D2G_EINVAL;o->quant=q;o->packed_native=1;o->fallback_forbidden=1;switch(q){case D2G_Q2_K:o->executor_id=2;break;case D2G_Q3_K:o->executor_id=3;break;case D2G_Q4_K:o->executor_id=4;break;case D2G_Q5_K:o->executor_id=5;break;case D2G_Q6_K:o->executor_id=6;break;case D2G_Q8_0:o->executor_id=8;break;default:o->executor_id=0;o->packed_native=0;return D2G_ECAP;}return D2G_OK;}
int d2g_lm_head_tiles(uint32_t rows,uint32_t tile,uint32_t share,D2GLmHeadPlan* o){uint32_t r0;if(!o||!rows||!tile)return D2G_EINVAL;if(share>65536)share=65536;r0=(uint32_t)(((uint64_t)rows*share)>>16);r0=(uint32_t)d2g_align_down(r0,tile);if(r0>rows)r0=rows;o->row0_begin=0;o->row0_end=r0;o->row1_begin=r0;o->row1_end=rows;o->tile_rows=tile;return D2G_OK;}
int d2g_compact_reduce(uint32_t p,uint64_t n,uint32_t eb,D2GReducePlan* o){if(!o||p<2||!n||!eb)return D2G_EINVAL;o->partial_count=p;o->op=1;o->bytes_in=n*eb*p;o->bytes_out=n*eb;return D2G_OK;}
int d2g_sampler_commit(uint32_t tok,uint64_t le,uint64_t ce,D2GSamplerCommit* o){if(!o||!le)return D2G_EINVAL;o->token_id=tok;o->valid=1;o->logits_epoch=le;o->commit_epoch=ce+1;return D2G_OK;}

static uint32_t d2g_utf8_need(uint8_t b){ if((b&0x80)==0)return 1;if((b&0xE0)==0xC0)return 2;if((b&0xF0)==0xE0)return 3;if((b&0xF8)==0xF0)return 4;return 0; }
int d2g_utf8_chunk(const uint8_t* b,uint32_t n,uint32_t off,uint32_t max,D2GStreamChunk* o){uint32_t i,end,last;if(!o||(!b&&n)||off>n||!max)return D2G_EINVAL;end=off+max;if(end>n)end=n;last=off;i=off;while(i<end){uint32_t need=d2g_utf8_need(b[i]),j;if(!need||i+need>end)break;for(j=1;j<need;j++)if((b[i+j]&0xC0)!=0x80)break;if(j!=need)break;i+=need;last=i;}o->offset=off;o->bytes=last-off;o->final_chunk=(last==n);o->valid_utf8_boundary=1;return (last==off&&off<n)?D2G_ECAP:D2G_OK;}
int d2g_cancel_reset(uint64_t ep,uint32_t cancel,uint32_t reset,D2GResetPlan* o){if(!o)return D2G_EINVAL;o->old_epoch=ep;o->cancel=cancel?1u:0u;o->reset=reset?1u:0u;o->new_epoch=ep+(reset?1u:0u);o->reusable=reset?1u:(cancel?0u:1u);return D2G_OK;}

int d2g_authority_receipt(const D2GAuthorityInput* x,D2GAuthorityReceipt* o){
    uint64_t m=0; uint32_t bit=0;
    #define PASS(c) do{ if(c) m|=(1ull<<bit); else if(o->first_fail_bit==0xFFFFFFFFu)o->first_fail_bit=bit; bit++; }while(0)
    if(!x||!o) return D2G_EINVAL;
    o->pass=0;
    o->first_fail_bit=0xFFFFFFFFu;
    o->pass_mask=0;
    PASS(x->product_linked); PASS(x->packed_live); PASS(x->material_overlap); PASS(x->full_forward); PASS(x->final_norm); PASS(x->lm_head); PASS(x->sampler_commit); PASS(x->kv_advance); PASS(x->output_parity);
    PASS(!x->sealed_logits_reuse); PASS(!x->host_forward_calls); PASS(!x->host_materializations); PASS(!x->cpu_f32_expands); PASS(!x->command_rebuilds); PASS(!x->kv_host_roundtrips); PASS(!x->critical_nvme_reads); PASS(!x->serial_gpu_chain); PASS(!x->weight_migration); PASS(!x->synthetic_io); PASS(!x->device_lost); PASS(!x->external_runtime_calls); PASS(x->gpu0_forwards>0); PASS(x->gpu1_forwards>0);
    o->pass_mask=m;o->pass=(o->first_fail_bit==0xFFFFFFFFu);return o->pass?D2G_OK:D2G_EAUTH;
    #undef PASS
}
