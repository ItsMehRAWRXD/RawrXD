#include "d2u.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#if !defined(_WIN32)
#include <sys/types.h>
#endif

static int rd(FILE *f, void *p, size_t n) { return fread(p,1,n,f)==n ? D2U_OK : D2U_E_IO; }
static int skip(FILE *f, uint64_t n) {
#if defined(_WIN32)
    return _fseeki64(f, (__int64)n, SEEK_CUR)==0 ? D2U_OK : D2U_E_IO;
#else
    return fseek(f, (long)n, SEEK_CUR)==0 ? D2U_OK : D2U_E_IO;
#endif
}
static uint64_t tell64(FILE *f) {
#if defined(_WIN32)
    __int64 p=_ftelli64(f); return p<0?UINT64_MAX:(uint64_t)p;
#else
    long p=ftell(f); return p<0?UINT64_MAX:(uint64_t)p;
#endif
}
static uint64_t file_size(FILE *f) {
    uint64_t cur=tell64(f), end;
    if(cur==UINT64_MAX) return 0;
#if defined(_WIN32)
    if(_fseeki64(f,0,SEEK_END)!=0) return 0; end=(uint64_t)_ftelli64(f); _fseeki64(f,(__int64)cur,SEEK_SET);
#else
    if(fseek(f,0,SEEK_END)!=0) return 0;
    end=(uint64_t)ftell(f);
    if(fseek(f,(long)cur,SEEK_SET)!=0) return 0;
#endif
    return end;
}
static int read_string(FILE *f, char **out, uint64_t *len_out) {
    uint64_t n=0; char *p;
    if(rd(f,&n,8)) return D2U_E_IO;
    if(n > (1ull<<30)) return D2U_E_FORMAT;
    p=(char*)malloc((size_t)n+1); if(!p) return D2U_E_OOM;
    if(n && rd(f,p,(size_t)n)){free(p);return D2U_E_IO;}
    p[n]=0; *out=p; if(len_out)*len_out=n; return D2U_OK;
}

static int skip_value(FILE *f, uint32_t type);
static int skip_array(FILE *f) {
    uint32_t et=0; uint64_t n=0,i;
    if(rd(f,&et,4)||rd(f,&n,8)) return D2U_E_IO;
    if(n > (1ull<<40)) return D2U_E_FORMAT;
    for(i=0;i<n;i++){int rc=skip_value(f,et);if(rc)return rc;}
    return D2U_OK;
}
static int skip_value(FILE *f, uint32_t type) {
    static const uint8_t sz[13]={1,1,2,2,4,4,4,1,0,0,8,8,8};
    uint64_t n;
    if(type>12) return D2U_E_FORMAT;
    if(type==8){if(rd(f,&n,8))return D2U_E_IO;return skip(f,n);}
    if(type==9)return skip_array(f);
    return skip(f,sz[type]);
}

static int keyeq(const char *a,const char *b){return strcmp(a,b)==0;}
static void set_u32(d2u_config *c,const char*k,uint64_t v){
#define SETU(KEY,FIELD) if(keyeq(k,KEY)){c->FIELD=(uint32_t)v;return;}
    SETU("general.alignment",alignment)
    SETU("deepseek2.block_count",block_count)
    SETU("deepseek2.leading_dense_block_count",leading_dense_block_count)
    SETU("deepseek2.embedding_length",embedding_length)
    SETU("deepseek2.feed_forward_length",feed_forward_length)
    SETU("deepseek2.vocab_size",vocab_size)
    SETU("deepseek2.context_length",context_length)
    SETU("deepseek2.expert_count",expert_count)
    SETU("deepseek2.expert_used_count",expert_used_count)
    SETU("deepseek2.expert_shared_count",expert_shared_count)
    SETU("deepseek2.attention.q_lora_rank",q_lora_rank)
    SETU("deepseek2.attention.kv_lora_rank",kv_lora_rank)
    SETU("deepseek2.attention.qk_nope_head_dim",qk_nope_head_dim)
    SETU("deepseek2.rope.dimension_count",rope_dimension_count)
    SETU("deepseek2.attention.v_head_dim",v_head_dim)
    SETU("deepseek2.attention.head_count",attention_head_count)
    SETU("deepseek2.attention.key_length",attention_key_length)
    SETU("deepseek2.attention.value_length",attention_value_length)
    SETU("deepseek2.expert_feed_forward_length",expert_feed_forward_length)
    SETU("deepseek2.expert_group_count",expert_group_count)
    SETU("deepseek2.expert_group_used_count",expert_group_used_count)
#undef SETU
}
static void set_f(d2u_config*c,const char*k,double v){
#define SETF(KEY,FIELD) if(keyeq(k,KEY)){c->FIELD=(float)v;return;}
    SETF("deepseek2.expert_weights_scale",expert_weights_scale)
    SETF("deepseek2.attention.layer_norm_rms_epsilon",rms_norm_eps)
    SETF("deepseek2.attention.rms_norm_epsilon",rms_norm_eps)
    SETF("deepseek2.rope.freq_base",rope_freq_base)
    SETF("deepseek2.rope.scaling.factor",rope_scaling_factor)
    SETF("deepseek2.rope.scaling.original_context_length",rope_scaling_original_context_length)
    SETF("deepseek2.rope.scaling.beta_fast",rope_scaling_beta_fast)
    SETF("deepseek2.rope.scaling.beta_slow",rope_scaling_beta_slow)
    SETF("deepseek2.rope.scaling.mscale",rope_scaling_mscale)
    SETF("deepseek2.rope.scaling.mscale_all_dim",rope_scaling_mscale_all_dim)
#undef SETF
}
static int capture_value(FILE*f,d2u_config*c,const char*k,uint32_t type){
    uint8_t u8; int8_t i8; uint16_t u16; int16_t i16; uint32_t u32; int32_t i32; uint64_t u64; int64_t i64; float f32; double f64; char*s=0;
    switch(type){
    case 0: if(rd(f,&u8,1))return D2U_E_IO; set_u32(c,k,u8); break;
    case 1: if(rd(f,&i8,1))return D2U_E_IO; set_u32(c,k,(uint64_t)(int64_t)i8); break;
    case 2: if(rd(f,&u16,2))return D2U_E_IO; set_u32(c,k,u16); break;
    case 3: if(rd(f,&i16,2))return D2U_E_IO; set_u32(c,k,(uint64_t)(int64_t)i16); break;
    case 4: if(rd(f,&u32,4))return D2U_E_IO; set_u32(c,k,u32); break;
    case 5: if(rd(f,&i32,4))return D2U_E_IO; set_u32(c,k,(uint64_t)(int64_t)i32); break;
    case 6: if(rd(f,&f32,4))return D2U_E_IO; set_f(c,k,f32); break;
    case 7: if(rd(f,&u8,1))return D2U_E_IO; if(keyeq(k,"deepseek2.expert_weights_norm"))c->expert_weights_norm=u8?1:0; break;
    case 8: if(read_string(f,&s,0))return D2U_E_IO; if(keyeq(k,"general.architecture")){strncpy(c->architecture,s,sizeof(c->architecture)-1);} else if(keyeq(k,"general.name")){strncpy(c->name,s,sizeof(c->name)-1);} free(s); break;
    case 9: return skip_array(f);
    case 10: if(rd(f,&u64,8))return D2U_E_IO; set_u32(c,k,u64); break;
    case 11: if(rd(f,&i64,8))return D2U_E_IO; set_u32(c,k,(uint64_t)i64); break;
    case 12: if(rd(f,&f64,8))return D2U_E_IO; set_f(c,k,f64); break;
    default:return D2U_E_FORMAT;
    }
    return D2U_OK;
}

size_t d2u_type_block_size(uint32_t type){
    switch(type){case D2U_Q4_0:case D2U_Q4_1:case D2U_Q5_0:case D2U_Q5_1:case D2U_Q8_0:case D2U_Q8_1:return 32;
    case D2U_Q2_K:case D2U_Q3_K:case D2U_Q4_K:case D2U_Q5_K:case D2U_Q6_K:case D2U_Q8_K:return 256;
    default:return 1;}
}
size_t d2u_type_bytes_per_block(uint32_t type){
    switch(type){
    case D2U_F32:return 4; case D2U_F16:return 2; case D2U_BF16:return 2;
    case D2U_Q4_0:return 18; case D2U_Q4_1:return 20; case D2U_Q5_0:return 22; case D2U_Q5_1:return 24; case D2U_Q8_0:return 34; case D2U_Q8_1:return 40;
    case D2U_Q2_K:return 84; case D2U_Q3_K:return 110; case D2U_Q4_K:return 144; case D2U_Q5_K:return 176; case D2U_Q6_K:return 210; case D2U_Q8_K:return 292;
    default:return 0;}
}
static int tensor_bytes(uint32_t type,uint64_t n,uint64_t*out){
    size_t bs=d2u_type_block_size(type), bb=d2u_type_bytes_per_block(type);uint64_t blocks;
    if(!bb||!bs)return D2U_E_TYPE;
    if(bs>1 && n%bs)return D2U_E_FORMAT;
    blocks=n/bs; if(blocks>UINT64_MAX/bb)return D2U_E_RANGE;*out=blocks*bb;return 0;
}
static int append_tensor(d2u_model*m,const d2u_tensor*t){
    size_t nc; d2u_tensor*p;
    if(m->tensor_count==m->tensor_cap){nc=m->tensor_cap?m->tensor_cap*2:512;p=(d2u_tensor*)realloc(m->tensors,nc*sizeof(*p));if(!p)return D2U_E_OOM;m->tensors=p;m->tensor_cap=nc;}
    m->tensors[m->tensor_count++]=*t;return 0;
}
static int parse_shard(d2u_model*m,uint32_t si,const char*path){
    d2u_shard*s=&m->shards[si];uint32_t magic=0,ver=0;uint64_t nt=0,nk=0,i;int rc;
    memset(s,0,sizeof(*s));strncpy(s->path,path,sizeof(s->path)-1);s->fp=fopen(path,"rb");if(!s->fp)return D2U_E_IO;s->size=file_size(s->fp);if(!s->size)return D2U_E_IO;
    if(rd(s->fp,&magic,4)||rd(s->fp,&ver,4)||rd(s->fp,&nt,8)||rd(s->fp,&nk,8))return D2U_E_IO;
    if(magic!=D2U_GGUF_MAGIC||ver<2||ver>3)return D2U_E_FORMAT;
    s->gguf_version=ver; s->tensor_count=nt; s->kv_count=nk;
    for(i=0;i<nk;i++){char*k=0;uint32_t ty=0;if((rc=read_string(s->fp,&k,0)))return rc;if(rd(s->fp,&ty,4)){free(k);return D2U_E_IO;}rc=capture_value(s->fp,&m->cfg,k,ty);free(k);if(rc)return rc;}
    for(i=0;i<nt;i++){
        d2u_tensor t;char*n=0;uint32_t d,j;uint64_t rel=0,prod=1;memset(&t,0,sizeof(t));t.shard=si;
        if((rc=read_string(s->fp,&n,0)))return rc;
        strncpy(t.name,n,sizeof(t.name)-1); free(n);
        if(rd(s->fp,&d,4))return D2U_E_IO;
        if(!d||d>D2U_MAX_DIMS)return D2U_E_FORMAT;
        t.n_dims=d;
        for(j=0;j<d;j++){if(rd(s->fp,&t.dims[j],8))return D2U_E_IO;if(!t.dims[j]||prod>UINT64_MAX/t.dims[j])return D2U_E_RANGE;prod*=t.dims[j];}
        t.n_elem=prod;if(rd(s->fp,&t.type,4)||rd(s->fp,&rel,8))return D2U_E_IO;
        if((rc=tensor_bytes(t.type,t.n_elem,&t.size_bytes)))return rc;
        t.data_offset=rel; if((rc=append_tensor(m,&t)))return rc;
    }
    {uint64_t p=tell64(s->fp),a=m->cfg.alignment?m->cfg.alignment:32;if(p==UINT64_MAX)return D2U_E_IO;s->data_offset=(p+a-1)/a*a;}
    /* Add this shard's data base only to tensors parsed from it. */
    for(i=0;i<m->tensor_count;i++)if(m->tensors[i].shard==si){
        if(m->tensors[i].data_offset > UINT64_MAX-s->data_offset)return D2U_E_RANGE;
        m->tensors[i].data_offset += s->data_offset;
        if(m->tensors[i].data_offset > s->size || m->tensors[i].size_bytes > s->size-m->tensors[i].data_offset)return D2U_E_FORMAT;
    }
    return 0;
}

const d2u_tensor *d2u_tensor_find(const d2u_model*m,const char*name){size_t i;if(!m||!name)return 0;for(i=0;i<m->tensor_count;i++)if(strcmp(m->tensors[i].name,name)==0)return &m->tensors[i];return 0;}
static const d2u_tensor *find_suffix(const d2u_model*m,const char*suf){size_t i,n=strlen(suf);for(i=0;i<m->tensor_count;i++){size_t k=strlen(m->tensors[i].name);if(k>=n&&strcmp(m->tensors[i].name+k-n,suf)==0)return &m->tensors[i];}return 0;}
static void derive(d2u_model*m){
    const d2u_tensor*k,*v,*e,*kvb,*qb;
    k=find_suffix(m,"attn_k_b.weight");v=find_suffix(m,"attn_v_b.weight");e=find_suffix(m,"ffn_gate_exps.weight");
    kvb=find_suffix(m,"attn_kv_b.weight");qb=find_suffix(m,"attn_q_b.weight");
    if(k&&k->n_dims>=3){if(!m->cfg.qk_nope_head_dim){m->cfg.qk_nope_head_dim=(uint32_t)k->dims[0];m->cfg.derived_qk_nope=1;}if(!m->cfg.kv_lora_rank)m->cfg.kv_lora_rank=(uint32_t)k->dims[1];if(!m->cfg.attention_head_count)m->cfg.attention_head_count=(uint32_t)k->dims[2];}
    if(v&&v->n_dims>=3){if(!m->cfg.v_head_dim){m->cfg.v_head_dim=(uint32_t)v->dims[1];m->cfg.derived_v_head=1;}if(!m->cfg.attention_head_count)m->cfg.attention_head_count=(uint32_t)v->dims[2];}
    /* This R1 GGUF uses fused attn_kv_b + key_length/value_length KV (no separate k_b/v_b). */
    if(!m->cfg.qk_nope_head_dim && m->cfg.attention_key_length && m->cfg.rope_dimension_count
       && m->cfg.attention_key_length>m->cfg.rope_dimension_count){
        m->cfg.qk_nope_head_dim=m->cfg.attention_key_length-m->cfg.rope_dimension_count;m->cfg.derived_qk_nope=1;}
    if(!m->cfg.v_head_dim && m->cfg.attention_value_length){
        m->cfg.v_head_dim=m->cfg.attention_value_length;m->cfg.derived_v_head=1;}
    if(qb&&qb->n_dims>=2&&m->cfg.attention_head_count&&!m->cfg.qk_nope_head_dim&&m->cfg.rope_dimension_count){
        uint64_t per=qb->dims[1]/m->cfg.attention_head_count;
        if(per>m->cfg.rope_dimension_count){m->cfg.qk_nope_head_dim=(uint32_t)(per-m->cfg.rope_dimension_count);m->cfg.derived_qk_nope=1;}}
    if(kvb&&kvb->n_dims>=2&&!m->cfg.kv_lora_rank)m->cfg.kv_lora_rank=(uint32_t)kvb->dims[0];
    if(e&&e->n_dims>=3){if(!m->cfg.embedding_length)m->cfg.embedding_length=(uint32_t)e->dims[0];if(!m->cfg.expert_feed_forward_length)m->cfg.expert_feed_forward_length=(uint32_t)e->dims[1];if(!m->cfg.expert_count)m->cfg.expert_count=(uint32_t)e->dims[2];}
    if(!m->cfg.expert_weights_scale)m->cfg.expert_weights_scale=1.0f;
    if(!m->cfg.rms_norm_eps)m->cfg.rms_norm_eps=1e-6f;
    if(!m->cfg.rope_freq_base)m->cfg.rope_freq_base=10000.0f;
    if(!m->cfg.rope_scaling_factor)m->cfg.rope_scaling_factor=1.0f;
    if(!m->cfg.rope_scaling_original_context_length)m->cfg.rope_scaling_original_context_length=(float)m->cfg.context_length;
    if(!m->cfg.rope_scaling_beta_fast)m->cfg.rope_scaling_beta_fast=32.0f;
    if(!m->cfg.rope_scaling_beta_slow)m->cfg.rope_scaling_beta_slow=1.0f;
}
int d2u_model_open(d2u_model*m,int argc,const char**paths){int i,rc;if(!m||argc<=0||(unsigned)argc>D2U_MAX_SHARDS||!paths)return D2U_E_ARG;memset(m,0,sizeof(*m));m->cfg.alignment=32;for(i=0;i<argc;i++){rc=parse_shard(m,(uint32_t)i,paths[i]);if(rc){d2u_model_close(m);return rc;}m->shard_count++;}derive(m);return 0;}
void d2u_model_close(d2u_model*m){uint32_t i;if(!m)return;for(i=0;i<D2U_MAX_SHARDS;i++)if(m->shards[i].fp){fclose(m->shards[i].fp);m->shards[i].fp=0;}free(m->tensors);memset(m,0,sizeof(*m));}
int d2u_validate_deepseek2(d2u_model*m,char*why,size_t wn){
#define FAIL(MSG) do{if(why&&wn){strncpy(why,MSG,wn-1);why[wn-1]=0;}return D2U_E_FORMAT;}while(0)
    d2u_config*c;if(!m)return D2U_E_ARG;c=&m->cfg;if(strcmp(c->architecture,"deepseek2")!=0)FAIL("general.architecture != deepseek2");
    if(!c->block_count||!c->embedding_length||!c->expert_count||!c->expert_used_count)FAIL("required architecture dimensions missing");
    if(c->expert_used_count>D2U_MAX_TOPK||c->expert_used_count>c->expert_count)FAIL("invalid expert top-k");
    if(!c->q_lora_rank||!c->kv_lora_rank||!c->qk_nope_head_dim||!c->rope_dimension_count||!c->v_head_dim||!c->attention_head_count)FAIL("MLA dimensions incomplete");
    if(!d2u_tensor_find(m,"token_embd.weight")&&!d2u_tensor_find(m,"tok_embeddings.weight"))FAIL("token embedding tensor missing");
    if(c->leading_dense_block_count>c->block_count)FAIL("dense block count exceeds block count");
    if(why&&wn){strncpy(why,"PASS",wn-1);why[wn-1]=0;}return 0;
#undef FAIL
}
