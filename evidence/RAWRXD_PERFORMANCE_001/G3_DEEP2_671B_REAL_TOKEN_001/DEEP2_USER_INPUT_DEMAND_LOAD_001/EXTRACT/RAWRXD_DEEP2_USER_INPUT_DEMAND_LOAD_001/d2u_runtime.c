#include "d2u.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>

static void rms(float *x,const float*w,size_t n,float eps){double ss=0;size_t i;for(i=0;i<n;i++)ss+=(double)x[i]*x[i];{float q=1.0f/sqrtf((float)(ss/n)+eps);for(i=0;i<n;i++)x[i]=x[i]*q*w[i];}}
static const d2u_tensor *embedding(const d2u_model*m){const d2u_tensor*t=d2u_tensor_find(m,"token_embd.weight");if(!t)t=d2u_tensor_find(m,"tok_embeddings.weight");return t;}
static const d2u_tensor *output_head(const d2u_model*m){const d2u_tensor*t=d2u_tensor_find(m,"output.weight");return t?t:embedding(m);}
int d2u_runtime_open(d2u_runtime*r,uint64_t owner_cookie,int argc,const char**paths){char why[256];int rc;if(!r||!owner_cookie)return D2U_E_ARG;memset(r,0,sizeof(*r));r->owner_cookie=owner_cookie;rc=d2u_model_open(&r->model,argc,paths);if(rc)return rc;rc=d2u_validate_deepseek2(&r->model,why,sizeof(why));if(rc){d2u_model_close(&r->model);return rc;}r->model_valid=1;rc=d2u_authority_init(&r->auth,owner_cookie);if(rc)goto fail;r->auth.product_open_pass=1;rc=d2u_expert_cache_init(&r->expert_cache,16ull*1024*1024*1024);if(rc)goto fail;rc=d2u_mla_cache_init(&r->cache,r->model.cfg.block_count,r->model.cfg.context_length,r->model.cfg.kv_lora_rank,r->model.cfg.rope_dimension_count);if(rc)goto fail;r->hidden=(float*)malloc(r->model.cfg.embedding_length*sizeof(float));r->scratch=(float*)malloc(r->model.cfg.embedding_length*sizeof(float));r->logits=(float*)malloc(r->model.cfg.vocab_size*sizeof(float));if(!r->hidden||!r->scratch||!r->logits){rc=D2U_E_OOM;goto fail;}return 0;
fail:d2u_runtime_close(r);return rc;}
void d2u_runtime_close(d2u_runtime*r){if(!r)return;free(r->hidden);free(r->scratch);free(r->logits);d2u_mla_cache_free(&r->cache);d2u_expert_cache_free(&r->expert_cache);d2u_model_close(&r->model);memset(r,0,sizeof(*r));}
int d2u_runtime_enter(d2u_runtime*r){int rc;if(!r||!r->model_valid)return D2U_E_STATE;rc=d2u_scheduler_claim(&r->auth,r->owner_cookie);if(rc)return rc;r->auth.session_enter_pass=1;return 0;}
int d2u_runtime_step(d2u_runtime*r,uint32_t input_token,uint32_t token_index,uint32_t*output_token){const d2u_tensor*emb,*on,*oh;uint32_t l,i,best=0;uint64_t tk;float bestv;int rc,kvok=0,logitsok=0;if(!r||!output_token||!r->auth.scheduler_authority)return D2U_E_AUTH;if(input_token>=r->model.cfg.vocab_size||token_index>=r->model.cfg.context_length)return D2U_E_RANGE;if(r->auth.failed)return D2U_E_STATE;
    r->auth.decode_authority=0;r->auth.token_commit_pass=0;r->auth.completed_layers=0;
    emb=embedding(&r->model);if(!emb||emb->n_dims<2||emb->dims[0]!=r->model.cfg.embedding_length||input_token>=emb->dims[1])return D2U_E_TENSOR;
    rc=d2u_op_begin(&r->auth,r->owner_cookie,token_index,0,D2U_OP_EMBED,D2U_IO_CURRENT_TOKEN_EMBED,&tk);if(rc)return rc;rc=d2u_tensor_read_row_f32(&r->model,&r->auth,tk,emb,input_token,r->hidden,r->model.cfg.embedding_length,D2U_IO_CURRENT_TOKEN_EMBED);d2u_op_end(&r->auth,r->owner_cookie,tk,rc==0);if(rc)return rc;
    for(l=0;l<r->model.cfg.block_count;l++){
        rc=d2u_mla_forward(&r->model,&r->auth,r->owner_cookie,token_index,l,r->hidden,r->scratch,&r->cache);if(rc)return rc;
        rc=d2u_ffn_layer(&r->model,&r->auth,r->owner_cookie,token_index,l,r->scratch,r->hidden,0,&r->expert_cache);if(rc)return rc;
        rc=d2u_note_layer_complete(&r->auth,l,r->model.cfg.block_count);if(rc)return rc;
    }
    /* Cache commit is an explicit foreground scheduler operation. */
    rc=d2u_op_begin(&r->auth,r->owner_cookie,token_index,r->model.cfg.block_count,D2U_OP_KV_COMMIT,D2U_IO_CURRENT_TENSOR,&tk);if(rc)return rc;kvok=(r->cache.length>=token_index+1);d2u_op_end(&r->auth,r->owner_cookie,tk,kvok);if(!kvok)return D2U_E_STATE;
    on=d2u_tensor_find(&r->model,"output_norm.weight");oh=output_head(&r->model);if(!on||!oh||on->n_dims!=1||on->dims[0]!=r->model.cfg.embedding_length||oh->n_dims<2||oh->dims[0]!=r->model.cfg.embedding_length||oh->dims[1]<r->model.cfg.vocab_size)return D2U_E_TENSOR;
    rc=d2u_op_begin(&r->auth,r->owner_cookie,token_index,r->model.cfg.block_count,D2U_OP_OUTPUT,D2U_IO_CURRENT_OUTPUT_ROW,&tk);if(rc)return rc;rc=d2u_tensor_read_row_f32(&r->model,&r->auth,tk,on,0,r->scratch,r->model.cfg.embedding_length,D2U_IO_CURRENT_OUTPUT_ROW);if(!rc){rms(r->hidden,r->scratch,r->model.cfg.embedding_length,r->model.cfg.rms_norm_eps);rc=d2u_tensor_gemv(&r->model,&r->auth,tk,oh,r->hidden,r->model.cfg.embedding_length,r->logits,r->model.cfg.vocab_size,D2U_IO_CURRENT_OUTPUT_ROW);}d2u_op_end(&r->auth,r->owner_cookie,tk,rc==0);if(rc)return rc;logitsok=1;
    bestv=r->logits[0];for(i=1;i<r->model.cfg.vocab_size;i++)if(r->logits[i]>bestv){bestv=r->logits[i];best=i;}if(!isfinite(bestv))return D2U_E_NUMERIC;
    rc=d2u_mint_decode_authority(&r->auth,r->model.cfg.block_count,kvok,logitsok);if(rc)return rc;
    rc=d2u_op_begin(&r->auth,r->owner_cookie,token_index,r->model.cfg.block_count,D2U_OP_TOKEN_COMMIT,D2U_IO_CURRENT_TENSOR,&tk);if(rc)return rc;d2u_op_end(&r->auth,r->owner_cookie,tk,1);
    rc=d2u_commit_token(&r->auth,r->owner_cookie,best);if(rc)return rc;*output_token=best;(void)d2u_try_promote(&r->auth,r->model_valid);return 0;}
