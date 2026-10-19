#include "d2u.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

static const d2u_tensor *layer_tensor(const d2u_model*m,uint32_t layer,const char*suffix,char*name,size_t cap){snprintf(name,cap,"blk.%u.%s",layer,suffix);return d2u_tensor_find(m,name);}
static float sigmoidf_safe(float x){if(x>=0){float z=expf(-x);return 1.0f/(1.0f+z);}else{float z=expf(x);return z/(1.0f+z);}}
static void top_indices(const float*s,uint32_t n,uint32_t k,uint32_t*out){uint32_t i,j;for(i=0;i<k;i++){uint32_t best=UINT32_MAX;float bv=-INFINITY;for(j=0;j<n;j++){uint32_t q;int used=0;for(q=0;q<i;q++)if(out[q]==j){used=1;break;}if(!used&&s[j]>bv){bv=s[j];best=j;}}out[i]=best;}}
int d2u_route_deepseek(const d2u_model*m,d2u_authority*a,uint64_t ticket,uint32_t layer,const float*hidden,d2u_route*r){
    const d2u_config*c;const d2u_tensor*w,*bias;char n[D2U_MAX_NAME];float*logits=0,*orig=0,*sel=0,*b=0,*gs=0;uint32_t ne,k,i,g;int rc=0,use_sigmoid=0;
    if(!m||!a||!hidden||!r)return D2U_E_ARG;
    c=&m->cfg; ne=c->expert_count; k=c->expert_used_count;
    if(!ne||!k||k>D2U_MAX_TOPK)return D2U_E_FORMAT;
    w=layer_tensor(m,layer,"ffn_gate_inp.weight",n,sizeof(n));if(!w)return D2U_E_TENSOR;if(w->n_dims<2||w->dims[0]!=c->embedding_length||w->dims[1]!=ne)return D2U_E_FORMAT;
    bias=layer_tensor(m,layer,"exp_probs_b.bias",n,sizeof(n));use_sigmoid=bias!=0;
    logits=(float*)malloc(ne*sizeof(float));orig=(float*)malloc(ne*sizeof(float));sel=(float*)malloc(ne*sizeof(float));if(!logits||!orig||!sel){rc=D2U_E_OOM;goto done;}
    rc=d2u_tensor_gemv(m,a,ticket,w,hidden,c->embedding_length,logits,ne,D2U_IO_CURRENT_TENSOR);if(rc)goto done;
    if(use_sigmoid){for(i=0;i<ne;i++)orig[i]=sigmoidf_safe(logits[i]);}
    else{float mx=logits[0],sum=0;for(i=1;i<ne;i++)if(logits[i]>mx)mx=logits[i];for(i=0;i<ne;i++){orig[i]=expf(logits[i]-mx);sum+=orig[i];}if(!(sum>0)){rc=D2U_E_NUMERIC;goto done;}for(i=0;i<ne;i++)orig[i]/=sum;}
    memcpy(sel,orig,ne*sizeof(float));
    if(bias){b=(float*)malloc(ne*sizeof(float));if(!b){rc=D2U_E_OOM;goto done;}if(bias->n_dims!=1||bias->dims[0]!=ne){rc=D2U_E_FORMAT;goto done;}rc=d2u_tensor_read_row_f32(m,a,ticket,bias,0,b,ne,D2U_IO_CURRENT_TENSOR);if(rc)goto done;for(i=0;i<ne;i++)sel[i]+=b[i];}
    if(c->expert_group_count){
        uint32_t ng=c->expert_group_count,kg=c->expert_group_used_count,per;if(!kg||ng>ne||ne%ng){rc=D2U_E_FORMAT;goto done;}per=ne/ng;gs=(float*)malloc(ng*sizeof(float));if(!gs){rc=D2U_E_OOM;goto done;}
        for(g=0;g<ng;g++){uint32_t j;float best=-INFINITY,second=-INFINITY;for(j=0;j<per;j++){float v=sel[g*per+j];if(v>best){second=best;best=v;}else if(v>second)second=v;}gs[g]=bias?(best+second):best;}
        {uint32_t keep[D2U_MAX_TOPK];uint8_t*ok;if(kg>D2U_MAX_TOPK){rc=D2U_E_FORMAT;goto done;}top_indices(gs,ng,kg,keep);ok=(uint8_t*)calloc(ng,1);if(!ok){rc=D2U_E_OOM;goto done;}for(i=0;i<kg;i++)ok[keep[i]]=1;for(g=0;g<ng;g++)if(!ok[g]){uint32_t j;for(j=0;j<per;j++)sel[g*per+j]=-INFINITY;}free(ok);}
    } else if(bias) { rc=D2U_E_FORMAT; goto done; } /* R1 correction-bias gate requires grouping metadata. */
    r->count=k;top_indices(sel,ne,k,r->ids);{float sum=0,scale=c->expert_weights_scale?c->expert_weights_scale:1.0f;for(i=0;i<k;i++){if(r->ids[i]==UINT32_MAX){rc=D2U_E_NUMERIC;goto done;}r->weights[i]=orig[r->ids[i]];sum+=r->weights[i];}if((use_sigmoid||c->expert_weights_norm)&&sum>0)for(i=0;i<k;i++)r->weights[i]/=sum;for(i=0;i<k;i++)r->weights[i]*=scale;}
 done:free(logits);free(orig);free(sel);free(b);free(gs);return rc;
}
