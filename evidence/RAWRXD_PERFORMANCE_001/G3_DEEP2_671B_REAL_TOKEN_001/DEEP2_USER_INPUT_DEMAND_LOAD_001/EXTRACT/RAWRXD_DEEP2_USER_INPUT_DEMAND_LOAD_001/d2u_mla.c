#include "d2u.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

static const d2u_tensor *lt(const d2u_model*m,uint32_t l,const char*s,char*n,size_t z){snprintf(n,z,"blk.%u.%s",l,s);return d2u_tensor_find(m,n);}
static float dot(const float*a,const float*b,size_t n){float s=0;size_t i;for(i=0;i<n;i++)s+=a[i]*b[i];return s;}
static int load_vec(const d2u_model*m,d2u_authority*a,uint64_t tk,const d2u_tensor*t,float*v,size_t n){if(!t||t->n_dims!=1||t->dims[0]!=n)return D2U_E_FORMAT;return d2u_tensor_read_row_f32(m,a,tk,t,0,v,n,D2U_IO_CURRENT_TENSOR);}
static void rms(float*x,const float*w,size_t n,float eps){double ss=0;size_t i;for(i=0;i<n;i++)ss+=(double)x[i]*x[i];{float s=1.0f/sqrtf((float)(ss/n)+eps);for(i=0;i<n;i++)x[i]=x[i]*s*w[i];}}
static int ticket_gemv(const d2u_model*m,d2u_authority*a,uint64_t owner,uint32_t tok,uint32_t layer,d2u_op_kind op,const d2u_tensor*t,const float*x,size_t xn,float*y,size_t yn){uint64_t tk;int rc=d2u_op_begin(a,owner,tok,layer,op,D2U_IO_CURRENT_TENSOR,&tk);if(rc)return rc;rc=d2u_tensor_gemv(m,a,tk,t,x,xn,y,yn,D2U_IO_CURRENT_TENSOR);d2u_op_end(a,owner,tk,rc==0);return rc;}
static float yarn_freq(const d2u_config*c,uint32_t pair){
    float dim=(float)c->rope_dimension_count,base=c->rope_freq_base?c->rope_freq_base:10000.0f,factor=c->rope_scaling_factor?c->rope_scaling_factor:1.0f;
    float freq=1.0f/powf(base,(2.0f*pair)/dim);float orig=c->rope_scaling_original_context_length;
    if(factor<=1.0f||orig<=0.0f||c->context_length<=(uint32_t)orig)return freq;
    {float bf=c->rope_scaling_beta_fast?c->rope_scaling_beta_fast:32.0f,bs=c->rope_scaling_beta_slow?c->rope_scaling_beta_slow:1.0f;
     float lo=dim*logf(orig/(bf*2.0f*3.14159265358979323846f))/(2.0f*logf(base));
     float hi=dim*logf(orig/(bs*2.0f*3.14159265358979323846f))/(2.0f*logf(base));
     lo=floorf(lo);hi=ceilf(hi);if(lo<0)lo=0;if(hi>dim/2-1)hi=dim/2-1;
     {float smooth;if((float)pair<=lo)smooth=0.0f;else if((float)pair>=hi)smooth=1.0f;else smooth=((float)pair-lo)/(hi-lo+1e-6f);return freq*((1.0f-smooth)+smooth/factor);}}
}
static void rope_apply(float*x,uint32_t dim,uint32_t pos,const d2u_config*c){uint32_t i;for(i=0;i<dim/2;i++){float th=(float)pos*yarn_freq(c,i),cs=cosf(th),sn=sinf(th),a=x[2*i],b=x[2*i+1];x[2*i]=a*cs-b*sn;x[2*i+1]=a*sn+b*cs;}}
static int ensure_cache(d2u_mla_cache*c,uint32_t need){
    uint32_t nc;size_t ln,pn;float*nl,*np;if(need<=c->capacity)return 0;if(need>c->max_context)return D2U_E_RANGE;nc=c->capacity?c->capacity:16;while(nc<need){if(nc>c->max_context/2){nc=c->max_context;break;}nc*=2;}
    ln=(size_t)nc*c->layers*c->kv_rank;pn=(size_t)nc*c->layers*c->rope_dim;nl=(float*)realloc(c->latent,ln*sizeof(float));if(!nl)return D2U_E_OOM;c->latent=nl;np=(float*)realloc(c->pe,pn*sizeof(float));if(!np)return D2U_E_OOM;c->pe=np;c->capacity=nc;return 0;
}
int d2u_mla_cache_init(d2u_mla_cache*c,uint32_t layers,uint32_t maxctx,uint32_t kvr,uint32_t rd){if(!c||!layers||!maxctx||!kvr||!rd)return D2U_E_ARG;memset(c,0,sizeof(*c));c->layers=layers;c->max_context=maxctx;c->kv_rank=kvr;c->rope_dim=rd;return ensure_cache(c,maxctx<16?maxctx:16);}
void d2u_mla_cache_free(d2u_mla_cache*c){if(!c)return;free(c->latent);free(c->pe);memset(c,0,sizeof(*c));}

int d2u_mla_forward(const d2u_model*m,d2u_authority*a,uint64_t owner,uint32_t token,uint32_t layer,const float*hidden,float*out,d2u_mla_cache*cache){
    const d2u_config*c;char nm[D2U_MAX_NAME];const d2u_tensor *tn,*qa,*qan,*qb,*kva,*kvn,*kb,*vb,*wo;uint32_t H,RQ,RK,RD,VH,NH,QD;float *x=0,*nw=0,*qz=0,*q=0,*kvz=0,*lat=0,*kpe=0,*ctx=0,*headv=0,*proj=0,*qabs=0,*scores=0;uint64_t tk;uint32_t h,p,i,v;int rc=0;
    if(!m||!a||!hidden||!out||!cache)return D2U_E_ARG;
    c=&m->cfg; H=c->embedding_length; RQ=c->q_lora_rank; RK=c->kv_lora_rank; RD=c->rope_dimension_count; VH=c->v_head_dim; NH=c->attention_head_count; QD=c->qk_nope_head_dim+RD;
    if(!H||!RQ||!RK||!RD||!VH||!NH)return D2U_E_FORMAT;
    if(layer>=c->block_count||token>=cache->max_context)return D2U_E_RANGE;
    if((rc=ensure_cache(cache,token+1)))return rc;
    tn=lt(m,layer,"attn_norm.weight",nm,sizeof(nm));qa=lt(m,layer,"attn_q_a.weight",nm,sizeof(nm));qan=lt(m,layer,"attn_q_a_norm.weight",nm,sizeof(nm));qb=lt(m,layer,"attn_q_b.weight",nm,sizeof(nm));kva=lt(m,layer,"attn_kv_a_mqa.weight",nm,sizeof(nm));kvn=lt(m,layer,"attn_kv_a_norm.weight",nm,sizeof(nm));kb=lt(m,layer,"attn_k_b.weight",nm,sizeof(nm));vb=lt(m,layer,"attn_v_b.weight",nm,sizeof(nm));wo=lt(m,layer,"attn_output.weight",nm,sizeof(nm));
    if(!tn||!qa||!qan||!qb||!kva||!kvn||!kb||!vb||!wo)return D2U_E_TENSOR;
    x=(float*)malloc(H*sizeof(float));nw=(float*)malloc(H*sizeof(float));qz=(float*)malloc(RQ*sizeof(float));q=(float*)malloc((size_t)NH*QD*sizeof(float));kvz=(float*)malloc((RK+RD)*sizeof(float));lat=(float*)malloc(RK*sizeof(float));kpe=(float*)malloc(RD*sizeof(float));ctx=(float*)calloc(RK,sizeof(float));headv=(float*)malloc((size_t)NH*VH*sizeof(float));proj=(float*)malloc(H*sizeof(float));qabs=(float*)malloc(RK*sizeof(float));scores=(float*)malloc((token+1)*sizeof(float));if(!x||!nw||!qz||!q||!kvz||!lat||!kpe||!ctx||!headv||!proj||!qabs||!scores){rc=D2U_E_OOM;goto done;}
    memcpy(x,hidden,H*sizeof(float));
    /* Q operation owns norm + q_a + q norm + q_b reads. */
    rc=d2u_op_begin(a,owner,token,layer,D2U_OP_MLA_Q,D2U_IO_CURRENT_TENSOR,&tk);if(rc)goto done;
    rc=load_vec(m,a,tk,tn,nw,H);if(!rc){rms(x,nw,H,c->rms_norm_eps);rc=d2u_tensor_gemv(m,a,tk,qa,x,H,qz,RQ,D2U_IO_CURRENT_TENSOR);}if(!rc){rc=load_vec(m,a,tk,qan,nw,RQ);if(!rc)rms(qz,nw,RQ,c->rms_norm_eps);}if(!rc)rc=d2u_tensor_gemv(m,a,tk,qb,qz,RQ,q,(size_t)NH*QD,D2U_IO_CURRENT_TENSOR);d2u_op_end(a,owner,tk,rc==0);if(rc)goto done;
    for(h=0;h<NH;h++)rope_apply(q+(size_t)h*QD+c->qk_nope_head_dim,RD,token,c);
    /* KV latent + positional key. */
    rc=d2u_op_begin(a,owner,token,layer,D2U_OP_MLA_KV,D2U_IO_CURRENT_TENSOR,&tk);if(rc)goto done;rc=d2u_tensor_gemv(m,a,tk,kva,x,H,kvz,RK+RD,D2U_IO_CURRENT_TENSOR);if(!rc){memcpy(lat,kvz,RK*sizeof(float));memcpy(kpe,kvz+RK,RD*sizeof(float));rc=load_vec(m,a,tk,kvn,nw,RK);if(!rc)rms(lat,nw,RK,c->rms_norm_eps);}d2u_op_end(a,owner,tk,rc==0);if(rc)goto done;rope_apply(kpe,RD,token,c);
    memcpy(cache->latent+((size_t)token*cache->layers+layer)*RK,lat,RK*sizeof(float));memcpy(cache->pe+((size_t)token*cache->layers+layer)*RD,kpe,RD*sizeof(float));if(cache->length<token+1)cache->length=token+1;
    /* Absorbed attention score: q_nope*K_B -> latent rank, then latent-cache dot. */
    rc=d2u_op_begin(a,owner,token,layer,D2U_OP_MLA_SCORE,D2U_IO_CURRENT_TENSOR,&tk);if(rc)goto done;
    for(h=0;h<NH&&!rc;h++){
        float *qh=q+(size_t)h*QD;for(i=0;i<RK;i++){uint64_t row=(uint64_t)h*RK+i;rc=d2u_tensor_dot_row(m,a,tk,kb,row,qh,c->qk_nope_head_dim,&qabs[i],D2U_IO_CURRENT_TENSOR);if(rc)break;}
        if(rc)break;
        {float mx=-INFINITY,sum=0,scale=1.0f/sqrtf((float)(c->qk_nope_head_dim+RD));float factor=c->rope_scaling_factor?c->rope_scaling_factor:1.0f;if(factor>1.0f){float mp=c->rope_scaling_mscale?c->rope_scaling_mscale:1.0f;float ms=0.1f*mp*logf(factor)+1.0f;scale*=ms*ms;}
         for(p=0;p<=token;p++){const float*lc=cache->latent+((size_t)p*cache->layers+layer)*RK;const float*pc=cache->pe+((size_t)p*cache->layers+layer)*RD;scores[p]=scale*(dot(qabs,lc,RK)+dot(qh+c->qk_nope_head_dim,pc,RD));if(scores[p]>mx)mx=scores[p];}
         for(p=0;p<=token;p++){scores[p]=expf(scores[p]-mx);sum+=scores[p];}if(!(sum>0)){rc=D2U_E_NUMERIC;break;}memset(ctx,0,RK*sizeof(float));for(p=0;p<=token;p++){float z=scores[p]/sum;const float*lc=cache->latent+((size_t)p*cache->layers+layer)*RK;for(i=0;i<RK;i++)ctx[i]+=z*lc[i];}
         for(v=0;v<VH;v++){uint64_t row=(uint64_t)h*VH+v;rc=d2u_tensor_dot_row(m,a,tk,vb,row,ctx,RK,&headv[(size_t)h*VH+v],D2U_IO_CURRENT_TENSOR);if(rc)break;}}
    }
    d2u_op_end(a,owner,tk,rc==0);if(rc)goto done;
    rc=ticket_gemv(m,a,owner,token,layer,D2U_OP_MLA_OUT,wo,headv,(size_t)NH*VH,proj,H);if(rc)goto done;for(i=0;i<H;i++)out[i]=hidden[i]+proj[i];
 done:free(x);free(nw);free(qz);free(q);free(kvz);free(lat);free(kpe);free(ctx);free(headv);free(proj);free(qabs);free(scores);return rc;
}
