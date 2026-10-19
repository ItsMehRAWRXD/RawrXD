#include "d2u.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

static const d2u_tensor *lt(const d2u_model *m, uint32_t l, const char *s, char *n, size_t z) {
    snprintf(n, z, "blk.%u.%s", l, s);
    return d2u_tensor_find(m, n);
}
static void silu_mul(float *g, const float *u, size_t n) {
    size_t i; for (i=0;i<n;i++) { float z=g[i]; g[i]=(z/(1.0f+expf(-z)))*u[i]; }
}
static void rms(float *x,const float *w,size_t n,float eps) {
    double ss=0; size_t i; for(i=0;i<n;i++)ss+=(double)x[i]*x[i];
    { float q=1.0f/sqrtf((float)(ss/n)+eps); for(i=0;i<n;i++)x[i]=x[i]*q*w[i]; }
}
static int row_info(const d2u_tensor *t, uint64_t *rb) {
    size_t bs,bb; if(!t||!rb)return D2U_E_ARG; bs=d2u_type_block_size(t->type); bb=d2u_type_bytes_per_block(t->type);
    if(!bs||!bb||!t->n_dims||t->dims[0]%bs)return D2U_E_FORMAT;
    *rb=(t->dims[0]/bs)*bb; return 0;
}
static int raw_gemv(uint32_t type,const uint8_t *raw,uint64_t rb,size_t rows,size_t cols,const float *x,float *y) {
    size_t bs=d2u_type_block_size(type),bb=d2u_type_bytes_per_block(type),nb=cols/bs,r,b,j,nv,pos;
    float tmp[256]; int rc;
    for(r=0;r<rows;r++) { float s=0; pos=0;
        for(b=0;b<nb;b++) { rc=d2u_dequant_block(type,raw+r*(size_t)rb+b*bb,tmp,256,&nv); if(rc)return rc;
            for(j=0;j<nv;j++)s+=tmp[j]*x[pos+j];
            pos+=nv; }
        y[r]=s;
    }
    return 0;
}
static int expert_slice_bytes(const d2u_tensor *t, uint64_t *slice) {
    uint64_t rb; int rc=row_info(t,&rb); if(rc)return rc; if(t->n_dims!=3)return D2U_E_FORMAT;
    if(rb>UINT64_MAX/t->dims[1])return D2U_E_RANGE;
    *slice=rb*t->dims[1]; return 0;
}
int d2u_expert_cache_init(d2u_expert_cache *c,uint64_t budget_bytes) {
    if(!c||!budget_bytes)return D2U_E_ARG;
    memset(c,0,sizeof(*c)); c->budget_bytes=budget_bytes; return 0;
}
void d2u_expert_cache_free(d2u_expert_cache *c) {
    size_t i; if(!c)return; for(i=0;i<c->count;i++){free(c->entries[i].gate);free(c->entries[i].up);free(c->entries[i].down);}free(c->entries);memset(c,0,sizeof(*c));
}
static d2u_cached_expert *cache_find(d2u_expert_cache *c,uint32_t layer,uint32_t expert) {
    size_t i; for(i=0;i<c->count;i++)if(c->entries[i].layer==layer&&c->entries[i].expert==expert)return &c->entries[i]; return 0;
}
static void cache_remove(d2u_expert_cache *c,size_t idx) {
    d2u_cached_expert *e=&c->entries[idx]; c->used_bytes-=e->bytes; free(e->gate);free(e->up);free(e->down);
    if(idx+1<c->count)memmove(&c->entries[idx],&c->entries[idx+1],(c->count-idx-1)*sizeof(*c->entries));
    c->count--; c->evictions++;
}
static int cache_evict_for(d2u_expert_cache *c,uint64_t need) {
    if(need>c->budget_bytes)return D2U_E_BUDGET;
    while(c->used_bytes>c->budget_bytes-need && c->count){size_t i,best=0;uint64_t tick=c->entries[0].tick;for(i=1;i<c->count;i++)if(c->entries[i].tick<tick){tick=c->entries[i].tick;best=i;}cache_remove(c,best);}
    return c->used_bytes<=c->budget_bytes-need?0:D2U_E_BUDGET;
}
static int cache_load(d2u_expert_cache *c,const d2u_model *m,d2u_authority *a,uint64_t tk,uint32_t layer,uint32_t expert,const d2u_tensor *g,const d2u_tensor *u,const d2u_tensor *d,d2u_cached_expert **out) {
    uint64_t gb,ub,db,total; d2u_cached_expert e,*p; int rc; size_t nc;
    if((rc=expert_slice_bytes(g,&gb))||(rc=expert_slice_bytes(u,&ub))||(rc=expert_slice_bytes(d,&db)))return rc;
    if(gb>UINT64_MAX-ub||gb+ub>UINT64_MAX-db)return D2U_E_RANGE;
    total=gb+ub+db; if((rc=cache_evict_for(c,total)))return rc;
    memset(&e,0,sizeof(e)); e.layer=layer;e.expert=expert;e.bytes=total;e.gate_bytes=gb;e.up_bytes=ub;e.down_bytes=db;e.tick=++c->tick;
    e.gate=(uint8_t*)malloc((size_t)gb);e.up=(uint8_t*)malloc((size_t)ub);e.down=(uint8_t*)malloc((size_t)db);if(!e.gate||!e.up||!e.down){free(e.gate);free(e.up);free(e.down);return D2U_E_OOM;}
    rc=d2u_tensor_read(m,a,tk,g,(uint64_t)expert*gb,e.gate,(size_t)gb,D2U_IO_ROUTER_TOPK_EXPERT);
    if(!rc)rc=d2u_tensor_read(m,a,tk,u,(uint64_t)expert*ub,e.up,(size_t)ub,D2U_IO_ROUTER_TOPK_EXPERT);
    if(!rc)rc=d2u_tensor_read(m,a,tk,d,(uint64_t)expert*db,e.down,(size_t)db,D2U_IO_ROUTER_TOPK_EXPERT);
    if(rc){free(e.gate);free(e.up);free(e.down);return rc;}
    if(c->count==c->cap){nc=c->cap?c->cap*2:64;p=(d2u_cached_expert*)realloc(c->entries,nc*sizeof(*p));if(!p){free(e.gate);free(e.up);free(e.down);return D2U_E_OOM;}c->entries=p;c->cap=nc;}
    c->entries[c->count]=e;c->used_bytes+=total;c->misses++;*out=&c->entries[c->count++];return 0;
}
static int cache_get(d2u_expert_cache *c,const d2u_model *m,d2u_authority *a,uint64_t tk,uint32_t layer,uint32_t expert,const d2u_tensor *g,const d2u_tensor *u,const d2u_tensor *d,d2u_cached_expert **out) {
    d2u_cached_expert *e=cache_find(c,layer,expert); if(e){e->tick=++c->tick;c->hits++;*out=e;return 0;} return cache_load(c,m,a,tk,layer,expert,g,u,d,out);
}
static int read_norm(const d2u_model *m,d2u_authority *a,uint64_t owner,uint32_t tok,uint32_t layer,const d2u_tensor *t,float *x,size_t n) {
    float *w; uint64_t tk; int rc; if(!t||t->n_dims!=1||t->dims[0]!=n)return D2U_E_FORMAT; w=(float*)malloc(n*sizeof(float));if(!w)return D2U_E_OOM;
    rc=d2u_op_begin(a,owner,tok,layer,D2U_OP_NORM,D2U_IO_CURRENT_TENSOR,&tk); if(!rc)rc=d2u_tensor_read_row_f32(m,a,tk,t,0,w,n,D2U_IO_CURRENT_TENSOR); d2u_op_end(a,owner,tk,rc==0); if(!rc)rms(x,w,n,m->cfg.rms_norm_eps);free(w);return rc;
}
static int dense_ffn(const d2u_model *m,d2u_authority *a,uint64_t owner,uint32_t tok,uint32_t layer,const float *x,float *out) {
    char n[D2U_MAX_NAME]; const d2u_tensor *g=lt(m,layer,"ffn_gate.weight",n,sizeof(n)),*u=lt(m,layer,"ffn_up.weight",n,sizeof(n)),*d=lt(m,layer,"ffn_down.weight",n,sizeof(n));
    size_t H=m->cfg.embedding_length,F; float *gv,*uv; uint64_t tk=0; int rc;
    if(!g||!u||!d||g->n_dims<2)return D2U_E_TENSOR;
    F=(size_t)g->dims[1]; if(u->dims[1]!=F||d->dims[0]!=F||d->dims[1]!=H)return D2U_E_FORMAT;
    gv=(float*)malloc(F*sizeof(float));uv=(float*)malloc(F*sizeof(float));if(!gv||!uv){free(gv);free(uv);return D2U_E_OOM;}
    rc=d2u_op_begin(a,owner,tok,layer,D2U_OP_DENSE_FFN,D2U_IO_CURRENT_TENSOR,&tk); if(!rc)rc=d2u_tensor_gemv(m,a,tk,g,x,H,gv,F,D2U_IO_CURRENT_TENSOR); if(!rc)rc=d2u_tensor_gemv(m,a,tk,u,x,H,uv,F,D2U_IO_CURRENT_TENSOR); if(!rc){silu_mul(gv,uv,F);rc=d2u_tensor_gemv(m,a,tk,d,gv,F,out,H,D2U_IO_CURRENT_TENSOR);} d2u_op_end(a,owner,tk,rc==0);free(gv);free(uv);return rc;
}
static int shared_ffn(const d2u_model *m,d2u_authority *a,uint64_t owner,uint32_t tok,uint32_t layer,const float *x,float *out) {
    char n[D2U_MAX_NAME]; const d2u_tensor *g=lt(m,layer,"ffn_gate_shexp.weight",n,sizeof(n)),*u=lt(m,layer,"ffn_up_shexp.weight",n,sizeof(n)),*d=lt(m,layer,"ffn_down_shexp.weight",n,sizeof(n));
    size_t H=m->cfg.embedding_length,F; float *gv,*uv; uint64_t tk=0; int rc;
    if(!g||!u||!d||g->n_dims<2||u->n_dims<2||d->n_dims<2)return D2U_E_TENSOR;
    F=(size_t)g->dims[1];if(g->dims[0]!=H||u->dims[0]!=H||u->dims[1]!=F||d->dims[0]!=F||d->dims[1]!=H)return D2U_E_FORMAT;
    gv=(float*)malloc(F*sizeof(float));uv=(float*)malloc(F*sizeof(float));if(!gv||!uv){free(gv);free(uv);return D2U_E_OOM;}
    rc=d2u_op_begin(a,owner,tok,layer,D2U_OP_SHARED_EXPERT,D2U_IO_SHARED_EXPERT,&tk);if(!rc)rc=d2u_tensor_gemv(m,a,tk,g,x,H,gv,F,D2U_IO_SHARED_EXPERT);if(!rc)rc=d2u_tensor_gemv(m,a,tk,u,x,H,uv,F,D2U_IO_SHARED_EXPERT);if(!rc){silu_mul(gv,uv,F);rc=d2u_tensor_gemv(m,a,tk,d,gv,F,out,H,D2U_IO_SHARED_EXPERT);}d2u_op_end(a,owner,tk,rc==0);free(gv);free(uv);return rc;
}
static int routed_ffn(const d2u_model *m,d2u_authority *a,uint64_t owner,uint32_t tok,uint32_t layer,const float *x,float *out,d2u_route *r,d2u_expert_cache *cache) {
    char n[D2U_MAX_NAME]; const d2u_tensor *g=lt(m,layer,"ffn_gate_exps.weight",n,sizeof(n)),*u=lt(m,layer,"ffn_up_exps.weight",n,sizeof(n)),*d=lt(m,layer,"ffn_down_exps.weight",n,sizeof(n));
    size_t H=m->cfg.embedding_length,F;float *gv,*uv,*ev;uint64_t tk=0,grb,urb,drb;uint32_t q;int rc;
    if(!cache||!g||!u||!d||g->n_dims!=3)return D2U_E_TENSOR;
    F=(size_t)g->dims[1];if(g->dims[0]!=H||g->dims[2]!=m->cfg.expert_count||u->dims[0]!=H||u->dims[1]!=F||u->dims[2]!=g->dims[2]||d->dims[0]!=F||d->dims[1]!=H||d->dims[2]!=g->dims[2])return D2U_E_FORMAT;
    if(row_info(g,&grb)||row_info(u,&urb)||row_info(d,&drb))return D2U_E_FORMAT;
    gv=(float*)malloc(F*sizeof(float));uv=(float*)malloc(F*sizeof(float));ev=(float*)malloc(H*sizeof(float));if(!gv||!uv||!ev){free(gv);free(uv);free(ev);return D2U_E_OOM;}memset(out,0,H*sizeof(float));
    rc=d2u_op_begin(a,owner,tok,layer,D2U_OP_EXPERT,D2U_IO_ROUTER_TOPK_EXPERT,&tk);if(rc)goto done;
    for(q=0;q<r->count&&!rc;q++){d2u_cached_expert *ce=0;uint32_t e=r->ids[q];size_t i;rc=cache_get(cache,m,a,tk,layer,e,g,u,d,&ce);if(rc)break;rc=raw_gemv(g->type,ce->gate,grb,F,H,x,gv);if(!rc)rc=raw_gemv(u->type,ce->up,urb,F,H,x,uv);if(!rc){silu_mul(gv,uv,F);rc=raw_gemv(d->type,ce->down,drb,H,F,gv,ev);}if(!rc)for(i=0;i<H;i++)out[i]+=r->weights[q]*ev[i];}
    d2u_op_end(a,owner,tk,rc==0);
done: free(gv);free(uv);free(ev);return rc;
}
int d2u_ffn_layer(const d2u_model *m,d2u_authority *a,uint64_t owner,uint32_t tok,uint32_t layer,const float *hidden,float *out,d2u_route *route_out,d2u_expert_cache *cache) {
    size_t H;float *x=0,*ff=0,*sh=0;char n[D2U_MAX_NAME];const d2u_tensor *norm;uint64_t tk=0;int rc;d2u_route r;memset(&r,0,sizeof(r));
    if(!m||!a||!hidden||!out)return D2U_E_ARG;
    H=m->cfg.embedding_length;x=(float*)malloc(H*sizeof(float));ff=(float*)malloc(H*sizeof(float));sh=(float*)calloc(H,sizeof(float));if(!x||!ff||!sh){rc=D2U_E_OOM;goto done;}memcpy(x,hidden,H*sizeof(float));norm=lt(m,layer,"ffn_norm.weight",n,sizeof(n));if(!norm){rc=D2U_E_TENSOR;goto done;}rc=read_norm(m,a,owner,tok,layer,norm,x,H);if(rc)goto done;
    if(layer<m->cfg.leading_dense_block_count){rc=dense_ffn(m,a,owner,tok,layer,x,ff);if(rc)goto done;}
    else{rc=d2u_op_begin(a,owner,tok,layer,D2U_OP_ROUTER,D2U_IO_CURRENT_TENSOR,&tk);if(rc)goto done;rc=d2u_route_deepseek(m,a,tk,layer,x,&r);d2u_op_end(a,owner,tk,rc==0);if(rc)goto done;rc=routed_ffn(m,a,owner,tok,layer,x,ff,&r,cache);if(rc)goto done;if(m->cfg.expert_shared_count){rc=shared_ffn(m,a,owner,tok,layer,x,sh);if(rc)goto done;}}
    {size_t i;for(i=0;i<H;i++)out[i]=hidden[i]+ff[i]+sh[i];}if(route_out)*route_out=r;
done: free(x);free(ff);free(sh);return rc;
}
