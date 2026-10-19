#include "Deep2DeepSeekDualStickAdapter.hpp"

namespace Deep2 { namespace dsv3 {
static uint64_t Cost(void*p,unsigned g,int pref,uint64_t b,int hit){
    (void)pref; DualStickCtx*c=(DualStickCtx*)p; return c->api.est?c->api.est(g,hit,b):1ull;
}
static unsigned Assign(void*p,int pref,uint64_t b,int hit){
    DualStickCtx*c=(DualStickCtx*)p; return c->api.assign?c->api.assign(pref,b,hit):0u;
}
static int Resident(void*p,uint32_t l,int e,unsigned*s){
    DualStickCtx*c=(DualStickCtx*)p; return c->api.resident?c->api.resident((int)l,e,s):0;
}
static int Prefetch(void*p,uint32_t l,int e,unsigned g){
    DualStickCtx*c=(DualStickCtx*)p; return c->api.prefetch?c->api.prefetch((int)l,e,g):0;
}
Hooks MakeDualStickHooks(DualStickCtx&c){ Hooks h{&c,Cost,Assign,Resident,Prefetch}; return h; }
}}
