#include "deep2_endurance.h"
#include <string.h>
size_t d2_kv_words_required(uint32_t l,uint32_t p){uint64_t bits=(uint64_t)l*p;return (size_t)((bits+63)/64);}
int d2_kv_init(D2KvGuard *k,uint32_t l,uint32_t p,uint64_t e,uint64_t *w,size_t n){size_t need;if(!k||!l||!p||!w)return D2_EINVAL;need=d2_kv_words_required(l,p);if(n<need)return D2_ECAP;k->layers=l;k->max_positions=p;k->epoch=e;k->written_bits=w;k->written_words=need;memset(w,0,need*sizeof *w);return D2_OK;}
static int idx(const D2KvGuard *k,uint32_t l,uint32_t p,size_t *wi,uint64_t *mask){uint64_t b;if(!k||l>=k->layers||p>=k->max_positions)return D2_EBOUNDS;b=(uint64_t)l*k->max_positions+p;*wi=(size_t)(b>>6);*mask=UINT64_C(1)<<(b&63);return D2_OK;}
int d2_kv_mark_write(D2KvGuard *k,uint32_t l,uint32_t p,uint64_t e){size_t w;uint64_t m;int rc;if(!k||e!=k->epoch)return D2_ESTATE;rc=idx(k,l,p,&w,&m);if(rc)return rc;if(k->written_bits[w]&m)return D2_ESTATE;k->written_bits[w]|=m;return D2_OK;}
int d2_kv_require_read(const D2KvGuard *k,uint32_t l,uint32_t p,uint64_t e){size_t w;uint64_t m;int rc;if(!k||e!=k->epoch)return D2_ESTATE;rc=idx(k,l,p,&w,&m);if(rc)return rc;return (k->written_bits[w]&m)?D2_OK:D2_ESTATE;}
int d2_kv_reset(D2KvGuard *k,uint64_t e){if(!k||e==k->epoch)return D2_EINVAL;memset(k->written_bits,0,k->written_words*sizeof(uint64_t));k->epoch=e;return D2_OK;}
