#include "d2_locality.h"
#include <string.h>
void d2_locality_init(D2Locality *l){ if(l) memset(l,0,sizeof(*l)); }
int d2_locality_observe(D2Locality *l,const uint32_t *ids,size_t n,uint64_t token){
    size_t i; if(!l || (!ids && n) || n>D2_MAX_SELECTED) return D2_EINVAL;
    for(i=0;i<D2_MAX_EXPERTS;i++) l->expert[i].selected_now=0;
    l->token=token;
    for(i=0;i<n;i++){
        uint32_t id=ids[i]; if(id>=D2_MAX_EXPERTS) return D2_EINVAL;
        l->expert[id].selected_now=1; l->expert[id].last_token=token;
        if(l->expert[id].hits!=UINT64_MAX) l->expert[id].hits++;
    }
    return D2_OK;
}
uint64_t d2_locality_score(const D2Locality *l,uint32_t id,uint32_t dev,uint64_t bytes){
    uint64_t age, recency, freq, resident, size_penalty;
    if(!l || id>=D2_MAX_EXPERTS || dev>=D2_MAX_DEVICES) return 0;
    age = l->token>=l->expert[id].last_token ? l->token-l->expert[id].last_token : 0;
    recency = age>=1024 ? 0 : (1024-age)*1000000ULL;
    freq = l->expert[id].hits>1000000ULL?1000000ULL:l->expert[id].hits;
    resident = (l->expert[id].resident_mask&(1u<<dev)) ? 2000000000ULL:0;
    size_penalty = bytes>>12;
    return resident + recency + freq*4096ULL + (l->expert[id].selected_now?4000000000ULL:0) - (size_penalty<resident+recency?size_penalty:0);
}
int d2_locality_mark_resident(D2Locality *l,uint32_t id,uint32_t dev,uint64_t bytes,int resident){
    if(!l || id>=D2_MAX_EXPERTS || dev>=D2_MAX_DEVICES) return D2_EINVAL;
    if(resident){ l->expert[id].resident_mask|=(1u<<dev); l->expert[id].resident_bytes[dev]=bytes; }
    else { l->expert[id].resident_mask&=~(1u<<dev); l->expert[id].resident_bytes[dev]=0; }
    return D2_OK;
}
