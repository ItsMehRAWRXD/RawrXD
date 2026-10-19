#include "d2_plan.h"
#include "d2_range.h"
#include <string.h>
static const D2ExpertTensorSet *findset(const D2ExpertTensorSet *s,size_t n,uint32_t id){size_t i;for(i=0;i<n;i++)if(s[i].expert_id==id)return &s[i];return 0;}
int d2_plan_token(D2Residency *res,D2Locality *loc,uint64_t token,const uint32_t *sel,size_t n,const D2ExpertTensorSet *sets,size_t sn,const D2PlacementCost *cost,D2TokenPlan *out){
    size_t i,j; int rc;if(!res||!loc||(!sel&&n)||!sets||!cost||!out||n>D2_MAX_SELECTED)return D2_EINVAL;memset(out,0,sizeof(*out));out->token=token;rc=d2_locality_observe(loc,sel,n,token);if(rc)return rc;
    for(i=0;i<n;i++){const D2ExpertTensorSet *s=findset(sets,sn,sel[i]);if(!s)return D2_ENOTFOUND;for(j=0;j<s->range_count;j++){uint32_t d;size_t idx;D2PlanItem *pi;if(out->count>=D2_MAX_RANGES)return D2_ENOSPC;if(!d2_range_valid(&s->ranges[j]))return D2_EINVAL;rc=d2_dual_gpu_choose(res,loc,s->expert_id,s->ranges[j].tensor_id,s->ranges[j].bytes,cost,&d);if(rc)return rc;pi=&out->item[out->count++];pi->range=s->ranges[j];pi->device=d;pi->resident_hit=(d2_residency_find(res,d,pi->range.tensor_id,&idx)==D2_OK);out->bytes_by_device[d]+=pi->range.bytes;}}
    return D2_OK;
}
