#include "deep2_endurance.h"
int d2_range_validate(const D2TensorRange *r,uint64_t shard){uint32_t i;if(!r||!r->bytes||r->ndims>4)return D2_EINVAL;if(r->offset>shard||r->bytes>shard-r->offset)return D2_EBOUNDS;for(i=0;i<r->ndims;i++)if(!r->dims[i])return D2_EINVAL;return D2_OK;}
int d2_range_contains(const D2TensorRange *r,uint64_t o,uint64_t b){if(!r||!b)return D2_EINVAL;if(o<r->offset||o-r->offset>r->bytes)return D2_EBOUNDS;if(b>r->bytes-(o-r->offset))return D2_EBOUNDS;return D2_OK;}
