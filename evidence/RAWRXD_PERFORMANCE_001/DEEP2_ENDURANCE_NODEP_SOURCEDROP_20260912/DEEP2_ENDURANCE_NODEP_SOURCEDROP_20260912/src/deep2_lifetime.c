#include "deep2_endurance.h"
#include <string.h>
void d2_life_init(D2Lifetime *l){if(l)memset(l,0,sizeof *l);}
int d2_life_create(D2Lifetime *l){if(!l)return D2_EINVAL;l->creates++;l->live++;if(l->live>l->peak_live)l->peak_live=l->live;return D2_OK;}
int d2_life_destroy(D2Lifetime *l){if(!l||!l->live)return D2_ESTATE;l->destroys++;l->live--;return D2_OK;}
int d2_life_finalize(const D2Lifetime *l){return l&&l->live==0&&l->creates==l->destroys?D2_OK:D2_ESTATE;}
