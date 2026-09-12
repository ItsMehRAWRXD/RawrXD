#include "deep2_endurance.h"
void d2_watch_init(D2ProgressWatch *w,uint64_t m){if(w){w->last_serial=0;w->stagnant_ticks=0;w->max_stagnant_ticks=m?m:1;}}
int d2_watch_tick(D2ProgressWatch *w,uint64_t s){if(!w)return D2_EINVAL;if(s!=w->last_serial){w->last_serial=s;w->stagnant_ticks=0;return D2_OK;}if(++w->stagnant_ticks>=w->max_stagnant_ticks)return D2_ESTALL;return D2_OK;}
