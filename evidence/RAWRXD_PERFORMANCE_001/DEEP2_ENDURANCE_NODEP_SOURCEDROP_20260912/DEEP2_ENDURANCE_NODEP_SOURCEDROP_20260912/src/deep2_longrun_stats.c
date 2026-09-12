#include "deep2_endurance.h"
#include <string.h>
static unsigned lg2u(uint64_t v){unsigned n=0;while(v>1&&n<31){v>>=1;n++;}return n;}
void d2_stats_init(D2LongStats *s){if(s){memset(s,0,sizeof *s);s->min_ns=UINT64_MAX;}}
void d2_stats_add(D2LongStats *s,uint64_t ns){if(!s)return;s->count++;if(ns<s->min_ns)s->min_ns=ns;if(ns>s->max_ns)s->max_ns=ns;s->sum_ns+=(long double)ns;s->buckets[lg2u(ns)]++;}
uint64_t d2_stats_mean(const D2LongStats *s){return !s||!s->count?0:(uint64_t)(s->sum_ns/(long double)s->count);}
uint64_t d2_stats_p50_approx(const D2LongStats *s){uint64_t want,seen=0;unsigned i;if(!s||!s->count)return 0;want=(s->count+1)/2;for(i=0;i<32;i++){seen+=s->buckets[i];if(seen>=want)return UINT64_C(1)<<i;}return s->max_ns;}
