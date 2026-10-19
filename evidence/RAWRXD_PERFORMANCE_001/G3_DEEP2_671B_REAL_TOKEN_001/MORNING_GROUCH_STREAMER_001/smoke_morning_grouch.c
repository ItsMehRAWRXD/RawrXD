/* smoke_morning_grouch.c */
#include "morning_grouch.h"
#include <stdio.h>

int main(void)
{
    mg_counters c;
    mg_counters_clear(&c);
    mg_on_touch(&c, MG_COLD, 1000, 50, 1, 0);   /* expert first touch */
    mg_on_touch(&c, MG_WARM, 1000, 1, 1, 0);    /* reuse */
    mg_on_touch(&c, MG_HOT, 1000, 1, 0, 0);     /* hot non-expert */
    mg_on_touch(&c, MG_COLD, 1, 1, 0, 1);       /* speculative → reject */
    printf("MG_LOADS=%llu MG_BYTES=%llu WARM=%llu HOT=%llu\n",
           (unsigned long long)c.morning_grouch_loads,
           (unsigned long long)c.morning_grouch_bytes,
           (unsigned long long)c.warm_cache_hits,
           (unsigned long long)c.hot_gpu_hits);
    printf("EXP_FIRST=%llu EXP_REUSE=%llu REJECT_SPEC=%llu\n",
           (unsigned long long)c.expert_first_touches,
           (unsigned long long)c.expert_reuses,
           (unsigned long long)c.rejected_speculative);
    if (c.morning_grouch_loads != 1 || c.morning_grouch_bytes != 1000) return 1;
    if (c.warm_cache_hits != 1 || c.hot_gpu_hits != 1) return 1;
    if (c.expert_first_touches != 1 || c.expert_reuses != 1) return 1;
    if (c.rejected_speculative != 1) return 1;
    puts("MORNING_GROUCH_COUNTER_SMOKE=PASS");
    return 0;
}
