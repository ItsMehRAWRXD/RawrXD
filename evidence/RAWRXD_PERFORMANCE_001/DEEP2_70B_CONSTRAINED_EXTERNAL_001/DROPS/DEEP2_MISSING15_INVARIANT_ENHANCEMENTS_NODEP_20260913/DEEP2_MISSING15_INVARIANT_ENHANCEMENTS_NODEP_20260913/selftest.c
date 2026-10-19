#include <stdio.h>
#include "deep2_missing15_nodep.h"

#define T(x) do { if (!(x)) { printf("FAIL line=%d\n", __LINE__); return 1; } } while (0)
int main(void) {
    d2_u32 w;
    T(d2m15_survival_gate(0,0,0,0,0));
    T(d2m15_budget_gate(12ull<<30,12ull<<30));
    T(d2m15_residency_gate(0));
    T(d2m15_sample_gate(1,1234));
    w=d2m15_confidence_q10(4,8); T(w==512u);
    T(d2m15_blend_ns(1000,2000,512)==1500);
    T(d2m15_risk_ns(1000,200,512)==1100);
    T(d2m15_execution_cost_ns(1000,250)==1250);
    T(d2m15_opportunity_ns(1000,1024)==2000);
    T(d2m15_clamp_ns(3000,900,1500)==1500);
    T(d2m15_decay_q10(1024,2,128)==768);
    T(d2m15_finish_ns(100,200,300,400)==1000);
    T(d2m15_balance_gate(499,16000000,16800000));
    T(d2m15_no_hidden_debt(0,0,0,0));
    T(d2m15_promote_gate(1,1,999,1,1,2,2,1));
    T(!d2m15_promote_gate(1,1,1000,1,1,2,2,1));
    puts("DEEP2_MISSING15_NODEP_SELFTEST=PASS");
    puts("TOP15_ENHANCEMENTS=15/15");
    puts("PRODUCT_BOUND=0");
    puts("PROMOTE=0");
    return 0;
}
