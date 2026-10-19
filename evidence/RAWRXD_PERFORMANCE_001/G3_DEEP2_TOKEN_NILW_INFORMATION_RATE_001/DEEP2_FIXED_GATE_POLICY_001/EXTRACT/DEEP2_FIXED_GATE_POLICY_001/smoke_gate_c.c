/* smoke_gate_c.c — diagnose fixed gate policy */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t magic, version, bytesPerTokenMax, bytesPerSecMax;
    uint64_t tpsMilliMin, windowTokensMin, nilwNum, nilwDen;
} GatePolicy;
typedef struct {
    uint64_t bytesPerToken, bytesPerSec, tpsMilli, windowTokens, nilwNum, nilwDen;
} RuntimeSample;
typedef struct {
    uint64_t passMask, failMask, policyValid, fixtureQ4Valid;
} GateResult;

extern uint64_t Deep2FixedGatePolicy_Init(GatePolicy *);
extern uint64_t Deep2FixedGatePolicy_Validate(GatePolicy *);
extern uint64_t Deep2FixedGatePolicy_Q4Witness(void);
extern uint64_t Deep2FixedGatePolicy_Evaluate(RuntimeSample *, GateResult *);

int main(void) {
    GatePolicy p; RuntimeSample s; GateResult r;
    uint64_t a, b, c, d;
    memset(&p, 0, sizeof p); memset(&s, 0, sizeof s); memset(&r, 0, sizeof r);
    a = Deep2FixedGatePolicy_Init(&p);
    b = Deep2FixedGatePolicy_Validate(&p);
    c = Deep2FixedGatePolicy_Q4Witness();
    printf("Init=%llu Validate=%llu Q4=%llu\n", a, b, c);
    printf("magic=%llx ver=%llx bpt=%llu bps=%llu tps=%llu win=%llu nilw=%llu/%llu\n",
           p.magic, p.version, p.bytesPerTokenMax, p.bytesPerSecMax,
           p.tpsMilliMin, p.windowTokensMin, p.nilwNum, p.nilwDen);
    s.bytesPerToken = 100000000; s.bytesPerSec = 1000000000;
    s.tpsMilli = 10000; s.windowTokens = 128; s.nilwNum = 1; s.nilwDen = 1250;
    d = Deep2FixedGatePolicy_Evaluate(&s, &r);
    printf("Eval=%llu pass=%llx fail=%llx pol=%llu q4f=%llu\n",
           d, r.passMask, r.failMask, r.policyValid, r.fixtureQ4Valid);
    s.bytesPerToken = 100000001;
    d = Deep2FixedGatePolicy_Evaluate(&s, &r);
    printf("Eval+1=%llu pass=%llx fail=%llx\n", d, r.passMask, r.failMask);
    puts((a && b && c && r.failMask == 1) ? "DEEP2_FIXED_GATE_POLICY_SMOKE=PASS" :
         "DEEP2_FIXED_GATE_POLICY_SMOKE=FAIL");
    return (a && b && c) ? 0 : 1;
}
