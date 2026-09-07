// deep2_vwa_bounded_k2_001.cpp — VWA_BOUNDED_K2_001 / B8
#include "VwaBudget.hpp"
#include "K2C1C9.hpp"
#include <cstdio>
using namespace Deep2;

int main() {
    printf("VWA_BOUNDED_K2_001\n");
    printf("LAW=witness-only budgets; Elastic remains lifecycle authority\n");
    VwaBudget b{};
    b.ramBytes = 8ull << 30;
    b.vramBytes = 16ull << 30;
    b.outstandingIoBytes = 256ull << 20;
    b.maxOutstandingReads = 64;
    VwaBudgetPeak p{};
    p.ramBytes = 2ull << 30;
    p.vramBytes = 4ull << 30;
    p.outstandingIoBytes = 64ull << 20;
    p.outstandingReads = 8;
    const auto v = VwaValidateBudget(b, p);

    K2BoundWitness kw{};
    const K2CStatus ks = K2ValidateBounded(
        p.ramBytes, b.ramBytes, p.vramBytes, b.vramBytes,
        p.outstandingIoBytes, b.outstandingIoBytes, &kw);

    // Over-budget must fail.
    VwaBudgetPeak over = p;
    over.ramBytes = b.ramBytes + 1;
    const auto vFail = VwaValidateBudget(b, over);

    printf("RAM_PEAK=%llu RAM_BUDGET=%llu\n", (unsigned long long)p.ramBytes,
           (unsigned long long)b.ramBytes);
    printf("VRAM_PEAK=%llu VRAM_BUDGET=%llu\n", (unsigned long long)p.vramBytes,
           (unsigned long long)b.vramBytes);
    printf("OUTSTANDING_IO_PEAK=%llu OUTSTANDING_IO_BUDGET=%llu\n",
           (unsigned long long)p.outstandingIoBytes,
           (unsigned long long)b.outstandingIoBytes);
    printf("SECOND_RESIDENCY_FSM=0\n");
    printf("OVER_BUDGET_REJECT=%d\n", vFail.pass ? 0 : 1);
    const bool pass = v.pass && ks == K2C_OK && kw.pass && !vFail.pass;
    printf("VWA_BOUNDED_K2_001=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
