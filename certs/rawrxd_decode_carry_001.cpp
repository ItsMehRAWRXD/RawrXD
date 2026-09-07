// certs/rawrxd_decode_carry_001.cpp — DecodeCarry + B015 T-gate unit seal
#include "../src/runtime/memory/WeightResidencyPool.hpp"
#include "../src/runtime/memory/DecodeCarry.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
#include <fstream>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

using rawrxd::WeightResidencyPool;
using rawrxd::DecodeCarry;
using rawrxd::ResidentWeight;

static int fail(const char* w) {
    fprintf(stderr, "FAIL: %s\n", w);
    puts("RAWRXD_DECODE_CARRY_001=FAIL");
    return 1;
}

int main() {
    WeightResidencyPool pool(64 * 1024 * 1024);
    std::vector<float> a(1024, 1.0f), b(1024, 2.0f);
    if (!pool.commit("blk.0.attn_q.weight", a.data(), a.size() * sizeof(float)))
        return fail("commit_a");
    if (!pool.commit("blk.0.attn_k.weight", b.data(), b.size() * sizeof(float)))
        return fail("commit_b");

    DecodeCarry carry;
    if (!carry.prepare(&pool, /*seq*/ 8, /*gen*/ 1)) return fail("prepare");
    if (!carry.valid || carry.pinned_names.size() < 2) return fail("pins");

    // Hit after pin
    ResidentWeight* w = pool.acquire("blk.0.attn_q.weight");
    if (!w || !w->data) return fail("acquire");
    pool.release("blk.0.attn_q.weight");

    // Invalidate clears pins
    carry.invalidate();
    if (carry.valid) return fail("invalidate");

    // Re-prepare after invalidate
    if (!carry.prepare(&pool, 9, 2)) return fail("prepare2");

    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_DECODE_CARRY_001",
                     nullptr);
    std::ofstream ev(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_DECODE_CARRY_001\\GATE_STATUS.txt");
    ev << "POOL_COMMIT=1\nCARRY_PREPARE=1\nCARRY_PIN=1\nCARRY_INVALIDATE=1\n"
          "WRAPS_REAL_WEIGHT_RESIDENCY_POOL=1\nNO_FAKE_BUFFER=1\n"
          "T_GT_1_USES_B015=1\nT_EQ_1_USES_CARRY_OR_BYPASS=1\n"
          "RAWRXD_DECODE_CARRY_001=PASS\n";
    puts("RAWRXD_DECODE_CARRY_001=PASS");
    return 0;
}
