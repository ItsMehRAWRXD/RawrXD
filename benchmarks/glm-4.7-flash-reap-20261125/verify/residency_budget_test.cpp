// Standalone acceptance test for Deep2::ResidencyBudget (Gate B).
// Compile: g++ -std=c++17 -O2 -Wall -Wextra residency_budget_test.cpp -o t && t
#include "../../../src/deep2/ResidencyBudget.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>

using namespace Deep2;

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL: %s\n", #x); std::exit(1); } } while (0)

int main() {
    // --- saturating subtraction never wraps ---
    CHECK(satSub(0, 1) == 0);
    CHECK(satSub(10, 3) == 7);
    CHECK(satSub(UINT64_MAX, UINT64_MAX) == 0);

    // --- the measured failure: 7541 MiB free, 17113 MiB required ---
    ResidencyBudget contended{};
    contended.physical = 32624ull << 20;      // 32 GiB total
    contended.budget   = 32624ull << 20;      // budget == physical
    contended.usage    = (32624ull - 7541ull) << 20; // ~25 GiB used -> 7541 free
    contended.margin   = 0;
    const uint64_t need = 17113ull << 20;
    CHECK(usableVRAM(contended) == (7541ull << 20));
    CHECK(!admitModel(contended, need, 0, 0, 0));   // must REJECT oversubscription

    // --- uncontended: 31707 MiB free admits the model ---
    ResidencyBudget freeGpu{};
    freeGpu.physical = 32624ull << 20;
    freeGpu.budget   = 32624ull << 20;
    freeGpu.usage    = (32624ull - 31707ull) << 20;
    CHECK(usableVRAM(freeGpu) == (31707ull << 20));
    CHECK(admitModel(freeGpu, need, (64ull << 20), (128ull << 20), (170ull << 20)));

    // --- budget < physical uses the budget (VK_EXT_memory_budget smaller) ---
    ResidencyBudget capped{};
    capped.physical = 32624ull << 20;
    capped.budget   = 20000ull << 20;
    capped.usage    = 1000ull << 20;
    CHECK(usableVRAM(capped) == (19000ull << 20));

    // --- pending + margin are subtracted ---
    ResidencyBudget reserved = freeGpu;
    reserved.pending = 1000ull << 20;
    reserved.margin  = 500ull << 20;
    CHECK(usableVRAM(reserved) == ((31707ull - 1500ull) << 20));

    // --- unknown budget falls back to physical ---
    ResidencyBudget noBudget{};
    noBudget.physical = 24000ull << 20;   // budget == 0
    CHECK(usableVRAM(noBudget) == (24000ull << 20));

    // --- each requirement class is enforced (no underflow) ---
    ResidencyBudget tight{};
    tight.physical = tight.budget = 1000ull << 20;
    CHECK(!admitModel(tight, (600ull << 20), (600ull << 20), 0, 0)); // kv overflows
    CHECK(admitModel(tight, (400ull << 20), (300ull << 20), (200ull << 20), (100ull << 20)));

    std::printf(
        "usable_contended=%llu MiB (reject=%d)\n"
        "usable_free=%llu MiB (admit=%d)\n"
        "RESIDENCY_BUDGET_ACCEPTANCE PASS\n",
        (unsigned long long)(usableVRAM(contended) >> 20), admitModel(contended, need, 0, 0, 0) ? 1 : 0,
        (unsigned long long)(usableVRAM(freeGpu) >> 20), admitModel(freeGpu, need, 0, 0, 0) ? 1 : 0);
    return 0;
}