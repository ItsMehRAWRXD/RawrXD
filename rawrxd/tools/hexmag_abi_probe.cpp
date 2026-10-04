// ============================================================================
// tools/hexmag_abi_probe.cpp  --  HEXMAG_ABI_001 driver
// ============================================================================
// Tests all 25 hand-written HexMag MASM exports for Windows-x64 calling-ABI
// conformance: every nonvolatile GPR and XMM, RSP restoration, stack alignment,
// writes above the shadow space, and the direction flag.
//
// The canaries live in RawrXD_HexMag_AbiProbe.asm on purpose. A C++ caller
// cannot be made to hold a value in RSI across a call, so a C++-only conformance
// test would pass by luck while the ABI is being violated -- which is exactly
// the defect class this gate exists to detect.
//
// Each export is invoked in a harness that gives it something plausible to do:
// a live swarm is initialised and a goal submitted before the probe runs, so an
// export tested against a dead backend would pass for the wrong reason.
// ============================================================================
#include "core/hexmag_swarm.hpp"
#include "core/hexmag_repeat_tuner.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

extern "C" uint64_t HexMag_AbiProbe_Check(void* target, uint64_t firstArg);
extern "C" uint64_t HexMag_AbiProbe_CanaryBad();
extern "C" uint64_t HexMag_AbiProbe_CanaryBadRep();

namespace {

int g_total = 0, g_passed = 0, g_failed = 0;
std::string g_firstBadExport = "NONE";
std::string g_firstBadRegister = "NONE";

const uint64_t ABI_BAD_RBX   = 1ull << 0;
const uint64_t ABI_BAD_RBP   = 1ull << 1;
const uint64_t ABI_BAD_RSI   = 1ull << 2;
const uint64_t ABI_BAD_RDI   = 1ull << 3;
const uint64_t ABI_BAD_R12   = 1ull << 4;
const uint64_t ABI_BAD_R13   = 1ull << 5;
const uint64_t ABI_BAD_R14   = 1ull << 6;
const uint64_t ABI_BAD_R15   = 1ull << 7;
const uint64_t ABI_BAD_XMM6  = 1ull << 8;
const uint64_t ABI_BAD_XMM7  = 1ull << 9;
const uint64_t ABI_BAD_XMM8  = 1ull << 10;
const uint64_t ABI_BAD_XMM9  = 1ull << 11;
const uint64_t ABI_BAD_XMM10 = 1ull << 12;
const uint64_t ABI_BAD_XMM11 = 1ull << 13;
const uint64_t ABI_BAD_XMM12 = 1ull << 14;
const uint64_t ABI_BAD_XMM13 = 1ull << 15;
const uint64_t ABI_BAD_XMM14 = 1ull << 16;
const uint64_t ABI_BAD_XMM15 = 1ull << 17;
const uint64_t ABI_BAD_RSP   = 1ull << 18;
const uint64_t ABI_BAD_ALIGN = 1ull << 19;
const uint64_t ABI_BAD_ABOVE = 1ull << 20;
const uint64_t ABI_BAD_DF    = 1ull << 21;

struct BitName { uint64_t bit; const char* name; };
const BitName kBits[] = {
    {ABI_BAD_RBX, "RBX"},   {ABI_BAD_RBP, "RBP"},   {ABI_BAD_RSI, "RSI"},
    {ABI_BAD_RDI, "RDI"},   {ABI_BAD_R12, "R12"},   {ABI_BAD_R13, "R13"},
    {ABI_BAD_R14, "R14"},   {ABI_BAD_R15, "R15"},   {ABI_BAD_XMM6, "XMM6"},
    {ABI_BAD_XMM7, "XMM7"}, {ABI_BAD_XMM8, "XMM8"}, {ABI_BAD_XMM9, "XMM9"},
    {ABI_BAD_XMM10, "XMM10"}, {ABI_BAD_XMM11, "XMM11"}, {ABI_BAD_XMM12, "XMM12"},
    {ABI_BAD_XMM13, "XMM13"}, {ABI_BAD_XMM14, "XMM14"}, {ABI_BAD_XMM15, "XMM15"},
    {ABI_BAD_RSP, "RSP"},   {ABI_BAD_ALIGN, "STACK_ALIGNMENT"},
    {ABI_BAD_ABOVE, "WROTE_ABOVE_SHADOW"}, {ABI_BAD_DF, "DF"},
};

std::string decode(uint64_t mask) {
    std::vector<std::string> hit;
    for (const auto& b : kBits) {
        if (mask & b.bit) hit.emplace_back(b.name);
    }
    if (hit.empty()) return "none";
    std::string s;
    for (size_t i = 0; i < hit.size(); ++i) {
        if (i) s += "+";
        s += hit[i];
    }
    return s;
}

// Scratch large enough for an HxEvent (512 B) or an HxGenProfile (48 B).
// Exports that write through a pointer argument are handed this rather than the
// address of some unrelated object.
alignas(16) unsigned char g_scratch[1024] = {};

void report(const char* name, void* target, uint64_t firstArg) {
    ++g_total;
    const uint64_t mask = HexMag_AbiProbe_Check(target, firstArg);
    const bool ok = (mask == 0);
    if (ok) {
        ++g_passed;
    } else {
        ++g_failed;
        if (g_firstBadExport == "NONE") {
            g_firstBadExport = name;
            // Name the first offending bit in register order.
            for (const auto& b : kBits) {
                if (mask & b.bit) { g_firstBadRegister = b.name; break; }
            }
        }
    }
    std::printf("%-4s %-28s mask=0x%06llX %s\n", ok ? "ok" : "FAIL", name,
                static_cast<unsigned long long>(mask),
                ok ? "" : decode(mask).c_str());
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== HEXMAG_ABI_001 ===\n");
    std::printf("EXPORTS_TESTED=25\n");
    std::printf("NONVOLATILE_CONTRACT=RBX RBP RSI RDI R12 R13 R14 R15 XMM6-XMM15\n");
    std::printf("CANARY_SOURCE=RawrXD_HexMag_AbiProbe.asm (MASM, not C++)\n");

    // A live backend, so exports are exercised against real state rather than a
    // dead one. An export that "passes" because it refused to do anything has
    // not been tested.
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    const char* goal = "Prove that 17 is prime";
    (void)HexMag_SubmitGoal(goal, static_cast<uint32_t>(std::strlen(goal)));
    (void)HexMag_RunToSatisfied(64);
    (void)HexMag_Tuner_Init(8);
    (void)HexMag_Tuner_Reset(0x5EED5EED5EED5EEDull);

    std::printf("\n--- swarm exports (15) ---\n");
    report("HexMag_Init",              (void*)&HexMag_Init, 0);
    report("HexMag_Shutdown",         (void*)&HexMag_Shutdown, 0);
    report("HexMag_GetState",         (void*)&HexMag_GetState, 0);
    report("HexMag_SubmitGoal",       (void*)&HexMag_SubmitGoal, 0);
    report("HexMag_Step",             (void*)&HexMag_Step, 0);
    // Re-arm before probing PollEvent. Its copy path -- the one that addresses
    // through RSI and RDI and runs `rep movsb` -- is only reached when the queue
    // is NON-EMPTY; on an empty queue it returns immediately and touches no
    // register at all. Probing it after earlier calls have drained the queue
    // would clear an export that was never actually exercised, which is the
    // "a gate that refuses everything passes" failure in its purest form.
    (void)HexMag_Feedback(HX_FAIL_WRONG);
    (void)HexMag_Shutdown();
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(goal, static_cast<uint32_t>(std::strlen(goal)));
    (void)HexMag_RunToSatisfied(64);
    report("HexMag_PollEvent",        (void*)&HexMag_PollEvent,
           reinterpret_cast<uint64_t>(g_scratch));
    report("HexMag_RunToSatisfied",   (void*)&HexMag_RunToSatisfied, 64);
    report("HexMag_BotCount",         (void*)&HexMag_BotCount, 0);
    report("HexMag_AgentsSpawned",    (void*)&HexMag_AgentsSpawned, 0);
    report("HexMag_LastAgentId",      (void*)&HexMag_LastAgentId, 0);
    report("HexMag_TunerAttempt",     (void*)&HexMag_TunerAttempt, 0);
    report("HexMag_IsInitialized",    (void*)&HexMag_IsInitialized, 0);
    report("HexMag_Feedback",         (void*)&HexMag_Feedback, 0);
    report("HexMag_SetParallelAgents",(void*)&HexMag_SetParallelAgents, 2);
    report("HexMag_GetParallelAgents",(void*)&HexMag_GetParallelAgents, 0);

    std::printf("\n--- tuner exports (10) ---\n");
    report("HexMag_Tuner_Init",        (void*)&HexMag_Tuner_Init, 8);
    report("HexMag_Tuner_Reset",       (void*)&HexMag_Tuner_Reset, 0x5EED5EEDull);
    report("HexMag_Tuner_Initial",     (void*)&HexMag_Tuner_Initial,
           reinterpret_cast<uint64_t>(g_scratch));
    report("HexMag_Tuner_Next",        (void*)&HexMag_Tuner_Next,
           reinterpret_cast<uint64_t>(g_scratch));
    report("HexMag_Tuner_Fingerprint", (void*)&HexMag_Tuner_Fingerprint,
           reinterpret_cast<uint64_t>(g_scratch));
    report("HexMag_Tuner_GenerationId",(void*)&HexMag_Tuner_GenerationId, 0);
    report("HexMag_Tuner_GetProfile",  (void*)&HexMag_Tuner_GetProfile,
           reinterpret_cast<uint64_t>(g_scratch));
    report("HexMag_Tuner_WeightDelta", (void*)&HexMag_Tuner_WeightDelta, 0);
    report("HexMag_Tuner_Attempt",     (void*)&HexMag_Tuner_Attempt, 0);
    report("HexMag_Tuner_Strategy",    (void*)&HexMag_Tuner_Strategy, 0);

    // -------------------------------------------------------------------
    // NEGATIVE CONTROL FIRST, and it gates everything after it.
    // HexMag_AbiProbe_CanaryBad clobbers RSI, RBX and XMM14 on purpose. If the
    // probe does not report exactly those three, the probe is broken and every
    // "ok" it goes on to produce is worthless.
    // -------------------------------------------------------------------
    const uint64_t negMask = HexMag_AbiProbe_Check(
        reinterpret_cast<void*>(&HexMag_AbiProbe_CanaryBad), 0);
    const uint64_t expectNeg = ABI_BAD_RSI | ABI_BAD_RBX | ABI_BAD_XMM14;
    const bool negativeControlPasses = (negMask == expectNeg);
    std::printf("--- negative control (must detect RSI+RBX+XMM14) ---\n");
    std::printf("%-4s %-28s mask=0x%06llX got[%s] want[RSI+RBX+XMM14]\n",
                negativeControlPasses ? "ok" : "FAIL",
                "HexMag_AbiProbe_CanaryBad",
                static_cast<unsigned long long>(negMask),
                decode(negMask).c_str());
    if (!negativeControlPasses) {
        std::printf("\nPROBE_HAS_POWER=0  the gate is inoperable; refusing to certify\n");
        std::printf("VERDICT=FAIL\n");
        return 1;
    }
    // Second negative control: the exact register shape HexMag_PollEvent uses
    // (address in RSI, destination in RDI, then rep movsb). Both must move.
    const uint64_t repMask = HexMag_AbiProbe_Check(
        reinterpret_cast<void*>(&HexMag_AbiProbe_CanaryBadRep), 0);
    const bool repControlPasses =
        (repMask & ABI_BAD_RSI) != 0 && (repMask & ABI_BAD_RDI) != 0;
    std::printf("%-4s %-28s mask=0x%06llX got[%s] want[RSI+RDI from rep movsb]\n",
                repControlPasses ? "ok" : "FAIL",
                "CanaryBadRep (rep movsb)",
                static_cast<unsigned long long>(repMask), decode(repMask).c_str());
    if (!repControlPasses) {
        std::printf("\nPROBE_HAS_POWER=0  cannot see rep-string register damage\n");
        std::printf("VERDICT=FAIL\n");
        return 1;
    }

    std::printf("PROBE_HAS_POWER=1\n");

    std::printf("\nCHECKS_TOTAL=%d\n", g_total);
    std::printf("CHECKS_PASS=%d\n", g_passed);
    std::printf("CHECKS_FAIL=%d\n", g_failed);
    std::printf("FIRST_BAD_EXPORT=%s\n", g_firstBadExport.c_str());
    std::printf("FIRST_BAD_REGISTER=%s\n", g_firstBadRegister.c_str());

    if (g_failed == 0) {
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("VERDICT=FAIL\n");
    return 1;
}
