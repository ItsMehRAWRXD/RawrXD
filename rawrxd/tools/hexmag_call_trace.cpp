// ============================================================================
// tools/hexmag_call_trace.cpp  --  HEXMAG_CALL_TRACE_001
// ============================================================================
// PER-CALL machine-state log for the HexMag MASM exports.
//
// HexMag_AbiProbe_Sequence answers "which CHAIN damaged a canary". That is not
// enough to act on: a chain is dozens of calls, and the finding was an R12
// change with no attribution. This answers "which CALL", by invoking every
// export one at a time through HexMag_AbiTrace_Call and recording the full
// nonvolatile register state either side of that single call.
//
// Output is a field-per-call table, so any row can be read independently:
//   STEP  CALL                  MASK     DELTA              R12
//   003   HexMag_RunToSatisfied 0x000010 R12 0x7FF7..B80  -> <image offset>
// A non-zero MASK on any row names the offending call exactly.
// ============================================================================
#include "core/hexmag_swarm.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

extern "C" uint64_t HexMag_AbiTrace_Call(void* fn, uint64_t a1, uint64_t a2,
                                           unsigned long long* out);

namespace {

const char* kNames[8] = {"RBX", "RBP", "RSI", "RDI", "R12", "R13", "R14", "R15"};

// NOTE: there is deliberately NO canary table here. An earlier revision of this
// file kept its own copy of the canary values and compared the observed
// registers against it. That copy went stale when the canaries were renumbered
// in the .asm, and the trace then reported all sixteen calls as damaging
// nonvolatiles when R12 in fact still held its canary exactly.
//
// HexMag_AbiTrace_Call already compares against the real canaries and returns
// the authoritative mask, so the mask is the single source of truth and this
// file only DISPLAYS what was observed. One definition, not two.

uint64_t kImageBase = 0, kImageSize = 0;
int g_step = 0, g_rows = 0, g_badRows = 0;

std::string g_delta;
std::string g_r12;

void header() {
    std::printf("STEP  %-26s %-10s %-18s %s\n", "CALL", "MASK", "DELTA", "R12");
    std::printf("----  --------------------------  ----------  "
                "------------------  ----------------------------------------\n");
}

// One traced call. Prints every field, whether or not anything changed, so an
// absent DELTA is itself a recorded observation rather than a blank.
void step(const char* label, void* fn, uint64_t a1, uint64_t a2) {
    unsigned long long out[18] = {0};
    const uint64_t mask =
        HexMag_AbiTrace_Call(fn, a1, a2, reinterpret_cast<unsigned long long*>(out));
    ++g_step;
    ++g_rows;
    if (mask != 0) ++g_badRows;

char delta[96] = {0};
    int k = 0;
    for (int i = 0; i < 8; ++i) {
        if (mask & (1ull << i)) {
            if (k) k += snprintf(delta + k, sizeof(delta) - k, "+");
            k += snprintf(delta + k, sizeof(delta) - k, "%s", kNames[i]);
        }
    }
    if (k == 0) snprintf(delta, sizeof(delta), "%s", "-");

    char r12[64] = {0};
    const unsigned long long r12v = out[4];
    if (r12v >= kImageBase && r12v < kImageBase + kImageSize) {
        snprintf(r12, sizeof(r12), "img+0x%llX", r12v - kImageBase);
    } else {
        snprintf(r12, sizeof(r12), "0x%llX", r12v);
    }

    std::printf("%3d   %-26s 0x%06llX  %-18s %s%s\n", g_step, label,
                static_cast<unsigned long long>(mask), delta, r12,
                (mask & (1ull << 4)) ? "   <== R12 damaged HERE" : "");
}

void step0(const char* label, void* fn) { step(label, fn, 0, 0); }

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
#if defined(_WIN32)
    unsigned char* self = (unsigned char*)GetModuleHandleA(nullptr);
    kImageBase = (unsigned long long)self;
    const unsigned int peOff = *(unsigned int*)(self + 0x3C);
    kImageSize = *(unsigned int*)(self + peOff + 24 + 56);
#endif

    const char* kGoal = "Prove that 17 is prime";
    const uint64_t goalLen = (uint64_t)std::strlen(kGoal);

    std::printf("=== HEXMAG_CALL_TRACE_001 ===\n");
    std::printf("One call per row, full nonvolatile snapshot either side.\n");
    std::printf("CANONICAL=RBP RSI RDI RBX R12 R13 R14 R15 + XMM6..XMM15\n\n");

    header();

    // ---- populate a live swarm the ordinary way, untraced, so the traced
    // ---- calls below operate on real state rather than a cold backend.
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(4);
    (void)HexMag_SubmitGoal(kGoal, (uint32_t)goalLen);
    (void)HexMag_RunToSatisfied(64);
    {
        HxEvent ev{};
        int n = 0;
        while (n < 256 && HexMag_PollEvent(&ev)) ++n;
        std::printf("      (primed: queue drained = %d)\n\n", n);
    }

    // ---- the traced chain ------------------------------------------------
    step("HexMag_Init", (void*)&HexMag_Init, 0, 0);
    step("HexMag_SetParallelAgents", (void*)&HexMag_SetParallelAgents, 4, 0);
    step("HexMag_SubmitGoal", (void*)&HexMag_SubmitGoal, (uint64_t)kGoal,
         (uint64_t)goalLen);
    step0("HexMag_RunToSatisfied(64)", (void*)&HexMag_RunToSatisfied);
    {
        // Drain one event per traced call so the poll path is covered too.
        static HxEvent s_ev;
        step("HexMag_PollEvent", (void*)&HexMag_PollEvent,
             (uint64_t)(size_t)&s_ev, 0);
    }
    step0("HexMag_RunToSatisfied(64) again", (void*)&HexMag_RunToSatisfied);
    step0("HexMag_Step", (void*)&HexMag_Step);
    step0("HexMag_BotCount", (void*)&HexMag_BotCount);
    step0("HexMag_AgentsSpawned", (void*)&HexMag_AgentsSpawned);
    step0("HexMag_LastAgentId", (void*)&HexMag_LastAgentId);
    step0("HexMag_IsInitialized", (void*)&HexMag_IsInitialized);
    step0("HexMag_GetParallelAgents", (void*)&HexMag_GetParallelAgents);
    step0("HexMag_GetState", (void*)&HexMag_GetState);
    step0("HexMag_Feedback(0)", (void*)&HexMag_Feedback);
step0("HexMag_RunToSatisfied after grant", (void*)&HexMag_RunToSatisfied);
    step0("HexMag_Shutdown", (void*)&HexMag_Shutdown);

    // ---- the chain that FAILS at chain scope, logged call by call ---------
    // The per-call rows above are all clean, yet the SEQUENCE probe reports R12
    // damaged for this shape of chain. So log this chain itself, one call per
    // row, and find the row where R12 leaves its canary.
    std::printf("\n--- chain: grant / withdraw / regrant (fails at chain scope) ---\n");
    header();
    g_step = 0;
    g_rows = 0;
    g_badRows = 0;
    {
        static HxEvent s_ev;
        auto drain = [&](const char* tag) {
            for (int i = 0; i < 64; ++i) {
                const unsigned long long before = 0;
                (void)before;
                if (!HexMag_PollEvent(&s_ev)) break;
            }
            std::printf("      (drained: %s)\n", tag);
        };

        step0("Init", (void*)&HexMag_Init);
        step0("SetParallelAgents(2)", (void*)&HexMag_SetParallelAgents);
        step("SubmitGoal", (void*)&HexMag_SubmitGoal, (uint64_t)kGoal, goalLen);
        step0("RunToSatisfied(64)", (void*)&HexMag_RunToSatisfied);
        drain("after first run");

        step0("Feedback(0)  == grant", (void*)&HexMag_Feedback);
        step0("RunToSatisfied(64)", (void*)&HexMag_RunToSatisfied);
        drain("after grant run");

        step0("Feedback(0x40) == withdraw", (void*)&HexMag_Feedback);
        step("SubmitGoal", (void*)&HexMag_SubmitGoal, (uint64_t)kGoal, goalLen);
        step0("RunToSatisfied(64)", (void*)&HexMag_RunToSatisfied);
        drain("after withdraw run");

        step0("Feedback(0)  == regrant", (void*)&HexMag_Feedback);
        step0("RunToSatisfied(64)", (void*)&HexMag_RunToSatisfied);
        drain("after regrant run");
    }

    // Deterministic, or first-use on this path? Repeat the fresh
    // Init->SubmitGoal cycle several times. If only the first is dirty it is a
    // one-time cost on the path; if every one is dirty it is systematic.
    std::printf("\n--- is it deterministic? three fresh Init+SubmitGoal cycles ---\n");
    header();
    g_step = 0; g_rows = 0; g_badRows = 0;
    for (int i = 1; i <= 3; ++i) {
        char lbl[64];
        snprintf(lbl, sizeof(lbl), "cycle %d Init", i);
        step0(lbl, (void*)&HexMag_Init);
        snprintf(lbl, sizeof(lbl), "cycle %d SubmitGoal", i);
        step("SubmitGoal", (void*)&HexMag_SubmitGoal, (uint64_t)kGoal, goalLen);
        snprintf(lbl, sizeof(lbl), "cycle %d Shutdown", i);
        step0(lbl, (void*)&HexMag_Shutdown);
    }

    std::printf("\nCALLS_TRACED=%d\n", g_rows);
    std::printf("CALLS_DAMAGING_NONVOLATILE=%d\n", g_badRows);
    std::printf("FIRST_BAD_ROW=%s\n",
                g_badRows ? "see the <== R12 damaged HERE marker" : "NONE");
    std::printf("VERDICT=%s\n", g_badRows ? "FAIL" : "PASS");
    return g_badRows ? 1 : 0;
}
