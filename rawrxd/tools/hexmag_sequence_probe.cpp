// ============================================================================
// tools/hexmag_sequence_probe.cpp  --  HEXMAG_ABI_SEQUENCE_001
// ============================================================================
// COMPOSITION test for the HexMag MASM backend.
//
// HEXMAG_ABI_001 (hexmag_abi_probe) proves each of the 25 exports honours the
// Windows-x64 calling convention in ISOLATION. That cannot see a defect that
// only appears when exports are composed: one export clobbering a register a
// later export then depends on, or state carried wrongly between calls, passes
// every isolated probe.
//
// So here the canaries are loaded once and held across a WHOLE CHAIN of calls.
// The chain is ordinary C++; the register discipline is supplied by
// HexMag_AbiProbe_Sequence in RawrXD_HexMag_AbiProbe.asm, because a C++ caller
// cannot be made to hold a value in RSI across a call.
//
// Interpretation, which is the point of this gate:
//   sequences pass  -> the backend is ABI-clean in composition, not just alone
//   sequences fail  -> a composition-only ABI defect exists that the isolated
//                      gate structurally cannot detect
// ============================================================================
#include "core/hexmag_swarm.hpp"
#include "core/hexmag_repeat_tuner.hpp"
#include "agent/hexmag_client.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

extern "C" uint64_t HexMag_AbiProbe_Sequence(void (*sequence)(void));
extern "C" void HexMag_AbiProbe_CorruptNonvolatiles(void);
extern "C" unsigned long long hxab_observed[8];   // RBX RBP RSI RDI R12 R13 R14 R15

namespace {

int g_total = 0, g_passed = 0, g_failed = 0;

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
const uint64_t ABI_BAD_DF    = 1ull << 21;

struct BitName { uint64_t bit; const char* name; };
const BitName kBits[] = {
    {ABI_BAD_RBX, "RBX"},   {ABI_BAD_RBP, "RBP"},   {ABI_BAD_RSI, "RSI"},
    {ABI_BAD_RDI, "RDI"},   {ABI_BAD_R12, "R12"},   {ABI_BAD_R13, "R13"},
    {ABI_BAD_R14, "R14"},   {ABI_BAD_R15, "R15"},   {ABI_BAD_XMM6, "XMM6"},
    {ABI_BAD_XMM7, "XMM7"}, {ABI_BAD_XMM8, "XMM8"}, {ABI_BAD_XMM9, "XMM9"},
    {ABI_BAD_XMM10, "XMM10"}, {ABI_BAD_XMM11, "XMM11"}, {ABI_BAD_XMM12, "XMM12"},
    {ABI_BAD_XMM13, "XMM13"}, {ABI_BAD_XMM14, "XMM14"}, {ABI_BAD_XMM15, "XMM15"},
    {ABI_BAD_RSP, "RSP"},   {ABI_BAD_DF, "DF"},
};

std::string decode(uint64_t mask) {
    std::string s;
    for (const auto& b : kBits) {
        if (mask & b.bit) {
            if (!s.empty()) s += "+";
            s += b.name;
        }
    }
    return s.empty() ? std::string("none") : s;
}

const char* kGoal = "Prove that 17 is prime";

// ---------------------------------------------------------------------------
// The sequences. Each is a realistic COMPOSITION of exports, not a single call.
// ---------------------------------------------------------------------------

// init -> configure -> acquire goal -> run -> drain -> release
void chainInitConfigureAcquireDrainRelease() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(4);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    HxEvent ev{};
    int guard = 0;
    while (guard++ < 256 && HexMag_PollEvent(&ev)) {}
    (void)HexMag_Feedback(0);
    (void)HexMag_Shutdown();
}

// grant -> withdraw -> regrant: the same goal cycled through all three states
void chainGrantWithdrawRegrant() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    HxEvent ev{};
    int guard = 0;
    while (guard++ < 256 && HexMag_PollEvent(&ev)) {}
    (void)HexMag_Feedback(0);                       // grant
    (void)HexMag_RunToSatisfied(64);
    guard = 0;
    while (guard++ < 256 && HexMag_PollEvent(&ev)) {}
    (void)HexMag_Feedback(HX_FAIL_WRONG);           // withdraw
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    guard = 0;
    while (guard++ < 256 && HexMag_PollEvent(&ev)) {}
    (void)HexMag_Feedback(0);                       // regrant
    (void)HexMag_RunToSatisfied(64);
    guard = 0;
    while (guard++ < 256 && HexMag_PollEvent(&ev)) {}
}

// tuner: init -> repeated mutation -> fingerprint -> strategy reads
void chainTunerMutationLoop() {
    (void)HexMag_Tuner_Init(8);
    (void)HexMag_Tuner_Reset(0xABCDEF0123456789ull);
    HxGenProfile p{};
    for (uint32_t attempt = 0; attempt < 6; ++attempt) {
        (void)HexMag_Tuner_Next(0xABCDEF0123456789ull, HX_FAIL_WRONG, attempt, &p);
        (void)HexMag_Tuner_Fingerprint(&p);
        (void)HexMag_Tuner_Strategy();
        (void)HexMag_Tuner_Attempt();
    }
    (void)HexMag_Tuner_GetProfile(&p);
}

// client trip -> event drain -> teardown, through the real transport
void chainClientTripDrainTeardown() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);

    rawrxd::agent::HexMagClient client;
    if (client.connect("masm://hexmag-sequence")) {
        (void)client.send(reinterpret_cast<const uint8_t*>(kGoal),
                          std::strlen(kGoal));
        (void)client.runToSatisfied(64);
        uint32_t kind = 0;
        std::string payload;
        int guard = 0;
        while (guard++ < 256 && client.pollEvent(kind, payload)) {}
        client.disconnect();
    }
}

// controller-facing: several swarm reads interleaved with tuner state
void chainInterleavedSwarmAndTuner() {
    (void)HexMag_Init();
    (void)HexMag_Tuner_Init(4);
    for (int i = 0; i < 4; ++i) {
        (void)HexMag_SetParallelAgents(static_cast<uint32_t>(i + 1));
        (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
        (void)HexMag_RunToSatisfied(32);
        HxEvent ev{};
        int guard = 0;
        while (guard++ < 64 && HexMag_PollEvent(&ev)) {}
        HxGenProfile p{};
        (void)HexMag_Tuner_Reset(0x1000ull + static_cast<uint64_t>(i));
        (void)HexMag_Tuner_Next(0x1000ull + static_cast<uint64_t>(i),
                                HX_FAIL_STAGNATION, 0, &p);
        (void)HexMag_GetParallelAgents();
        (void)HexMag_BotCount();
        (void)HexMag_AgentsSpawned();
        (void)HexMag_LastAgentId();
        (void)HexMag_IsInitialized();
    }
    (void)HexMag_Shutdown();
}

// ---------------------------------------------------------------------------
// Controls. A composition gate that cannot fail is not a gate.
// ---------------------------------------------------------------------------

// Control A: a chain that touches nothing. Must report clean, or the probe is
// reporting damage that is not there.
void chainEmptyControl() {
    volatile int local = 0;
    local = local + 1;
    (void)local;
}

// Control B: a chain that DELIBERATELY clobbers nonvolatiles across its own
// body. Must be detected, or the probe cannot see a chain-level violation and
// every "clean" result below is meaningless.
//
// It goes through the real API first, so the failure is proven to be detected
// in COMPOSITION with live backend calls, not in a vacuum.
void chainDeliberateViolation() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(32);
    HxEvent ev{};
    int guard = 0;
    while (guard++ < 64 && HexMag_PollEvent(&ev)) {}

    // No prologue, no epilogue: RSI/RDI/R12/XMM14 are simply overwritten.
    HexMag_AbiProbe_CorruptNonvolatiles();
}

// ---- bisect chains: isolate which call disturbs the canaries -------------
void chainBisectInitShutdown() {
    (void)HexMag_Init();
    (void)HexMag_Shutdown();
}
void chainBisectInitSubmitRunShutdown() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    (void)HexMag_Shutdown();
}
void chainBisectInitSubmitRunNoShutdown() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
}
void chainBisectSubmitRunNoInit() {
    (void)HexMag_SetParallelAgents(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
}
void chainBisectRunOnly() {
    (void)HexMag_RunToSatisfied(64);
}
void chainBisectSetAgentsOnly() {
    (void)HexMag_SetParallelAgents(3);
    (void)HexMag_SetParallelAgents(5);
}

// finer: isolate submit vs run on a LIVE swarm
void chainBisectInitSubmitOnly() {
    (void)HexMag_Init();
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
}
void chainBisectInitRunOnly() {
    (void)HexMag_Init();
    (void)HexMag_RunToSatisfied(64);
}
void chainBisectInitSubmitTwice() {
    (void)HexMag_Init();
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
}
void chainBisectInitSubmitThenDrain() {
    (void)HexMag_Init();
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    HxEvent ev{};
    int guard = 0;
    while (guard++ < 64 && HexMag_PollEvent(&ev)) {}
}

// ---------------------------------------------------------------------------
// WARM-UP -- kept, but it is NOT the explanation, and it does not make the gate
// pass.
//
// I hypothesised the R12 hits were a one-time CRT first-use path and added this
// to absorb them. THE WARM-UP DOES NOT HELP: the hits recur on the same chains
// afterwards. That hypothesis is REFUTED and is recorded here so it is not
// retried. The finding below is real and still unlocalised.
//
// What IS ruled out about the backend:
//   - an unbalanced push/pop: audited, every function's push count matches its
//     per-exit pop count (Emit 1/2, SubmitGoal 1/4, Step 1/8, PollEvent 1/2)
//   - R12 used at all outside hxS_Emit, which balances it
// What is NOT ruled out: something in the composed path writes R12. The value
// lands on a 0x80-aligned address inside this image, which is what
// hxab_observed's image-relative offset is printed for.
// ---------------------------------------------------------------------------
void warmUpRuntime() {
    (void)HexMag_Init();
    (void)HexMag_SetParallelAgents(4);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    HxEvent ev{};
    int guard = 0;
    while (guard++ < 256 && HexMag_PollEvent(&ev)) {}
    HxGenProfile p{};
    (void)HexMag_Tuner_Init(8);
    (void)HexMag_Tuner_Reset(0x5EED5EED5EED5EEDull);
    (void)HexMag_Tuner_Next(0x5EED5EED5EED5EEDull, HX_FAIL_WRONG, 0, &p);
}

static unsigned long long kImageBase = 0;
static unsigned long long kImageSize = 0;

struct Seq { const char* name; void (*fn)(void); };

void run(const Seq& s) {
    ++g_total;
    const uint64_t mask = HexMag_AbiProbe_Sequence(s.fn);
    const bool ok = (mask == 0);
    if (ok) ++g_passed; else ++g_failed;
std::printf("%-4s %-34s mask=0x%06llX %s\n", ok ? "ok" : "FAIL", s.name,
                static_cast<unsigned long long>(mask),
                ok ? "canaries intact across the whole sequence"
                   : decode(mask).c_str());
    if (!ok) {
        static const char* kN[8] = {"RBX", "RBP", "RSI", "RDI",
                                    "R12", "R13", "R14", "R15"};
        for (int i = 0; i < 8; ++i) {
            const unsigned long long v = hxab_observed[i];
            std::printf("        observed %-4s = 0x%016llX%s", kN[i], v,
                        (mask & (1ull << i)) ? "   <-- CLOBBERED" : "");
            if ((mask & (1ull << i)) && v >= kImageBase && v < kImageBase + kImageSize)
                std::printf("   image_offset=0x%llX", v - kImageBase);
            std::printf("\n");
        }
    }
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== HEXMAG_ABI_SEQUENCE_001 ===\n");
    std::printf("CONTRACT=nonvolatile GPR+XMM, RSP and DF held across a CHAIN of "
                "exports, not one call\n");
    std::printf("CANARY_SOURCE=RawrXD_HexMag_AbiProbe.asm (MASM)\n");

    {
        // SizeOfImage from our own headers, so a clobbered register that lands
        // inside this image can be reported as an offset a map file resolves.
        unsigned char* self = (unsigned char*)GetModuleHandleA(nullptr);
        kImageBase = (unsigned long long)self;
        const unsigned int peOff = *(unsigned int*)(self + 0x3C);
        kImageSize = *(unsigned int*)(self + peOff + 24 + 56);
    }
    warmUpRuntime();
    std::printf("WARMUP=done (does NOT absorb the R12 finding; see warmUpRuntime)\\n");

    const Seq controls[] = {
        {"CONTROL clean chain (must be ok)",     chainEmptyControl},
        {"CONTROL deliberate clobber (must fail)", chainDeliberateViolation},
    };
    std::printf("\n--- controls: these gate every result below ---\n");
    const uint64_t cleanMask = HexMag_AbiProbe_Sequence(chainEmptyControl);
    const bool cleanOk = (cleanMask == 0);
    std::printf("%-4s %-34s mask=0x%06llX %s\n", cleanOk ? "ok" : "FAIL",
                "CONTROL clean chain (must be ok)",
                static_cast<unsigned long long>(cleanMask),
                cleanOk ? "no false positives" : decode(cleanMask).c_str());

    const uint64_t badMask = HexMag_AbiProbe_Sequence(chainDeliberateViolation);
    // RSI, RDI, R12 and XMM14 are all clobbered by the control.
    const uint64_t wantBad = ABI_BAD_RSI | ABI_BAD_RDI | ABI_BAD_R12 | ABI_BAD_XMM14;
    const bool powerOk = ((badMask & wantBad) == wantBad);
    std::printf("%-4s %-34s mask=0x%06llX %s\n", powerOk ? "ok" : "FAIL",
                "CONTROL deliberate clobber (must fail)",
                static_cast<unsigned long long>(badMask),
                powerOk ? "detected RSI+RDI+R12+XMM14" : decode(badMask).c_str());

    const bool probeHasPower = cleanOk && powerOk;
    std::printf("PROBE_HAS_POWER=%d\n", probeHasPower ? 1 : 0);
    if (!probeHasPower) {
        std::printf("\nSEQUENCES_TESTED=0\nSEQUENCES_PASS=0\nSEQUENCES_FAIL=0\n");
        std::printf("COMPOSITION_ABI_DEFECT=UNDETERMINED\n");
        std::printf("VERDICT=FAIL  the gate is inoperable; refusing to certify\n");
        return 1;
    }

    std::printf("\n--- sequences ---\n");
    const Seq seqs[] = {
        {"init/configure/acquire/drain/release", chainInitConfigureAcquireDrainRelease},
        {"grant/withdraw/regrant",               chainGrantWithdrawRegrant},
        {"tuner mutation loop",                  chainTunerMutationLoop},
        {"client trip/drain/teardown",           chainClientTripDrainTeardown},
        {"interleaved swarm+tuner",              chainInterleavedSwarmAndTuner},
    };
    for (const auto& s : seqs) run(s);

    std::printf("\nSEQUENCES_TESTED=%d\n", g_total);
    std::printf("SEQUENCES_PASS=%d\n", g_passed);
    std::printf("SEQUENCES_FAIL=%d\n", g_failed);
    if (g_failed == 0) {
        std::printf("COMPOSITION_ABI_DEFECT=NONE_FOUND\n");
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("COMPOSITION_ABI_DEFECT=PRESENT\n");
    std::printf("VERDICT=FAIL\n");
    return 1;
}
