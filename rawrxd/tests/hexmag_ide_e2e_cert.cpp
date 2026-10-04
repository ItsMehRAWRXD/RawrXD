// ============================================================================
// tests/hexmag_ide_e2e_cert.cpp  --  HEXMAG_IDE_E2E_001
// ============================================================================
// End-to-end certification of the HexMag chain against the REAL MASM backend.
//
// This is the gate that was missing: the file was 43 bytes of "// STUB:", and so
// were its two sibling certs, so the chain had no executable end-to-end test at
// all.  The MASM backend it exercises was itself an auto-generated stub defining
// only RawrXD_HexMag_Swarm_Stub, which is why every HexMag_* call in the
// control plane and the runtime controller was an unresolved external.
//
// WHAT IS ACTUALLY ASSERTED
// The load-bearing checks are E11 and E19.  The product property is:
//
//     the swarm may not certify itself.
//
// core/hexmag_control_plane.cpp::claimFromSwarmAnswer() treats an answer
// containing "goal.satisfied" (or "#OK", or "llm.answer.final") as verifier
// evidence.  A backend that emitted that payload on completing its own search
// would mark the claim Verified with nothing having verified anything.  So this
// cert proves the opposite: with no external grant the run FAILS CLOSED and
// reports no satisfaction, and even the full C++ facade reports failure rather
// than a fabricated success.
//
// That is the assertion most likely to fail if someone "fixes" the swarm by
// making it emit GOAL_SATISFIED on its own.  That is the point.
//
// Every printed value is an observation.  The verdict is computed from them.
//
// ---------------------------------------------------------------------------
// VERIFIED STATE -- read this before trusting a green run
// ---------------------------------------------------------------------------
//   /Od   62/62 PASS, exit 0
//   /O2   FAILS. One open defect remains, and it is NOT the one that was open
//         when this note was first written.
//
// RESOLVED SINCE: a systematic Windows-x64 ABI violation in the MASM backend.
// RSI and RDI are NONVOLATILE, and nearly every routine in
// RawrXD_HexMag_Swarm.asm used them without restoring them. That is precisely
// the shape that hides at /Od (which spills everything) and destroys live
// values at /O2 (which trusts the ABI). tools/hexmag_abi_probe.cpp found it --
// FIRST_BAD_EXPORT=HexMag_Shutdown, FIRST_BAD_REGISTER=RDI -- and repairing all
// twelve offending routines made these previously failing /O2 checks pass:
//     E07_queue_consistent   queued=10 drained=9   (was drained=0)
//     E08_events_present     events drained=11
//     E09_spawn_count        spawn events=4
//     E10_candidate_shape    cand=00 fp=6C7B6B51D092D7B5 len=0016
// The "drain computed 9 events but the caller saw 0" mystery was this.
//
// STILL OPEN, at /O1 and /O2. Narrowed to a single instruction, and one
// hypothesis tested and REFUTED along the way.
//
// Machine state captured at the fault (exception 0xC0000005, READ):
//     RIP=0x7FF6481FAF7D  (CRT module, not this exe)
//     CODE_AT_RIP=0F1048700F1149F0488D808000000049
//       -> movups xmm1,[rax+0x70] ; movups xmm0,[rcx-0x10] ; lea rax,[rax+0x80]
//     RAX=0xCA2AAFFF90  RCX=0xCA2AAFFB10  RSP=0xCA2AAFEF50
//     FAULT_ADDRESS=0xCA2AB00000 = RAX+0x70
//   That is a memcpy whose source is ~4.1 KB ABOVE the current stack pointer,
//   copying upward until it leaves the committed stack. EFLAGS DF=0, so the
//   direction is a genuine forward copy, not a flag left set.
//
// REFUTED: "the 1280-byte Drain return copy runs off the stack".
//   The geometry fit that description exactly (SRC+1280 = 0xCA2AB00490 spans
//   the fault), but shrinking Drain from 1280 to under 512 bytes -- by replacing
//   the two 480-byte candidate payload buffers with exact typed index and
//   fingerprint values -- did NOT cure the fault. Same crash, same signature.
//
// STILL REQUIRED: identify which object the upward copy is actually walking.
//   The source is in E11's frame, ~4 KB above the faulting frame's RSP.
//
// Consequence: treat this cert as certified at default optimisation, with the
// E01-E11 subset additionally passing at /O2. It is NOT evidence that the
// whole chain is correct in an optimised shipping build.
// ============================================================================
#include "core/hexmag_swarm.hpp"
#include "core/hexmag_repeat_tuner.hpp"
#include "core/hexmag_control_plane.hpp"
#include "agent/hexmag_client.hpp"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
#include <cstring>
#include <type_traits>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// windows.h MUST be included at file scope. Inside the anonymous namespace it
// declares every Windows entity with internal linkage, which breaks the
// calling convention on the exception handler below.
#include <windows.h>
#endif

namespace {

using namespace RawrXD::HexMag;

// If this cert dies it must say WHERE. A crash that produces no output is
// indistinguishable from a crash in the backend, and the difference between the
// two is the whole diagnosis.
#if defined(_WIN32)
LONG WINAPI crashReporter(EXCEPTION_POINTERS* ep) {
    const EXCEPTION_RECORD* rec = ep->ExceptionRecord;
    const CONTEXT* ctx = ep->ContextRecord;
    std::printf("\nEXCEPTION code=0x%08lX faulting_address=%p op=%llu\n",
                static_cast<unsigned long>(rec->ExceptionCode),
                rec->ExceptionAddress,
                static_cast<unsigned long long>(
                    rec->ExceptionInformation[0]));
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        rec->ExceptionCode == 0xC0000409u) {
        std::printf("  access_address=%p rip=%p rsp=%p rbp=%p\n",
                    reinterpret_cast<void*>(rec->ExceptionInformation[1]),
                    reinterpret_cast<void*>(ctx->Rip),
                    reinterpret_cast<void*>(ctx->Rsp),
                    reinterpret_cast<void*>(ctx->Rbp));
    }
    std::fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}
void installCrashReporter() { AddVectoredExceptionHandler(1, crashReporter); }
#else
void installCrashReporter() {}
#endif

int g_total = 0;
int g_passed = 0;
int g_failed = 0;

// Derived from the struct, not hardcoded: this is the number of payload bytes
// the producer is allowed to fill, computed the same way a caller would.
constexpr size_t kPayloadCapacity =
    sizeof(HxEvent) - offsetof(HxEvent, payload);
static_assert(kPayloadCapacity == 480, "HxEvent payload must be 480 bytes");

void check(bool ok, const char* id, const std::string& detail) {
    ++g_total;
    if (ok) {
        ++g_passed;
    } else {
        ++g_failed;
    }
    std::printf("%-4s %-36s %s\n", ok ? "ok" : "FAIL", id, detail.c_str());
}

std::string b(bool v) { return v ? "1" : "0"; }

std::string rcs(uint64_t rc) {
    switch (rc) {
        case HX_OK:               return "OK";
        case HX_ERR_ALLOC:        return "ALLOC";
        case HX_ERR_NOT_INIT:     return "NOT_INIT";
        case HX_ERR_ALREADY_INIT: return "ALREADY_INIT";
        case HX_ERR_BAD_ARG:      return "BAD_ARG";
        case HX_ERR_DEPTH:        return "DEPTH";
        case HX_ERR_REPEAT:       return "REPEAT";
        case HX_ERR_QUEUE_FULL:   return "QUEUE_FULL";
        case HX_ERR_IDLE_FAIL:    return "IDLE_FAIL";
        case HX_ERR_TIMEOUT:      return "TIMEOUT";
        case HX_ERR_NEED_INPUT:   return "NEED_INPUT";
        default: {
            char tmp[32];
            std::snprintf(tmp, sizeof(tmp), "rc=%llu",
                          static_cast<unsigned long long>(rc));
            return std::string(tmp);
        }
    }
}

// Drain the whole queue and report what was actually observed.
// Tally what the swarm actually emitted, in one pass.
//
// This deliberately does NOT keep the raw 512-byte records in a
// std::vector<HxEvent> and re-scan them afterwards. Two reasons: a second
// traversal of a vector of raw records is machinery these checks do not need,
// and it was the one place in this cert whose result could not be explained --
// the drain itself completed cleanly (poll count correct, every event
// validated) while iterating the stored vector produced garbage under /O2.
// Tally during the drain so the counts come from the same bytes the checks
// inspect, with no second structure to go stale or corrupt.
struct Drain {
    int polls = 0;
    bool drainTruncated = false;
    int pollsBeyondEmpty = 0;

    int countByKind[HX_EVT_COUNT] = {};
    bool sawSatisfied = false;
    bool sawFinal = false;
    int candidates = 0;
    int spawns = 0;

    int malformedKind = 0;
    int badPayloadLen = 0;
    int unterminatedPayload = 0;
    int wrongGoalId = 0;

    // Agent ids are recorded in a fixed array, not a std::vector. The swarm clamps
// its width to [1,8], so 8 slots are sufficient, and Drain is returned BY VALUE
// from drainAll() -- a struct carrying a heap member through that copy is the
// last thing a diagnostic should do. With no heap members at all, Drain is
// trivially copyable and the return cannot alias anything.
static constexpr int kMaxAgentIds = 8;
uint64_t agentIds[kMaxAgentIds] = {};
int agentIdCount = 0;
int agentIdOverflow = 0;

// Candidate payloads are recorded as EXACT typed values, not as text.
    //
    // This is the measured fix for the /O2 fault. The faulting instruction was a
    // CRT memcpy whose source sat ~1.1 KB below the top of the committed stack,
    // copying 1280 bytes upward until it ran off the stack -- and the object
    // being copied was this struct, 75% of which was these two 480-byte payload
    // buffers. They existed only so E10 could assert on one 36-character string.
    // Recording the candidate index and the 64-bit goal fingerprint instead
    // makes E10's assertion exact (integer equality, not a substring match) and
    // removes the oversized copy that faulted.
    static constexpr int kMaxCandidates = 8;
    uint64_t candidateFp[kMaxCandidates] = {};
    uint32_t candidateIdx[kMaxCandidates] = {};
    int candidateCount = 0;
    int candidateOverflow = 0;

    int drainExceptionCount = 0;
    char drainExceptionWhat[96] = {};   // fixed buffer, NOT a std::string

    int count(uint32_t kind) const {
        return (kind < HX_EVT_COUNT) ? countByKind[kind] : 0;
    }
};

// Parse up to 16 hex digits from the start of s. Hand-rolled rather than
// sscanf: it removes a format-string dependency from a diagnostic, it avoids
// reading past the payload if the producer ever emits an unterminated one, and
// it makes the accepted character set explicit.
bool parseHex64(const char* s, uint64_t& out) {
    uint64_t v = 0;
    int digits = 0;
    for (; digits < 16; ++digits) {
        const char c = s[digits];
        uint64_t d;
        if (c >= '0' && c <= '9')      d = static_cast<uint64_t>(c - '0');
        else if (c >= 'A' && c <= 'F') d = static_cast<uint64_t>(c - 'A' + 10);
        else if (c >= 'a' && c <= 'f') d = static_cast<uint64_t>(c - 'a' + 10);
        else break;
        v = (v << 4) | d;
    }
    if (digits == 0) return false;
    out = v;
    return true;
}

// Reads the swarm's control block directly. HexMag_GetState() returns it, so
// this is ground truth about what the backend actually holds -- as opposed to
// inferring it from what came back out of the queue. Field offsets mirror the
// layout declared in src/asm/RawrXD_HexMag_Swarm.asm.
struct SwarmStateFields {
    uint32_t initialized;
    uint32_t parallel;
    uint32_t bots;
    uint32_t grant;
    uint32_t stage;
    uint32_t stepCount;
    uint32_t satisfied;
    uint32_t eventCount;
    uint32_t queueFull;
    uint32_t reserved0;
    uint64_t agentsSpawned;
    uint64_t goalId;
    uint64_t lastAgentId;
    uint32_t goalLen;
    uint32_t finalized;
};

const SwarmStateFields* readSwarmState() {
    const uint8_t* p = static_cast<const uint8_t*>(HexMag_GetState());
    return p ? reinterpret_cast<const SwarmStateFields*>(p) : nullptr;
}

// Layout receipts. These turn assumptions about Drain into executable facts, so
// packing or member-order drift becomes a compile error instead of a
// mysteriously wrong count at run time.
// is_trivially_copyable, not is_trivial: the "= {}" initialisers make default
// construction non-trivial, but trivial COPY is the property that governs a
// by-value return and any memcpy of the tally.
static_assert(std::is_trivially_copyable<Drain>::value,
              "Drain must stay trivially copyable -- it is returned by value");
static_assert(std::is_standard_layout<Drain>::value, "Drain must stay standard-layout");
static_assert(sizeof(HxEvent) == 512, "HxEvent must stay 512 bytes");
static_assert(offsetof(HxEvent, payload) == 32, "HxEvent payload must stay at +32");
static_assert(kPayloadCapacity == 480, "payload capacity must stay 480 bytes");
static_assert(offsetof(Drain, polls) == 0, "polls must stay first");
static_assert(sizeof(Drain) <= 512, 
              "Drain must stay small: a 1280-byte copy of it was measured running" 
              "off the top of the stack at /O2");
static_assert(offsetof(Drain, candidateFp) > offsetof(Drain, countByKind),
              "candidate data must follow the counters");

// A drain loop MUST be bounded. An unbounded drain is a harness that can hang
// or exhaust memory instead of reporting what it saw, which turns a backend bug
// into an unattributable failure.
constexpr int kMaxDrainPolls = 4096;

// Takes an out-parameter rather than returning Drain by value. Drain is a few
// kilobytes of counters and payload buffers, and returning it by value is
// exactly the kind of large-struct copy that can behave differently under
// optimisation. This harness must give the same answer at /Od and at /O2.
// Returns the tally BY VALUE.
//
// Measured reason, not preference: with an out-parameter at /O2 this drain ran
// correctly -- instrumentation inside the loop showed the polls succeeding and
// the backend's queued-event count falling to zero, nine times, then eleven,
// then twelve -- while the caller went on reading d.polls as 0. The work
// happened; the result did not reach the caller. Drain is now a POD of roughly
// a kilobyte, so returning it is cheap and there is nothing to alias.
// NOINLINE matters here: this returns a ~1.3 KB tally by value. Inlined into a
// caller that already holds two of them (E11 drains twice), the aggregate
// return buffer and the caller's locals share a frame that /O2 lays out
// differently from /Od.
__declspec(noinline) Drain drainAll() {
    Drain d{};
    // ONE HxEvent local, reused. This function used to declare three of them
    // (the poll target, a truncation probe, and an "is it still empty" probe).
    // Together with the 1280-byte tally and the by-value return buffer that put
    // the frame past 4096 bytes, which is where MSVC switches to a __chkstk
    // stack probe -- and this is the only difference found between a standalone
    // reproducer of this exact loop, which was stable at /O2, and this call
    // site, which was not.
    HxEvent ev{};
    while (d.polls < kMaxDrainPolls && HexMag_PollEvent(&ev)) {
        ++d.polls;

        if (ev.kind < HX_EVT_COUNT) ++d.countByKind[ev.kind];
        if (ev.kind >= HX_EVT_COUNT) ++d.malformedKind;

        // Clamp BEFORE indexing. Counting an out-of-range payload_len and then
        // indexing with it anyway is an out-of-bounds read: it happens to be
        // benign at /Od and corrupts state at /O2. A diagnostic that reads
        // outside its buffer is the instrument lying, not the system.
        const size_t len = (ev.payload_len < kPayloadCapacity) ? ev.payload_len
                                                              : kPayloadCapacity;
        if (ev.payload_len > kPayloadCapacity) ++d.badPayloadLen;
        if (ev.payload[len] != '\0') ++d.unterminatedPayload;
        if (ev.goal_id == 0) ++d.wrongGoalId;

        if (ev.kind == HX_EVT_GOAL_SATISFIED) d.sawSatisfied = true;
        if (ev.kind == HX_EVT_ANSWER_FINAL) d.sawFinal = true;

        if (ev.kind == HX_EVT_ANSWER_CANDIDATE) {
            ++d.candidates;
            // payload layout: "cand=" (0..4) NN (5..6) " fp=" (7..10) <16 hex> (11..26)
            if (d.candidateCount < Drain::kMaxCandidates) {
                const int slot = d.candidateCount++;
                uint64_t tmpIdx = 0, tmpFp = 0;
                d.candidateIdx[slot] = parseHex64(ev.payload + 5, tmpIdx)
                                           ? static_cast<uint32_t>(tmpIdx) : 0xFFFFFFFFu;
                d.candidateFp[slot] = parseHex64(ev.payload + 11, tmpFp) ? tmpFp : 0u;
            } else {
                ++d.candidateOverflow;
            }
        }

        if (ev.kind == HX_EVT_RESPONDER_SPAWN) {
            ++d.spawns;
            // payload is "spawn <16 hex agent id> bots=<4 hex>"; the id starts
            // after "spawn ". Bounded below by kPayloadBuf, so it cannot read
            // past the payload even if the producer stopped terminating it.
            uint64_t id = 0;
            const bool parsed =
                parseHex64(ev.payload + 6, id);
            if (parsed) {
                if (d.agentIdCount < Drain::kMaxAgentIds) {
                    d.agentIds[d.agentIdCount++] = id;
                } else {
                    ++d.agentIdOverflow;
                }
            }
        }
    }
    // One HxEvent for the WHOLE function, including the post-loop probes.
    //
    // Measured: at /O2 this function's frame carried two extra 512-byte
    // zero-initialised buffers (a truncation probe and an "is it still empty"
    // probe) on top of the poll target and the 1280-byte tally. MSVC forwards
    // the tally into the caller's sret buffer and parks its register-save slots
    // above the allocated frame, and `cmake`/disassembly of the /O2 object
    // shows the epilogue's saves landing past `sub rsp,630h`. Collapsing the
    // three buffers into one removes two 512-byte memsets and shrinks the frame,
    // and it removes the only reason those buffers existed: PollEvent reports
    // "empty" by its return value, so re-zeroing before each poll is unnecessary.
    if (d.polls >= kMaxDrainPolls) {
        // One more poll to distinguish "exactly at budget" from "kept going".
        if (HexMag_PollEvent(&ev)) d.drainTruncated = true;
    }

    // An empty queue must keep reporting empty, not start inventing events.
    for (int i = 0; i < 3; ++i) {
        if (HexMag_PollEvent(&ev)) ++d.pollsBeyondEmpty;
    }
    return d;
}

// Exact candidate fingerprint, or 0 when that candidate was not observed.
// Comparing digests as integers is a stronger assertion than the substring
// match it replaces.
std::string hex64(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

uint64_t candidateFpAt(const Drain& d, int nth) {
    return (nth < 0 || nth >= d.candidateCount) ? 0u : d.candidateFp[nth];
}

uint32_t candidateIdxAt(const Drain& d, int nth) {
    return (nth < 0 || nth >= d.candidateCount) ? 0xFFFFFFFFu : d.candidateIdx[nth];
}

const char* kGoal = "Prove that 17 is prime";

// Return the swarm to a known-clean live state.
//
// This exists because the swarm CORRECTLY refuses a new goal while one is in
// flight (E06_inflight_refused).  Without an explicit reset each scenario would
// inherit the previous one's in-flight goal and assert against stale state --
// which is what the first run of this cert did, and it produced nine checks that
// were really measuring the harness rather than the backend.
void resetSwarm(uint32_t parallel = 2) {
    (void)HexMag_Feedback(HX_FAIL_WRONG);
    (void)HexMag_Shutdown();
    (void)HexMag_Init();
(void)HexMag_SetParallelAgents(parallel);
}

// ---------------------------------------------------------------------------
// E01/E02 the backend links, initialises, and refuses a silent re-init
// ---------------------------------------------------------------------------
__declspec(noinline) void e01_init_lifecycle() {
    const uint64_t rc = HexMag_Init();
    check(rc == HX_OK, "E01_init",
          "HexMag_Init -> " + rcs(rc) + " isInitialized=" +
              std::to_string(HexMag_IsInitialized()));

    void* first = HexMag_GetState();
    const uint64_t again = HexMag_Init();
    void* second = HexMag_GetState();
    check(again == HX_ERR_ALREADY_INIT && second == first,
          "E02_reinit_refused",
          "second Init -> " + rcs(again) + ", state pointer unchanged=" +
              b(second == first) + " (a re-init must not wipe a live session)");
}

// ---------------------------------------------------------------------------
// E03 swarm width clamps to [1,8] and reports the EFFECTIVE value
// ---------------------------------------------------------------------------
__declspec(noinline) void e03_parallel_clamp() {
    check(HexMag_SetParallelAgents(0) == 1, "E03_clamp_low",
          "Set(0) -> " + std::to_string(HexMag_SetParallelAgents(0)) + " expected 1");
    check(HexMag_SetParallelAgents(99) == 8, "E03_clamp_high",
          "Set(99) -> " + std::to_string(HexMag_SetParallelAgents(99)) + " expected 8");
    check(HexMag_SetParallelAgents(3) == 3, "E03_in_range",
          "Set(3) -> " + std::to_string(HexMag_SetParallelAgents(3)));
    check(HexMag_GetParallelAgents() == 3, "E03_get_matches",
          "Get -> " + std::to_string(HexMag_GetParallelAgents()) + " expected 3");
}

// ---------------------------------------------------------------------------
// E04 no goal submitted yet is IDLE_FAIL, not success
// ---------------------------------------------------------------------------
__declspec(noinline) void e04_no_goal() {
    const uint64_t rc = HexMag_RunToSatisfied(16);
    check(rc != HX_OK, "E04_no_goal_fails",
          "RunToSatisfied with nothing submitted -> " + rcs(rc) +
              "; there is no goal, so nothing could possibly be satisfied");
}

// ---------------------------------------------------------------------------
// E05 goal argument validation
// ---------------------------------------------------------------------------
__declspec(noinline) void e05_goal_validation() {
    const uint64_t nul = HexMag_SubmitGoal(nullptr, 4);
    check(nul == HX_ERR_BAD_ARG, "E05_null_goal",
          "SubmitGoal(nullptr,4) -> " + rcs(nul));

    const uint64_t empty = HexMag_SubmitGoal(kGoal, 0);
    check(empty == HX_ERR_BAD_ARG, "E05_zero_length",
          "SubmitGoal(goal,0) -> " + rcs(empty));

    std::vector<char> big(HX_GOAL_BYTES + 16, 'x');
    const uint64_t huge = HexMag_SubmitGoal(big.data(), HX_GOAL_BYTES);
    check(huge == HX_ERR_BAD_ARG, "E05_oversize",
          "SubmitGoal(len=" + std::to_string(HX_GOAL_BYTES) + ") -> " + rcs(huge) +
              " expected BAD_ARG");
}

// ---------------------------------------------------------------------------
// E06 a goal is accepted and identified
// ---------------------------------------------------------------------------
__declspec(noinline) void e06_submit_goal() {
    const uint64_t gid = HexMag_SubmitGoal(kGoal,
                                           static_cast<uint32_t>(std::strlen(kGoal)));
    check(gid != 0, "E06_goal_id_nonzero",
          "goalId=" + std::to_string(gid) + " (0 is reserved for 'no goal')");

    // A second goal while one is in flight must be refused, not silently
    // swapped in -- swapping would strand the in-flight event queue.
    const uint64_t dup = HexMag_SubmitGoal(kGoal,
                                           static_cast<uint32_t>(std::strlen(kGoal)));
    check(dup == HX_ERR_REPEAT, "E06_inflight_refused",
          "second SubmitGoal while in flight -> " + rcs(dup));

    // The first event must echo the submitted bytes back.
    HxEvent ev{};
    const bool got = HexMag_PollEvent(&ev) != 0;
    const bool isRequested = got && ev.kind == HX_EVT_GOAL_REQUESTED;
    const bool echoed = isRequested &&
                        ev.payload_len == std::strlen(kGoal) &&
                        std::memcmp(ev.payload, kGoal, ev.payload_len) == 0;
const size_t echoLen = (ev.payload_len < kPayloadCapacity) ? ev.payload_len
                                                              : kPayloadCapacity;
    check(echoed, "E06_goal_echoed",
          std::string("first event kind=") + std::to_string(ev.kind) +
              " payload_len=" + std::to_string(ev.payload_len) +
              " payload='" + std::string(ev.payload, echoLen) + "'");
    if (got) {
        // Put it back in place by re-submitting so later checks start clean.
        HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    }
}

// ---------------------------------------------------------------------------
// E07 THE FAIL-CLOSED PROOF: no grant -> no satisfaction
// ---------------------------------------------------------------------------
// A real goal id is a 64-bit digest; the swarm reserves 0 for "no goal" and
// returns small status codes (HX_ERR_*) on refusal. Checking `gid != 0` alone
// therefore cannot tell a submitted goal from a refusal -- and a refusal looks
// exactly like a backend that silently emitted nothing.
constexpr uint64_t kSmallestRealGoalId = 64;
__declspec(noinline) void e07_no_grant_fails_closed() {
    resetSwarm(2);
    // Assert the reset actually took effect. If it did not, the swarm keeps its
    // previous stage, refuses the submission, and emits nothing -- which would
    // otherwise read as a backend that silently produced no events at all.
    check(HexMag_IsInitialized() != 0, "E07_reset_left_swarm_live",
          "after resetSwarm: isInitialized=" +
              std::to_string(HexMag_IsInitialized()) + " bots=" +
              std::to_string(HexMag_BotCount()) + " parallel=" +
              std::to_string(HexMag_GetParallelAgents()));

    const uint64_t gid = HexMag_SubmitGoal(kGoal,
                                           static_cast<uint32_t>(std::strlen(kGoal)));
const uint64_t rc = HexMag_RunToSatisfied(64);
    // Read the control block BEFORE draining. PollEvent decrements the queued
    // count as it hands events over, so reading afterwards reports zero and the
    // comparison below would be meaningless.
    const SwarmStateFields beforeDrain = []{ SwarmStateFields s{}; const SwarmStateFields* p = readSwarmState(); if (p) s = *p; return s; }();

    // One direct poll, ahead of the drain loop. This separates two questions
    // that the drain alone cannot answer: can the backend hand an event back at
    // all, and does the loop around it behave? A single poll that succeeds while
    // the loop returns nothing localises the fault to the caller, not the ABI.
    HxEvent probe{};
    const int probeResult = static_cast<int>(HexMag_PollEvent(&probe));
    check(probeResult == 1 && probe.kind == HX_EVT_GOAL_REQUESTED,
          "E07_single_poll_returns_event",
          "direct PollEvent -> " + std::to_string(probeResult) + " kind=" +
              std::to_string(probe.kind) + " (expected 1 / kind " +
              std::to_string(HX_EVT_GOAL_REQUESTED) + ") queued=" +
              std::to_string(beforeDrain.eventCount));

    Drain d = drainAll();

    check(gid >= kSmallestRealGoalId && rc != HX_OK, "E07_run_fails_closed",
          "goalId=" + std::to_string(gid) + " RunToSatisfied -> " + rcs(rc) +
              "; the goal must have been ACCEPTED (a real id, not a status code) "
              "and must still fail closed with no verification grant");
    check(beforeDrain.initialized == 1 && beforeDrain.satisfied == 0 &&
              beforeDrain.eventCount > 0 &&
              // +1 for the single direct poll E07 performs ahead of the drain.
              beforeDrain.eventCount ==
                  static_cast<uint32_t>(d.polls + d.pollsBeyondEmpty) + 1u,
          "E07_queue_consistent",
          "before drain: initialized=" + std::to_string(beforeDrain.initialized) +
              " stage=" + std::to_string(beforeDrain.stage) +
              " stepCount=" + std::to_string(beforeDrain.stepCount) +
              " satisfied=" + std::to_string(beforeDrain.satisfied) +
              " grant=" + std::to_string(beforeDrain.grant) +
              " queueFull=" + std::to_string(beforeDrain.queueFull) +
              " goalId=" + std::to_string(beforeDrain.goalId) +
              " | queued=" + std::to_string(beforeDrain.eventCount) +
              " drained=" + std::to_string(d.polls) +
              " fabricatedAfterEmpty=" + std::to_string(d.pollsBeyondEmpty));
    check(!d.sawSatisfied, "E07_no_satisfied_event",
          "GOAL_SATISFIED emitted: " + b(d.sawSatisfied) + " (expected 0)");
    check(!d.sawFinal, "E07_no_final_event",
          "ANSWER_FINAL emitted: " + b(d.sawFinal) + " (expected 0)");
check(d.candidates > 0, "E07_candidates_emitted",
          "the search still did real work: " +
              std::to_string(d.count(HX_EVT_ANSWER_CANDIDATE)) + " candidates from " +
              std::to_string(d.polls) + " polled events (truncated=" +
              b(d.drainTruncated) + ")");
    check(d.count(HX_EVT_VERIFY) == 1, "E07_halted_at_verify",
          "VERIFY events=" + std::to_string(d.count(HX_EVT_VERIFY)) +
              " polled=" + std::to_string(d.polls) +
              " (the machine stops here until an external verifier speaks)");
}

// ---------------------------------------------------------------------------
// E08 the event stream is well formed and honest
// ---------------------------------------------------------------------------
__declspec(noinline) void e08_event_integrity() {
    resetSwarm(3);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    Drain d = drainAll();

    check(d.drainExceptionCount == 0, "E08_drain_clean",
          "drain threw " + std::to_string(d.drainExceptionCount) + " time(s): " +
              std::string(d.drainExceptionWhat));
    check(d.polls > 0 && !d.drainTruncated, "E08_events_present",
          "events drained=" + std::to_string(d.polls) + " truncated=" +
              b(d.drainTruncated));
    check(d.malformedKind == 0, "E08_kinds_in_range",
          "events with kind >= HX_EVT_COUNT: " + std::to_string(d.malformedKind));
    check(d.badPayloadLen == 0, "E08_payload_len_in_range",
          "events with payload_len beyond the 480-byte payload: " +
              std::to_string(d.badPayloadLen));
    check(d.unterminatedPayload == 0, "E08_payload_terminated",
          "events whose payload is not NUL-terminated at payload_len: " +
              std::to_string(d.unterminatedPayload));
    check(d.wrongGoalId == 0, "E08_goal_id_carried",
          "events with goal_id==0: " + std::to_string(d.wrongGoalId));
    check(d.pollsBeyondEmpty == 0, "E08_no_fabricated_events",
          "PollEvent returned an event from an empty queue " +
              std::to_string(d.pollsBeyondEmpty) + " times after " +
              std::to_string(d.polls) + " real events were drained");

    // plan, spawns, role, candidates, verify -- and nothing after verify
    check(d.count(HX_EVT_GOAL_REQUESTED) == 1 && d.count(HX_EVT_PLAN) == 1,
          "E08_one_of_each_prelude",
          "goal.requested=" + std::to_string(d.count(HX_EVT_GOAL_REQUESTED)) +
              " plan=" + std::to_string(d.count(HX_EVT_PLAN)));
    check(d.count(HX_EVT_ROLE_REQUESTED) == 1, "E08_one_role_request",
          "role.requested=" + std::to_string(d.count(HX_EVT_ROLE_REQUESTED)));
}

// ---------------------------------------------------------------------------
// E09 agent ids are minted uniquely, one per effective parallel agent
// ---------------------------------------------------------------------------
__declspec(noinline) void e09_agent_ids() {
    resetSwarm(4);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    Drain d = drainAll();

    // Uniqueness is checked by pairwise comparison; Drain now holds plain
    // integers, so no temporary container is needed.
    int duplicates = 0;
    for (int i = 0; i < d.agentIdCount; ++i) {
        for (int j = i + 1; j < d.agentIdCount; ++j) {
            if (d.agentIds[i] == d.agentIds[j]) ++duplicates;
        }
    }
    const int distinct = d.agentIdCount - duplicates;

    check(d.spawns == 4, "E09_spawn_count",
          "spawn events=" + std::to_string(d.spawns) + " expected 4 (parallel=4)");
    check(distinct == d.agentIdCount && d.agentIdCount > 0,
          "E09_agent_ids_unique",
          "spawned=" + std::to_string(d.agentIdCount) + " distinct=" +
              std::to_string(distinct) + " duplicatePairs=" + std::to_string(duplicates) +
              "; every spawn must mint a fresh id");
    check(HexMag_AgentsSpawned() == 4, "E09_agents_spawned_counter",
          "HexMag_AgentsSpawned=" + std::to_string(HexMag_AgentsSpawned()) +
              " expected 4");
    check(HexMag_LastAgentId() != 0, "E09_last_agent_id",
          "last agent id=" + std::to_string(HexMag_LastAgentId()));
}

// ---------------------------------------------------------------------------
// E10 candidate payloads are a function of the submitted goal
// ---------------------------------------------------------------------------
__declspec(noinline) void e10_candidates_are_goal_derived() {
    resetSwarm(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    (void)HexMag_RunToSatisfied(64);
    Drain a = drainAll();
    const uint64_t fpA = candidateFpAt(a, 0);
    const uint32_t idxA = candidateIdxAt(a, 0);

    // A different goal must produce a different fingerprint.
    const char* other = "Prove that 19 is prime";
    resetSwarm(2);
    (void)HexMag_SubmitGoal(other, static_cast<uint32_t>(std::strlen(other)));
    (void)HexMag_RunToSatisfied(64);
    Drain c = drainAll();
    const uint64_t fpB = candidateFpAt(c, 0);

    check(fpA != 0, "E10_candidate_shape",
          "candidate fingerprint=" + hex64(fpA) + " from " +
              std::to_string(a.candidateCount) +
              " candidates (recorded exactly, not as text)");
    check(fpA != 0 && fpB != 0 && fpA != fpB,
          "E10_fingerprint_tracks_goal",
          "different goals -> different candidate fingerprints (" + hex64(fpA) +
              " vs " + hex64(fpB) + ")");
    check(idxA == 0u, "E10_candidate_indexed",
          "first candidate carries index " + std::to_string(idxA) +
              " (expected 0)");
}

// ---------------------------------------------------------------------------
// E11 THE GRANT PATH: an external verifier can complete the goal
// ---------------------------------------------------------------------------
__declspec(noinline) void e11_grant_completes() {
    resetSwarm(2);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));

    const uint32_t code = HexMag_Feedback(0);   // external verifier passed
    check(code == 2u, "E11_feedback_finalized",
          "Feedback(0) -> " + std::to_string(code) + " expected 2 (finalized)");

    const uint64_t rc = HexMag_RunToSatisfied(64);
    Drain d = drainAll();

    check(rc == HX_OK, "E11_grant_runs_to_satisfied",
          "RunToSatisfied after the grant -> " + rcs(rc) + " expected OK");
    check(d.sawFinal, "E11_final_emitted",
          "ANSWER_FINAL emitted: " + b(d.sawFinal));
    check(d.sawSatisfied, "E11_satisfied_emitted",
          "GOAL_SATISFIED emitted: " + b(d.sawSatisfied));

    // Satisfaction must be re-grantable, not a one-shot latch that lies twice.
    HexMag_Feedback(HX_FAIL_WRONG);
    (void)HexMag_SubmitGoal(kGoal, static_cast<uint32_t>(std::strlen(kGoal)));
    const uint64_t rc2 = HexMag_RunToSatisfied(64);
    Drain d2 = drainAll();
    check(rc2 != HX_OK && !d2.sawSatisfied, "E11_grant_withdrawn",
          "after a failure report, RunToSatisfied -> " + rcs(rc2) +
              " satisfied=" + b(d2.sawSatisfied) +
              "; a withdrawn grant must not leave the goal satisfied");
}

// ---------------------------------------------------------------------------
// E12 the swarm reports the tuner's own counter, not a private copy
// ---------------------------------------------------------------------------
__declspec(noinline) void e12_tuner_view() {
    (void)HexMag_Tuner_Init(4);
    (void)HexMag_Tuner_Reset(0x5EED5EED5EED5EEDull);
    HxGenProfile p{};
    (void)HexMag_Tuner_Next(0x5EED5EED5EED5EEDull, HX_FAIL_WRONG, 0, &p);
    check(HexMag_TunerAttempt() == HexMag_Tuner_Attempt(),
          "E12_tuner_view_matches",
          "swarm view=" + std::to_string(HexMag_TunerAttempt()) +
              " tuner view=" + std::to_string(HexMag_Tuner_Attempt()) +
              "; both read the same singleton");
    check(HexMag_Tuner_WeightDelta() == 0u, "E12_no_weight_delta",
          "WeightDelta=" + std::to_string(HexMag_Tuner_WeightDelta()) +
              "; the tuner owns no weight bytes");
}

// ---------------------------------------------------------------------------
// E13 the full C++ facade: the product refuses an unverified success
// ---------------------------------------------------------------------------
__declspec(noinline) void e13_facade_refuses_unverified() {
    resetSwarm(2);   // the facade submits its own goal; give it a clean slate
    const bool up = ensureControlPlane();
    check(up, "E13_control_plane_up",
          std::string("ensureControlPlane=") + b(up) + " healthCheck=" +
              b(healthCheck()) + " backend=" + resolveBaseUrl());

    // One mission whose answer cannot be verified by anything in this process.
    AskResult r = askWithAutoStart("Prove that 17 is prime", "");
    check(!r.success, "E13_no_fabricated_success",
          "success=" + b(r.success) + " goalSatisfied=" + b(r.goalSatisfied) +
              " claimState=" + std::to_string(static_cast<int>(r.claimState)) +
              " error='" + r.error + "'");
check(!r.goalSatisfied, "E13_no_satisfied_claim",
          "goalSatisfied=" + b(r.goalSatisfied) + " goalId=" +
              std::to_string(r.goalId) + " agentsSpawned=" +
              std::to_string(r.agentsSpawned) + " emittedFinal=" +
              b(r.emittedFinal) + " tunerAttempt=" + std::to_string(r.tunerAttempt));
check(r.candidateSource == "masm" && !r.selectedCandidate.empty(),
          "E13_real_candidate_flowed",
          "candidateSource='" + r.candidateSource + "' candidate='" +
              r.selectedCandidate + "' eventLog=[" + r.eventLog + "] provenance=[" +
              r.provenance + "]");
    check(r.oracleInvoked == false && r.deep2Invoked == false,
          "E13_no_silent_generator",
          "oracleInvoked=" + b(r.oracleInvoked) + " deep2Invoked=" +
              b(r.deep2Invoked) +
              "; no generators are registered, so neither may claim to have run");

    // Feedback routing through the facade.
    FeedbackResult fb = submitFeedback(true, 0);
    check(fb.finalized, "E13_feedback_finalized",
          "submitFeedback(correct) -> finalized=" + b(fb.finalized) +
              " scheduledRetry=" + b(fb.scheduledRetry) + " detail='" + fb.detail +
              "'");

    // Swarm width through the facade.
    const uint32_t set = setSwarmAgentCount(42);
    const uint32_t got = swarmAgentCount();
    check(set == 8u && got == 8u, "E13_facade_width_clamps",
          "setSwarmAgentCount(42)=" + std::to_string(set) + " swarmAgentCount()=" +
              std::to_string(got) + " expected 8/8");
}

// ---------------------------------------------------------------------------
// E14 the linked binary reports a real MASM backend
//
// This reads the backend identity through the transport client, which is a
// member of this target. The IDE's own startup diagnostic
// (core/hexmag_ide_link_probe.cpp -> RawrXD_HexMag_EmitIdeLinkDiagnostic) is a
// separate surface verified by the Win32IDE target, not by this cert.
// ---------------------------------------------------------------------------
__declspec(noinline) void e14_ide_link_probe() {
    // E13 leaves a verification grant in place (that is what submitFeedback
    // does), so start from a known-clean swarm rather than inheriting one.
    resetSwarm(2);
    // Connect through the real client so the observation includes the transport
    // path, not just a bare MASM call.
    rawrxd::agent::HexMagClient client;
    const bool connected = client.connect("masm://hexmag-control-plane");
    const rawrxd::agent::HexMagBackendIdentity id = rawrxd::agent::probeHexMagBackend();

    check(connected, "E14_client_connect",
          "HexMagClient::connect -> " + b(connected) +
              (client.lastError().empty() ? "" : " error='" + client.lastError() + "'"));

    // A full round trip through the client: submit, run, drain.
    const std::string goal = "Prove that 17 is prime";
    const bool sent = client.send(reinterpret_cast<const uint8_t*>(goal.data()), goal.size());
    check(sent, "E14_client_submit",
          "HexMagClient::send -> " + b(sent) + " goalId=" +
              std::to_string(client.goalId()) +
              (client.lastError().empty() ? "" : " error='" + client.lastError() + "'"));

    const uint64_t rc = client.runToSatisfied(64);
    check(rc != HX_OK, "E14_client_run_fails_closed",
          "client runToSatisfied -> " + rcs(rc) +
              "; the client must not report a satisfied goal with no grant");

    int kinds = 0;
    uint32_t kind = 0;
    std::string payload;
    while (client.pollEvent(kind, payload)) {
        ++kinds;
        if (kinds == 1) {
            check(kind == HX_EVT_GOAL_REQUESTED && payload == goal,
                  "E14_client_first_event",
                  "first event kind=" + std::to_string(kind) + " payload='" +
                      payload + "'");
        }
    }
    check(kinds > 0, "E14_client_drained",
          "client drained " + std::to_string(kinds) + " events then reported empty");

    client.disconnect();
    check(id.available && id.backend == "MASM", "E14_backend_reports_masm",
          "probeHexMagBackend: backend='" + id.backend + "' available=" + b(id.available) +
              " initialized=" + std::to_string(id.initialized) + " bots=" +
              std::to_string(id.bots) + " parallelAgents=" +
              std::to_string(id.parallelAgents));
}

// ---------------------------------------------------------------------------
// E15 shutdown really shuts down
// ---------------------------------------------------------------------------
__declspec(noinline) void e15_shutdown() {
    // E14 disconnects, which shuts the swarm down. Re-establish it so this
    // section tests the shutdown cycle rather than observing E14's teardown.
    resetSwarm(1);
    const uint64_t sd = HexMag_Shutdown();
    check(sd == HX_OK && HexMag_IsInitialized() == 0, "E15_shutdown",
          "Shutdown -> " + rcs(sd) + " isInitialized=" +
              std::to_string(HexMag_IsInitialized()));
check(HexMag_GetState() == nullptr, "E15_state_gone",
          std::string("GetState after shutdown = ") +
              (HexMag_GetState() ? "non-null" : "null"));
    const uint64_t rc = HexMag_SubmitGoal(kGoal,
                                          static_cast<uint32_t>(std::strlen(kGoal)));
    check(rc == HX_ERR_NOT_INIT, "E15_refuses_after_shutdown",
          "SubmitGoal after shutdown -> " + rcs(rc) + " expected NOT_INIT");
    const uint64_t twice = HexMag_Shutdown();
    check(twice == HX_ERR_NOT_INIT, "E15_double_shutdown",
          "second Shutdown -> " + rcs(twice) + " expected NOT_INIT");

    // and it can be brought back
    const uint64_t up = HexMag_Init();
    check(up == HX_OK, "E15_restart",
          "Init after shutdown -> " + rcs(up));
}

} // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    installCrashReporter();
    std::printf("=== HEXMAG_IDE_E2E_001 ===\n");
    std::printf("BACKEND=MASM swarm+repeat_tuner (real objects, no stub exports)\n");
    std::printf("LOAD_BEARING=E07 no-grant fails closed, E13 facade refuses success\n");

    // A cert must never abort: an escaping exception would report a crash
    // instead of a failed check, which is exactly the kind of unattributable
    // failure this gate exists to prevent.
    try {
        e01_init_lifecycle();
        e03_parallel_clamp();
        e04_no_goal();
        e05_goal_validation();
        e06_submit_goal();
        e07_no_grant_fails_closed();
        e08_event_integrity();
        e09_agent_ids();
        e10_candidates_are_goal_derived();
        e11_grant_completes();
        e12_tuner_view();
        e13_facade_refuses_unverified();
        e14_ide_link_probe();
        e15_shutdown();
    } catch (const std::exception& ex) {
        ++g_total;
        ++g_failed;
        std::printf("FAIL <escaped exception>           what='%s'\n", ex.what());
    } catch (...) {
        ++g_total;
        ++g_failed;
        std::printf("FAIL <escaped non-std exception>   (unknown type)\n");
    }

    std::printf("CHECKS_TOTAL=%d\n", g_total);
    std::printf("CHECKS_PASS=%d\n", g_passed);
    std::printf("CHECKS_FAIL=%d\n", g_failed);

    if (g_failed == 0) {
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("VERDICT=FAIL\n");
    return 1;
}
