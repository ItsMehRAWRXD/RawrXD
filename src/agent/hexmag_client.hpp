// hexmag_client.hpp — HexMag client (MASM control-plane path)
// ============================================================================
// HEXMAG_CLIENT_MASM_001
//
//   client may transport/decode/expose status
//   client MUST NOT invent FINAL, downgrade NEED_INPUT, bypass finalize gates,
//   or treat candidates as verified evidence.
//
// Runtime identity (required in GATE):
//   HEXMAG_BACKEND=MASM|NONE
//   HEXMAG_LINKED=0|1
//   HEXMAG_CLIENT_PATH=MASM|UNAVAILABLE|NATIVE_FALLBACK
// ============================================================================
#pragma once

#include "core/hexmag_control_plane.hpp"
#include "core/hexmag_swarm.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
// Legacy JIT demo exports — NOT the HexMag control plane.
__declspec(dllexport) int HexMagJIT_Init(size_t capacity);
__declspec(dllexport) void HexMagJIT_Shutdown(void);
__declspec(dllexport) int HexMagJIT_EmitExit42(void);
__declspec(dllexport) int HexMagJIT_Execute(void);
__declspec(dllexport) int HexMagCLI_Run(int argc, const char** argv);
// MASM builds: prints fail-closed diagnostic (no fake service).
__declspec(dllexport) void hexmag_connect_stub(void);
#ifdef __cplusplus
}
#endif

namespace RawrXD {
namespace HexMag {

struct ClientIdentity {
    const char* backend = "NONE";       // MASM | NONE
    int linked = 0;                     // 1 iff RAWR_HAS_MASM compiled in
    const char* clientPath = "UNAVAILABLE"; // MASM | UNAVAILABLE | NATIVE_FALLBACK
};

struct DecodedEvent {
    uint32_t kind = HX_EVT_NONE;
    std::string name;
    std::string payload;
};

struct ClientTrace {
    ClientIdentity id;
    bool masmInitCalled = false;
    bool masmSubmitCalled = false;
    bool masmRunCalled = false;
    bool masmPollCalled = false;
    uint64_t submitRc = 0;
    uint64_t runRc = 0;
    uint32_t pollCount = 0;
    uint64_t generationIdBefore = 0;
    uint64_t generationIdAfter = 0;
    uint32_t tunerAttempt = 0;
    std::vector<DecodedEvent> events; // order preserved
    std::string backendTrace;
    std::string diagnostic;
};

struct ClientAskResult {
    AskResult ask;          // control-plane / gate outcome (FINAL authority lives here)
    ClientTrace trace;
    // Invariants mirrored for cert readability:
    bool clientSuccess = false;     // transport/decode ok — NOT final authority
    bool finalAuthority = false;    // ask.success after allowFinal + isAllowedFinalClaim
    bool fabricatedFinal = false;   // must always be false
};

/// Snapshot of compile-time + optional env fallback policy.
ClientIdentity clientIdentity();

/// Format required GATE identity block.
std::string formatClientIdentityBlock();

class HexMagClient {
public:
    /// Fail-closed simulation (cert: Backend unavailable).
    void setForceUnavailable(bool v) { forceUnavailable_ = v; }
    bool forceUnavailable() const { return forceUnavailable_; }

    /// Init control plane (HexMag_Init). Fail closed if MASM absent / forced down.
    bool initialize(ClientTrace* trace = nullptr);

    /// Full ask: Init → SubmitGoal → RunToSatisfied → PollEvent → decode → FINAL gates.
    /// Does not invent FINAL; delegates allowFinal / isAllowedFinalClaim to control plane.
    ClientAskResult ask(const std::string& prompt, const std::string& context = {});

    /// Low-level: same MASM call chain, returns raw drained events without upgrading
    /// candidates to FINAL. Used by cert to prove ordering / NEED_INPUT / candidates.
    ClientAskResult runMasmChain(const std::string& goal, uint32_t maxSteps = 64);

    bool healthCheck() const;
    std::string resolveBaseUrl() const;

private:
    bool forceUnavailable_ = false;
    void fillIdentity(ClientTrace& t) const;
    void appendBackend(ClientTrace& t, const char* line) const;
};

} // namespace HexMag
} // namespace RawrXD
