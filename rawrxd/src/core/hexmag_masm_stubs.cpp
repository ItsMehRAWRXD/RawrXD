// ============================================================================
// hexmag_masm_stubs.cpp — C Stubs for HexMag MASM Exports
// ============================================================================
// The MASM HexMag implementation is not yet present. These C stubs satisfy
// the link requirements for the HexMag control plane and runtime controller.
// Every stub returns a safe neutral value (0 / false / nullptr) so that the
// control-plane code paths degrade gracefully when RAWR_HAS_MASM is not defined
// at compile time, but the symbols must still exist at link time because the
// call sites are not all behind #ifdef.
// ============================================================================

#include <cstdint>
#include <cstddef>

// HxEvent and HxGenProfile must match the layouts expected by the callers.
// These are opaque to the linker — only the sizes and field offsets matter
// to the callers, so we define the minimal shapes.

struct HxEvent {
    uint32_t kind;      // HX_EVT_* enum values
    const char* payload;
    uint32_t reserved;
};

struct HxGenProfile {
    uint32_t strategy;
    uint32_t reserved[7];
};

extern "C" {

// ---------------------------------------------------------------------------
// Control plane symbols
// ---------------------------------------------------------------------------

uint64_t HexMag_Init(void) {
    return 0; // not initialized
}

uint64_t HexMag_SubmitGoal(const char* goal, uint32_t len) {
    (void)goal; (void)len;
    return 0; // no goal id
}

int HexMag_PollEvent(HxEvent* ev) {
    (void)ev;
    return 0; // no event
}

uint64_t HexMag_RunToSatisfied(uint32_t timeoutMs) {
    (void)timeoutMs;
    return 0; // not satisfied
}

uint32_t HexMag_AgentsSpawned(void) {
    return 0;
}

uint32_t HexMag_TunerAttempt(void) {
    return 0;
}

uint32_t HexMag_Tuner_Strategy(void) {
    return 0;
}

uint32_t HexMag_SetParallelAgents(uint32_t count) {
    return count; // echo back
}

uint32_t HexMag_Feedback(uint32_t failKindOrZero) {
    (void)failKindOrZero;
    return 0; // no-op
}

// ---------------------------------------------------------------------------
// Runtime controller / tuner symbols
// ---------------------------------------------------------------------------

int HexMag_Tuner_Init(uint32_t maxRetries) {
    (void)maxRetries;
    return 0; // success stub
}

int HexMag_Tuner_Reset(uint64_t requestIdHash) {
    (void)requestIdHash;
    return 0; // success stub
}

int HexMag_Tuner_Initial(uint64_t requestIdHash, HxGenProfile* profile) {
    (void)requestIdHash;
    if (profile) {
        profile->strategy = 0;
    }
    return 0; // success stub
}

int HexMag_Tuner_Next(uint64_t requestIdHash, uint32_t failKindMask,
                      uint32_t attempt, HxGenProfile* profile) {
    (void)requestIdHash; (void)failKindMask; (void)attempt;
    if (profile) {
        profile->strategy = 0;
    }
    return 0; // success stub
}

} // extern "C"
