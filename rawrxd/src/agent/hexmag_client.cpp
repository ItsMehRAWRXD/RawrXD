// ============================================================================
// src/agent/hexmag_client.cpp -- real HexMag transport client
// ============================================================================
// Replaces the 24-byte "// Auto-generated stub".  Every method here performs a
// real call into the MASM control plane and reports what that call returned.
//
// Compile-time guard: this translation unit references the HexMag_* ABI, so it
// is only meaningful when that ABI is linked.  The CMake targets that include
// this file also include src/asm/RawrXD_HexMag_Swarm.asm, and every consumer
// compiles with RAWR_HAS_MASM=1.  If this file is ever compiled without the MASM
// objects, it fails loudly here instead of silently resolving against a stub --
// a stub that returns "connected" is exactly the defect this file removes.
// ============================================================================
#include "agent/hexmag_client.hpp"

#include "core/hexmag_swarm.hpp"

#include <cstring>
#include <string>

namespace rawrxd { namespace agent {

namespace {

/// Largest value any HX_ERR_* status code can take. A successful SubmitGoal
/// returns a 64-bit digest of the goal bytes, so anything at or below this is a
/// refusal rather than an identifier.
constexpr uint64_t kMaxStatusCode = 64;

std::string describe(uint64_t rc) {
    switch (rc) {
        case HX_OK:               return "OK";
        case HX_ERR_ALLOC:        return "ALLOC";
        case HX_ERR_NOT_INIT:     return "control plane not initialised";
        case HX_ERR_ALREADY_INIT: return "already initialised";
        case HX_ERR_BAD_ARG:      return "bad argument";
        case HX_ERR_DEPTH:        return "handoff depth exceeded";
        case HX_ERR_REPEAT:       return "repeat without gain";
        case HX_ERR_QUEUE_FULL:   return "event queue full";
        case HX_ERR_IDLE_FAIL:    return "stalled without verification";
        case HX_ERR_TIMEOUT:      return "step budget exhausted";
        case HX_ERR_NEED_INPUT:   return "insufficient information";
        default: {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "unmapped status %llu",
                          static_cast<unsigned long long>(rc));
            return std::string(buf);
        }
    }
}

} // namespace

HexMagBackendIdentity probeHexMagBackend() {
    HexMagBackendIdentity id;
    id.initialized = HexMag_IsInitialized();
    if (id.initialized == 0) {
        // Not initialised is not the same as absent, so report the raw reading
        // rather than claiming the ABI is missing.
        id.available = false;
        id.backend = "NONE";
        id.detail = "control plane not initialised";
        return id;
    }
    id.available = true;
    id.backend = "MASM";
    id.bots = HexMag_BotCount();
    id.parallelAgents = HexMag_GetParallelAgents();
    return id;
}

bool HexMagClient::connect(const char* endpoint) {
    connected = false;
    goalId_ = 0;
    lastError_.clear();

    if (endpoint == nullptr || endpoint[0] == '\0') {
        lastError_ = "no endpoint supplied";
        return false;
    }

    const uint64_t rc = HexMag_Init();
    // ALREADY_INIT is a legitimate outcome for a reconnect: the session is live.
    if (rc != HX_OK && rc != HX_ERR_ALREADY_INIT) {
        lastError_ = "HexMag_Init: " + describe(rc);
        return false;
    }
    if (HexMag_IsInitialized() == 0) {
        lastError_ = "HexMag_Init reported success but the swarm is not initialised";
        return false;
    }

    sessionId = HexMag_BotCount();      // non-zero only if the swarm is live
    connected = true;
    return true;
}

void HexMagClient::disconnect() {
    if (connected) {
        // Shutdown clears the swarm; an already-stopped swarm is not an error
        // for a client that is simply closing.
        (void)HexMag_Shutdown();
    }
    connected = false;
    goalId_ = 0;
    sessionId = 0;
    lastError_.clear();
}

bool HexMagClient::send(const uint8_t* data, size_t len) {
    lastError_.clear();
    if (!connected) {
        lastError_ = "send on a disconnected client";
        return false;
    }
    if (data == nullptr || len == 0) {
        lastError_ = "send with no payload";
        return false;
    }

    const std::string goal(reinterpret_cast<const char*>(data), len);
    const uint64_t rc = HexMag_SubmitGoal(goal.c_str(),
                                          static_cast<uint32_t>(goal.size()));
    // Distinguish a goal id from a status code by magnitude, not by sign: a real
    // goal id is a 64-bit digest of the submitted bytes, so it is always far
    // larger than any HX_ERR_* value. 0 is reserved as "no goal".
    if (rc == 0) {
        lastError_ = "backend returned a null goal id";
        goalId_ = 0;
        return false;
    }
    if (rc <= kMaxStatusCode) {
        lastError_ = "SubmitGoal refused: " + describe(rc);
        goalId_ = 0;
        return false;
    }
    goalId_ = rc;
    return true;
}

uint64_t HexMagClient::runToSatisfied(uint32_t maxSteps) {
    if (!connected || goalId_ == 0) {
        lastError_ = "runToSatisfied without a submitted goal";
        return HX_ERR_NOT_INIT;
    }
    const uint64_t rc = HexMag_RunToSatisfied(maxSteps);
    if (rc != HX_OK) {
        lastError_ = "RunToSatisfied: " + describe(rc);
    }
    return rc;
}

bool HexMagClient::pollEvent(uint32_t& kindOut, std::string& payloadOut) {
    HxEvent ev{};
    if (!HexMag_PollEvent(&ev)) {
        return false;
    }
    kindOut = ev.kind;
    // Bounded by payload_len, which the producer guarantees is a NUL offset.
    const size_t n = (ev.payload_len < sizeof(ev.payload)) ? ev.payload_len
                                                          : sizeof(ev.payload) - 1;
    payloadOut.assign(ev.payload, n);
    return true;
}

}} // namespace rawrxd::agent