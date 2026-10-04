// ============================================================================
// src/agent/hexmag_client.hpp -- HexMag transport client
// ============================================================================
// The three operations were inline no-ops that returned true unconditionally:
// connect() set connected = true and returned true whatever the endpoint was,
// and send() returned `connected` without looking at the bytes.  A transport
// that cannot fail is not a transport.
//
// The implementations now live in hexmag_client.cpp and talk to the real MASM
// control plane: connect() initialises the swarm and reports the actual result,
// send() submits the payload as a goal and returns false when the swarm
// refuses it, and disconnect() shuts the swarm down.
// ============================================================================
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace rawrxd { namespace agent {

/// What a live HexMag backend actually is, as observed -- never as assumed.
/// A previous revision hardcoded backend = "MASM"; this is read from the
/// swarm instead, so a link that lost the MASM objects reports NONE.
struct HexMagBackendIdentity {
    bool available = false;      ///< the HexMag_* ABI is present and initialised
    uint32_t initialized = 0;    ///< raw HexMag_IsInitialized()
    uint32_t bots = 0;           ///< raw HexMag_BotCount()
    uint32_t parallelAgents = 0; ///< raw HexMag_GetParallelAgents()
    std::string backend;         ///< "MASM", or "NONE" when unavailable
    std::string detail;          ///< last error text, empty when healthy
};

HexMagBackendIdentity probeHexMagBackend();

struct HexMagClient {
    uint32_t sessionId = 0;
    bool connected = false;

    /// Initialise the swarm.  Returns true only when the backend is live.
    bool connect(const char* endpoint);
    void disconnect();

    /// Submit `data` as a goal.  Returns false -- rather than reporting a
    /// transport that silently dropped the bytes -- when the backend refuses
    /// the submission, and records why in `lastError()`.
    bool send(const uint8_t* data, size_t len);

    /// Identifies the session goal, or 0 when no goal is in flight.
    uint64_t goalId() const { return goalId_; }

    const std::string& lastError() const { return lastError_; }

    /// Runs the current goal to completion.  Returns the swarm status; it is
    /// HX_OK only when the goal was actually satisfied.
    uint64_t runToSatisfied(uint32_t maxSteps);

    /// Pop the next real event.  Returns false once the queue is drained.
    bool pollEvent(uint32_t& kindOut, std::string& payloadOut);

private:
    uint64_t goalId_ = 0;
    std::string lastError_;
};

}} // namespace rawrxd::agent