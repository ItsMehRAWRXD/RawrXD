// ============================================================================
// hexmag_control_plane.hpp — End-to-end facade: policy stack + MASM swarm
// ============================================================================
#ifndef RAWRXD_HEXMAG_CONTROL_PLANE_HPP
#define RAWRXD_HEXMAG_CONTROL_PLANE_HPP

#include "core/hexmag_authority.hpp"
#include "core/hexmag_constitution.hpp"
#include "core/hexmag_repeat_tuner.hpp"
#include "core/hexmag_swarm.hpp"

#include <functional>
#include <string>

namespace RawrXD {
namespace HexMag {

struct AskResult {
    bool success = false;
    std::string answer;
    std::string error;
    uint64_t goalId = 0;
    uint64_t agentsSpawned = 0;
    uint32_t tunerAttempt = 0;
    bool goalSatisfied = false;
    bool needInput = false;     // HX_EVT_NEED_INPUT observed
    bool emittedFinal = false;  // HX_EVT_ANSWER_FINAL observed
    bool oracleInvoked = false;
    bool deep2Invoked = false;
    std::string candidateSource;    // oracle|deep2|scripted|masm
    std::string selectedCandidate;  // raw selected candidate (never FINAL authority)
    ClaimState claimState = ClaimState::Candidate;
    std::string provenance; // directive explain chain
    std::string eventLog;
};

struct StreamResult {
    bool success = false;
    std::string error;
    bool goalSatisfied = false;
    std::string finalAnswer;
};

struct FeedbackResult {
    bool scheduledRetry = false;
    bool finalized = false;
    bool exhausted = false;
    std::string detail;
};

bool ensureControlPlane();
bool tryLaunchService();
bool healthCheck();
std::string resolveBaseUrl();

/// Compile operator text into a L2 mission directive, then run MASM swarm.
AskResult askWithAutoStart(const std::string& prompt, const std::string& context);

StreamResult streamAgentWithAutoStart(
    const std::string& prompt,
    std::function<void(const std::string&)> onToken,
    float timeoutSeconds = 30.0f);

FeedbackResult submitFeedback(bool correct, uint32_t failKindMask = HX_FAIL_WRONG);

/// Cursor-style multi-response width: parallel polymorphic agents (1–8).
uint32_t setSwarmAgentCount(uint32_t count);
uint32_t swarmAgentCount();

bool noteAttempt(const Attempt& attempt);

std::string defaultResponseGenAsk(const std::string& question);

} // namespace HexMag
} // namespace RawrXD

#endif
