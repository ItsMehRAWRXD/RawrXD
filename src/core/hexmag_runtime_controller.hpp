// ============================================================================
// hexmag_runtime_controller.hpp — HEXMAG_RUNTIME_CONTROLLER_001
// ============================================================================
// controller owns sequencing
// controller does not own truth
// FINALIZE_POLICY owns final authority
//
// Does NOT invent FINAL, dispatch UI, or bypass allowFinal/isAllowedFinalClaim.
// ============================================================================
#ifndef RAWRXD_HEXMAG_RUNTIME_CONTROLLER_HPP
#define RAWRXD_HEXMAG_RUNTIME_CONTROLLER_HPP

#include "agent/hexmag_client.hpp"
#include "core/hexmag_authority.hpp"
#include "core/hexmag_finalize_policy.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace RawrXD {
namespace HexMag {

enum class ControllerPhase : uint8_t {
    Idle = 0,
    Request,
    ClassifyValidate,
    Dispatch,
    AwaitEvents,
    NeedInputLatched,
    CandidateReview,
    VerifyRoute,
    TunerRedispatch,
    FinalizeEval,
    Exhausted,
    FailedClosed,
    Done,
};

enum class ControllerFail : uint8_t {
    None = 0,
    NeedInput,
    BadCandidate,
    RetryExhausted,
    StaleGeneration,
    EmptyEventStream,
    OutOfOrderEvent,
    BackendFailure,
    FinalizeDenied,
    UnsupportedSuccess,
    ControllerException,
    EmptyGoal,
    DuplicateFinal,
};

inline const char* controllerPhaseName(ControllerPhase p) {
    switch (p) {
        case ControllerPhase::Idle:             return "IDLE";
        case ControllerPhase::Request:          return "REQUEST";
        case ControllerPhase::ClassifyValidate: return "CLASSIFY_VALIDATE";
        case ControllerPhase::Dispatch:         return "DISPATCH_CLIENT";
        case ControllerPhase::AwaitEvents:      return "CLIENT_RESULT";
        case ControllerPhase::NeedInputLatched: return "LATCH_NEED_INPUT";
        case ControllerPhase::CandidateReview:  return "CANDIDATE";
        case ControllerPhase::VerifyRoute:      return "VERIFY";
        case ControllerPhase::TunerRedispatch:  return "NEW_GENERATION";
        case ControllerPhase::FinalizeEval:     return "FINAL";
        case ControllerPhase::Exhausted:        return "EXHAUSTED";
        case ControllerPhase::FailedClosed:     return "FAIL_CLOSED";
        case ControllerPhase::Done:             return "STOPPED";
    }
    return "?";
}

inline const char* controllerFailName(ControllerFail f) {
    switch (f) {
        case ControllerFail::None:                return "none";
        case ControllerFail::NeedInput:           return "need_input";
        case ControllerFail::BadCandidate:        return "bad_candidate";
        case ControllerFail::RetryExhausted:      return "retry_exhausted";
        case ControllerFail::StaleGeneration:     return "stale_generation";
        case ControllerFail::EmptyEventStream:    return "empty_event_stream";
        case ControllerFail::OutOfOrderEvent:     return "out_of_order_event";
        case ControllerFail::BackendFailure:      return "backend_failure";
        case ControllerFail::FinalizeDenied:      return "finalize_denied";
        case ControllerFail::UnsupportedSuccess:  return "unsupported_success";
        case ControllerFail::ControllerException: return "controller_exception";
        case ControllerFail::EmptyGoal:           return "empty_goal";
        case ControllerFail::DuplicateFinal:      return "duplicate_final";
    }
    return "?";
}

/// Injected transport — live HexMagClient or scripted adversarial port.
struct IHexMagTransport {
    virtual ~IHexMagTransport() = default;
    virtual ClientAskResult ask(const std::string& prompt,
                                const std::string& context) = 0;
};

struct LiveHexMagTransport final : IHexMagTransport {
    HexMagClient client;
    ClientAskResult ask(const std::string& prompt,
                        const std::string& context) override {
        return client.ask(prompt, context);
    }
};

struct ScriptedHexMagTransport final : IHexMagTransport {
    std::function<ClientAskResult(const std::string&, const std::string&)> fn;
    uint32_t callCount = 0;
    ClientAskResult ask(const std::string& prompt,
                        const std::string& context) override {
        ++callCount;
        if (!fn) {
            ClientAskResult r;
            r.ask.error = "scripted transport empty";
            return r;
        }
        return fn(prompt, context);
    }
};

struct ControllerConfig {
    uint32_t maxRetries = 3; // redispatches after attempt 0
};

struct ControllerResult {
    ControllerPhase phase = ControllerPhase::Idle;
    ControllerFail fail = ControllerFail::None;
    bool clientBackendReady = false;
    bool controllerDispatched = false; // != success
    bool clientSuccess = false;
    bool candidateExists = false;
    bool sequencingOk = false;
    bool finalAuthority = false; // ONLY via FinalizePolicy
    bool needInputLatched = false;
    bool fabricatedFinal = false; // must stay false
    uint64_t generation = 0;
    uint32_t attempt = 0;
    uint32_t redispatches = 0;
    uint32_t authorityDecisions = 0;
    FinalizeDecision finalize;
    ClientAskResult lastClient;
    std::string diagnostic;
    std::vector<std::string> sequenceLog;
    std::vector<ControllerPhase> phases;
};

class HexMagRuntimeController {
public:
    explicit HexMagRuntimeController(IHexMagTransport* transport,
                                     ControllerConfig cfg = {})
        : transport_(transport), cfg_(cfg) {}

    /// Full state machine: REQUEST→…→FINAL|STOP (loops tuner redispatches).
    ControllerResult run(const std::string& prompt,
                         const std::string& context = {});

    /// Single-shot sequencing (no transport). Cert adversarial scripts.
    ControllerResult sequenceClientResult(ClientAskResult client,
                                          uint64_t expectedGeneration);

    /// After STOP/NEED_INPUT/FINAL — must not resurrect authority.
    ControllerResult tryResume(const std::string& prompt,
                               const std::string& context = {});

    uint64_t generation() const { return generation_; }
    uint32_t attempt() const { return attempt_; }
    bool needInputLatched() const { return needInputLatched_; }
    bool finalGranted() const { return finalGranted_; }

    void resetSession() {
        generation_ = 1;
        attempt_ = 0;
        needInputLatched_ = false;
        retriesUsed_ = 0;
        finalGranted_ = false;
        stopped_ = false;
        authorityDecisions_ = 0;
    }

    /// Cert: throw inside run loop.
    void setForceException(bool v) { forceException_ = v; }

private:
    IHexMagTransport* transport_ = nullptr;
    ControllerConfig cfg_{};
    uint64_t generation_ = 1;
    uint32_t attempt_ = 0;
    bool needInputLatched_ = false;
    uint32_t retriesUsed_ = 0;
    bool finalGranted_ = false;
    bool stopped_ = false;
    uint32_t authorityDecisions_ = 0;
    bool forceException_ = false;

    void enter(ControllerResult& r, ControllerPhase p, const char* step) const;
    ControllerResult failClosed(ControllerResult r, ControllerFail f,
                                const char* why);
};

} // namespace HexMag
} // namespace RawrXD

#endif
