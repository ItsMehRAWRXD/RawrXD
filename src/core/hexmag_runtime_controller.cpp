// ============================================================================
// hexmag_runtime_controller.cpp — sequencing owner (P0C); truth via finalize
// ============================================================================
#include "core/hexmag_runtime_controller.hpp"
#include "core/hexmag_repeat_tuner.hpp"

#include <algorithm>
#include <cstring>
#include <exception>

namespace RawrXD {
namespace HexMag {

void HexMagRuntimeController::enter(ControllerResult& r, ControllerPhase p,
                                    const char* step) const {
    r.phase = p;
    r.phases.push_back(p);
    r.sequenceLog.push_back(step && step[0] ? step : controllerPhaseName(p));
}

void HexMagRuntimeController::ensureTunerRequest(const std::string& prompt) {
#ifdef RAWR_HAS_MASM
    if (requestIdHash_ != 0)
        return;
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : prompt) {
        h ^= c;
        h *= 1099511628211ull;
    }
    if (h == 0)
        h = 1;
    requestIdHash_ = h;
    (void)HexMag_Tuner_Init(cfg_.maxRetries + 1);
    (void)HexMag_Tuner_Reset(requestIdHash_);
    HxGenProfile profile{};
    (void)HexMag_Tuner_Initial(requestIdHash_, &profile);
#else
    (void)prompt;
#endif
}

void HexMagRuntimeController::advanceTunerOnWrong(uint32_t failKindMask) {
#ifdef RAWR_HAS_MASM
    // NEED_INPUT is terminal for the request — never mutate toward FINAL.
    if (needInputLatched_)
        return;
    if (requestIdHash_ == 0)
        return;
    HxGenProfile profile{};
    (void)HexMag_Tuner_Next(requestIdHash_, failKindMask, attempt_, &profile);
#else
    (void)failKindMask;
#endif
}

ControllerResult HexMagRuntimeController::failClosed(ControllerResult r,
                                                     ControllerFail f,
                                                     const char* why) {
    r.fail = f;
    r.finalAuthority = false;
    r.sequencingOk = false;
    r.fabricatedFinal = false;
    r.diagnostic = why ? why : "fail_closed";
    r.finalize.allowed = false;
    r.finalize.reason = r.diagnostic;
    enter(r, ControllerPhase::FailedClosed, r.diagnostic.c_str());
    stopped_ = true;
    return r;
}

ControllerResult HexMagRuntimeController::sequenceClientResult(
    ClientAskResult client, uint64_t expectedGeneration) {
    ControllerResult r;
    r.lastClient = std::move(client);
    ClientAskResult& c = r.lastClient;
    r.generation = generation_;
    r.attempt = attempt_;
    r.needInputLatched = needInputLatched_;
    r.clientSuccess = c.clientSuccess;
    r.controllerDispatched = true;
    enter(r, ControllerPhase::Dispatch, "CTRL_DISPATCH");
    enter(r, ControllerPhase::AwaitEvents, "CTRL_CLIENT_RESULT");

    if (expectedGeneration != 0 && expectedGeneration != generation_) {
        return failClosed(std::move(r), ControllerFail::StaleGeneration,
                          "STALE_GENERATION");
    }

    // Default ClientIdentity.clientPath is "UNAVAILABLE" — that alone is not a
    // backend failure (scripted certs inject candidates without fillIdentity).
    // Require transport failure signals: !clientSuccess and/or explicit diagnostics.
    const bool pathMarkedUnavailable =
        c.trace.id.clientPath
        && std::strcmp(c.trace.id.clientPath, "UNAVAILABLE") == 0;
    const bool unavailableDiag =
        c.trace.diagnostic.find("unavailable") != std::string::npos
        || c.ask.error.find("unavailable") != std::string::npos
        || c.ask.error.find("fail-closed") != std::string::npos
        || c.ask.error.find("HexMag_Init failed") != std::string::npos
        || c.ask.error.find("no transport") != std::string::npos;
    if (unavailableDiag || (!c.clientSuccess && pathMarkedUnavailable)) {
        return failClosed(std::move(r), ControllerFail::BackendFailure,
                          "BACKEND_FAILURE");
    }

    if (needInputLatched_) {
        enter(r, ControllerPhase::NeedInputLatched, "CTRL_NEED_INPUT_LATCH_HOLD");
        if (c.finalAuthority || c.ask.success) {
            return failClosed(std::move(r), ControllerFail::NeedInput,
                              "NEED_INPUT_LATCH: reject FINAL resurrection");
        }
        r.phase = ControllerPhase::NeedInputLatched;
        r.fail = ControllerFail::NeedInput;
        r.sequencingOk = true;
        r.finalAuthority = false;
        r.needInputLatched = true;
        r.diagnostic = "NEED_INPUT latched";
        stopped_ = true;
        return r;
    }

    const bool sawNeedInput =
        c.ask.needInput
        || c.ask.claimState == ClaimState::MissingInput
        || std::any_of(c.trace.events.begin(), c.trace.events.end(),
                       [](const DecodedEvent& e) {
                           return e.kind == HX_EVT_NEED_INPUT
                               || e.name == "need_input";
                       });

    if (sawNeedInput) {
        needInputLatched_ = true;
        r.needInputLatched = true;
        enter(r, ControllerPhase::NeedInputLatched, "CTRL_NEED_INPUT_LATCH_SET");
        if (c.finalAuthority || c.ask.success) {
            return failClosed(std::move(r), ControllerFail::NeedInput,
                              "NEED_INPUT: strip illicit FINAL");
        }
        r.phase = ControllerPhase::NeedInputLatched;
        r.fail = ControllerFail::NeedInput;
        r.sequencingOk = true;
        r.finalAuthority = false;
        r.diagnostic = "NEED_INPUT";
        stopped_ = true;
        return r;
    }

    if (c.trace.diagnostic == "EMPTY_EVENT_STREAM"
        || (c.clientSuccess && c.trace.events.empty()
            && c.ask.selectedCandidate.empty() && c.ask.answer.empty())
        || (c.trace.masmSubmitCalled && c.trace.events.empty()
            && !c.finalAuthority && c.ask.answer.empty()
            && c.ask.error.empty() && !c.clientSuccess)) {
        return failClosed(std::move(r), ControllerFail::EmptyEventStream,
                          "EMPTY_EVENT_STREAM");
    }

    {
        int idxFinal = -1, idxCand = -1, idxNeed = -1, idxGoal = -1;
        for (int i = 0; i < static_cast<int>(c.trace.events.size()); ++i) {
            const auto& e = c.trace.events[static_cast<size_t>(i)];
            if (e.kind >= HX_EVT_COUNT) {
                return failClosed(std::move(r), ControllerFail::OutOfOrderEvent,
                                  "MALFORMED_EVENT_KIND");
            }
            if (idxGoal < 0
                && (e.kind == HX_EVT_GOAL_REQUESTED || e.name == "goal.requested"))
                idxGoal = i;
            if (idxCand < 0
                && (e.kind == HX_EVT_ANSWER_CANDIDATE || e.kind == HX_EVT_ANSWER
                    || e.name == "answer.candidate" || e.name == "answer"))
                idxCand = i;
            if (idxFinal < 0
                && (e.kind == HX_EVT_ANSWER_FINAL || e.name == "answer.final"))
                idxFinal = i;
            if (idxNeed < 0
                && (e.kind == HX_EVT_NEED_INPUT || e.name == "need_input"))
                idxNeed = i;
        }
        if (c.trace.diagnostic == "OUT_OF_ORDER_EVENT"
            || (idxFinal >= 0 && idxCand >= 0 && idxFinal < idxCand)
            || (idxNeed >= 0 && idxFinal >= 0 && idxFinal < idxNeed)
            || (idxFinal >= 0 && idxGoal >= 0 && idxFinal < idxGoal)
            || (idxNeed >= 0 && idxFinal > idxNeed)) {
            return failClosed(std::move(r), ControllerFail::OutOfOrderEvent,
                              "OUT_OF_ORDER_EVENT");
        }
    }

    const bool hasCandidate =
        !c.ask.selectedCandidate.empty()
        || !c.ask.answer.empty()
        || std::any_of(c.trace.events.begin(), c.trace.events.end(),
                       [](const DecodedEvent& e) {
                           return e.kind == HX_EVT_ANSWER_CANDIDATE
                               || e.kind == HX_EVT_ANSWER
                               || e.kind == HX_EVT_ANSWER_FINAL;
                       });
    r.candidateExists = hasCandidate;
    enter(r, ControllerPhase::CandidateReview,
          hasCandidate ? "CTRL_CANDIDATE" : "CTRL_NO_CANDIDATE");

    if ((c.ask.success || c.finalAuthority)
        && c.ask.claimState != ClaimState::Verified
        && c.ask.claimState != ClaimState::Proven) {
        return failClosed(std::move(r), ControllerFail::UnsupportedSuccess,
                          "UNSUPPORTED_SUCCESS: success without verified claim");
    }

    const bool badCandidate =
        c.trace.diagnostic == "BAD_CANDIDATE"
        || c.trace.diagnostic == "VERIFY_DENY"
        || (!c.finalAuthority && !c.ask.success && hasCandidate
            && (c.ask.claimState == ClaimState::Candidate
                || c.ask.claimState == ClaimState::UnderReview
                || c.ask.error.find("FINAL_GATE") != std::string::npos
                || c.ask.error.find("not verified") != std::string::npos));

    if (badCandidate) {
        enter(r, ControllerPhase::VerifyRoute, "CTRL_VERIFY_DENY");
        if (retriesUsed_ >= cfg_.maxRetries) {
            r.sequencingOk = true;
            r.finalAuthority = false;
            r.diagnostic = "RETRY_EXHAUSTED";
            r.fail = ControllerFail::RetryExhausted;
            enter(r, ControllerPhase::Exhausted, "CTRL_RETRY_EXHAUSTED");
            stopped_ = true;
            return r;
        }
        ++retriesUsed_;
        ++attempt_;
        ++generation_;
        // Polymorphic WRONG path: mutate genome inside controller (not IDE).
        advanceTunerOnWrong(HX_FAIL_WRONG | HX_FAIL_TEST | HX_FAIL_UNSUPPORTED);
        r.generation = generation_;
        r.attempt = attempt_;
        r.redispatches = retriesUsed_;
        r.sequencingOk = true;
        r.finalAuthority = false;
        r.fail = ControllerFail::BadCandidate;
        r.diagnostic = "BAD_CANDIDATE: generation+1 redispatch";
        enter(r, ControllerPhase::TunerRedispatch, "CTRL_TUNER_GENERATION_BUMP");
        return r;
    }

    if (!hasCandidate && !c.ask.success) {
        return failClosed(std::move(r), ControllerFail::EmptyEventStream,
                          "NO_CANDIDATE");
    }

    enter(r, ControllerPhase::VerifyRoute, "CTRL_VERIFY_ROUTE");
    enter(r, ControllerPhase::FinalizeEval, "CTRL_FINALIZE_POLICY");

    if (finalGranted_ || authorityDecisions_ > 0) {
        return failClosed(std::move(r), ControllerFail::DuplicateFinal,
                          "DUPLICATE_FINAL: one authority decision only");
    }

    Claim claim;
    claim.text = !c.ask.answer.empty() ? c.ask.answer : c.ask.selectedCandidate;
    claim.state = c.ask.claimState;
    claim.generationId = generation_;
    if (claim.state == ClaimState::Verified || claim.state == ClaimState::Proven) {
        Evidence e;
        e.kind = "control_plane_gates";
        e.tool = "hexmag_finalize_policy";
        e.payload = "claim_state_verified";
        e.passesVerifier = true;
        claim.evidence.push_back(std::move(e));
    }

    r.finalize = evaluateFinalize(claim);
    if (!r.finalize.allowed) {
        r.fail = ControllerFail::FinalizeDenied;
        r.finalAuthority = false;
        r.sequencingOk = true;
        r.diagnostic = r.finalize.reason;
        enter(r, ControllerPhase::FinalizeEval, "CTRL_FINAL_DENIED");
        if (retriesUsed_ < cfg_.maxRetries && hasCandidate) {
            ++retriesUsed_;
            ++attempt_;
            ++generation_;
            advanceTunerOnWrong(HX_FAIL_WRONG | HX_FAIL_UNSUPPORTED);
            r.generation = generation_;
            r.attempt = attempt_;
            r.redispatches = retriesUsed_;
            r.fail = ControllerFail::FinalizeDenied;
            r.diagnostic = "FINAL_DENIED: tuner redispatch";
            enter(r, ControllerPhase::TunerRedispatch, "CTRL_TUNER_AFTER_FINAL_DENY");
            return r;
        }
        stopped_ = true;
        return r;
    }

    ++authorityDecisions_;
    finalGranted_ = true;
    stopped_ = true;
    r.authorityDecisions = authorityDecisions_;
    r.finalAuthority = true;
    r.sequencingOk = true;
    r.fail = ControllerFail::None;
    r.diagnostic = "ACTIONABLE_FINAL";
    enter(r, ControllerPhase::Done, "CTRL_FINAL_ALLOWED");
    return r;
}

ControllerResult HexMagRuntimeController::tryResume(const std::string& prompt,
                                                    const std::string& context) {
    ControllerResult r;
    enter(r, ControllerPhase::Request, "CTRL_TRY_RESUME");
    if (needInputLatched_) {
        ClientAskResult illicit;
        illicit.ask.success = true;
        illicit.finalAuthority = true;
        illicit.clientSuccess = true;
        illicit.ask.claimState = ClaimState::Verified;
        illicit.ask.answer = "resurrect";
        return sequenceClientResult(std::move(illicit), generation_);
    }
    if (finalGranted_ || stopped_) {
        return failClosed(std::move(r), ControllerFail::DuplicateFinal,
                          "RESUME_FORBIDDEN: controller stopped");
    }
    return run(prompt, context);
}

ControllerResult HexMagRuntimeController::run(const std::string& prompt,
                                              const std::string& context) {
    try {
        ControllerResult bootstrap;
        enter(bootstrap, ControllerPhase::Request, "CTRL_RUN");
        enter(bootstrap, ControllerPhase::ClassifyValidate, "CTRL_CLASSIFY");

        if (prompt.empty()) {
            return failClosed(std::move(bootstrap), ControllerFail::EmptyGoal,
                              "EMPTY_GOAL: no fake success");
        }
        if (!transport_) {
            return failClosed(std::move(bootstrap), ControllerFail::BackendFailure,
                              "BACKEND_FAILURE: no transport");
        }

        ensureTunerRequest(prompt);

        const ClientIdentity id = clientIdentity();
        const bool backendReady = (std::strcmp(id.backend, "MASM") == 0)
            && id.linked == 1
            && std::strcmp(id.clientPath, "MASM") == 0;

        if (needInputLatched_) {
            enter(bootstrap, ControllerPhase::NeedInputLatched,
                  "CTRL_SKIP_TRANSPORT_LATCHED");
            ClientAskResult illicit;
            illicit.ask.success = true;
            illicit.finalAuthority = true;
            illicit.clientSuccess = true;
            illicit.ask.claimState = ClaimState::Verified;
            illicit.ask.answer = "illicit_final_after_need_input";
            auto step = sequenceClientResult(std::move(illicit), generation_);
            step.clientBackendReady = backendReady;
            return step;
        }
        if (finalGranted_) {
            return failClosed(std::move(bootstrap), ControllerFail::DuplicateFinal,
                              "DUPLICATE_FINAL: already granted");
        }

        std::vector<std::string> accumLog = bootstrap.sequenceLog;
        std::vector<ControllerPhase> accumPhases = bootstrap.phases;

        for (;;) {
            if (forceException_) {
                throw std::runtime_error("controller_force_exception");
            }
            const uint64_t genAtDispatch = generation_;
            auto step = sequenceClientResult(transport_->ask(prompt, context),
                                             genAtDispatch);
            step.clientBackendReady = backendReady;
            accumLog.insert(accumLog.end(), step.sequenceLog.begin(),
                            step.sequenceLog.end());
            accumPhases.insert(accumPhases.end(), step.phases.begin(),
                               step.phases.end());
            step.sequenceLog = accumLog;
            step.phases = accumPhases;

            if (step.phase == ControllerPhase::TunerRedispatch) {
                continue;
            }
            return step;
        }
    } catch (const std::exception& ex) {
        ControllerResult err;
        err.finalAuthority = false;
        err.fabricatedFinal = false;
        std::string msg = std::string("CONTROLLER_EXCEPTION: ") + ex.what();
        return failClosed(std::move(err), ControllerFail::ControllerException,
                          msg.c_str());
    } catch (...) {
        ControllerResult err;
        err.finalAuthority = false;
        return failClosed(std::move(err), ControllerFail::ControllerException,
                          "CONTROLLER_EXCEPTION: unknown");
    }
}

} // namespace HexMag
} // namespace RawrXD
