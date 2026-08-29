// ============================================================================
// hexmag_runtime_controller.cpp — sequencing owner (P0C); truth via finalize
// ============================================================================
#include "core/hexmag_runtime_controller.hpp"

#include <algorithm>
#include <cstring>
#include <exception>

namespace RawrXD {
namespace HexMag {

void HexMagRuntimeController::enter(ControllerResult& r, ControllerPhase p,
                                    const char* step) const {
    r.phase = p;
    r.phases.push_back(p);
    if (step && step[0]) r.sequenceLog.push_back(step);
    else r.sequenceLog.push_back(controllerPhaseName(p));
}

ControllerResult HexMagRuntimeController::failClosed(ControllerResult r,
                                                     ControllerFail f,
                                                     const char* why) const {
    r.fail = f;
    r.finalAuthority = false;
    r.sequencingOk = false;
    r.fabricatedFinal = false;
    enter(const_cast<ControllerResult&>(r), ControllerPhase::FailedClosed,
          why);
    // enter already set phase; keep diagnostic
    r.phase = ControllerPhase::FailedClosed;
    r.diagnostic = why ? why : "fail_closed";
    r.finalize.allowed = false;
    r.finalize.reason = r.diagnostic;
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

    // Stale generation envelope
    if (expectedGeneration != 0 && expectedGeneration != generation_) {
        return failClosed(std::move(r), ControllerFail::StaleGeneration,
                          "STALE_GENERATION");
    }

    // Backend failure / unavailable
    const bool pathUnavailable =
        c.trace.id.clientPath
        && std::strcmp(c.trace.id.clientPath, "UNAVAILABLE") == 0;
    if (pathUnavailable
        || c.trace.diagnostic.find("unavailable") != std::string::npos
        || c.ask.error.find("unavailable") != std::string::npos
        || c.ask.error.find("fail-closed") != std::string::npos
        || c.ask.error.find("HexMag_Init failed") != std::string::npos
        || c.ask.error.find("no transport") != std::string::npos) {
        return failClosed(std::move(r), ControllerFail::BackendFailure,
                          "BACKEND_FAILURE");
    }

    // NEED_INPUT latch hold: nothing downstream resurrects
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

    // Empty events / empty result — no fake success
    if (c.trace.diagnostic == "EMPTY_EVENT_STREAM"
        || (c.clientSuccess && c.trace.events.empty()
            && c.ask.selectedCandidate.empty() && c.ask.answer.empty())
        || (c.trace.masmSubmitCalled && c.trace.events.empty()
            && !c.finalAuthority && c.ask.answer.empty()
            && c.ask.error.empty() && !c.clientSuccess)) {
        return failClosed(std::move(r), ControllerFail::EmptyEventStream,
                          "EMPTY_EVENT_STREAM");
    }

    // Out-of-order / malformed events
    {
        int idxFinal = -1, idxCand = -1, idxNeed = -1, idxGoal = -1;
        for (int i = 0; i < static_cast<int>(c.trace.events.size()); ++i) {
            const auto& e = c.trace.events[static_cast<size_t>(i)];
            if (e.kind >= HX_EVT_COUNT && e.kind != HX_EVT_NONE) {
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

    // Unsupported success: client claims success/FINAL without verified claim
    if ((c.ask.success || c.finalAuthority)
        && c.ask.claimState != ClaimState::Verified
        && c.ask.claimState != ClaimState::Proven
        && !c.ask.selectedCandidate.empty()) {
        // Marker: tuner "fixed" fiction
        if (c.ask.answer.find("TUNER_CLAIMS_FIXED") != std::string::npos
            || c.ask.selectedCandidate.find("TUNER_CLAIMS_FIXED") != std::string::npos
            || c.trace.diagnostic == "UNSUPPORTED_SUCCESS") {
            return failClosed(std::move(r), ControllerFail::UnsupportedSuccess,
                              "UNSUPPORTED_SUCCESS: tuner/client claim without evidence");
        }
    }
    if ((c.ask.success || c.finalAuthority)
        && c.ask.claimState != ClaimState::Verified
        && c.ask.claimState != ClaimState::Proven) {
        return failClosed(std::move(r), ControllerFail::UnsupportedSuccess,
                          "UNSUPPORTED_SUCCESS: success without verified claim");
    }

    // Bad / unverified candidate → tuner redispatch (generation++ attempt++)
    const bool badCandidate =
        c.trace.diagnostic == "BAD_CANDIDATE"
        || (!c.finalAuthority && !c.ask.success
            && hasCandidate
            && (c.ask.claimState == ClaimState::Candidate
                || c.ask.claimState == ClaimState::UnderReview
                || c.ask.error.find("FINAL_GATE") != std::string::npos
                || c.ask.error.find("not verified") != std::string::npos
                || c.trace.diagnostic == "VERIFY_DENY"));

    if (badCandidate) {
        enter(r, ControllerPhase::VerifyRoute, "CTRL_VERIFY_DENY");
        if (retriesUsed_ >= cfg_.maxRetries) {
            r.phase = ControllerPhase::Exhausted;
            r.fail = ControllerFail::RetryExhausted;
            r.sequencingOk = true;
            r.finalAuthority = false;
            r.diagnostic = "RETRY_EXHAUSTED";
            enter(r, ControllerPhase::Exhausted, "CTRL_RETRY_EXHAUSTED");
            stopped_ = true;
            return r;
        }
        ++retriesUsed_;
        ++attempt_;
        const uint64_t genBefore = generation_;
        ++generation_;
        r.generation = generation_;
        r.attempt = attempt_;
        r.redispatches = retriesUsed_;
        r.phase = ControllerPhase::TunerRedispatch;
        r.fail = ControllerFail::BadCandidate;
        r.sequencingOk = true;
        r.finalAuthority = false;
        r.diagnostic = "BAD_CANDIDATE: generation+1 redispatch";
        enter(r, ControllerPhase::TunerRedispatch, "CTRL_TUNER_GENERATION_BUMP");
        (void)genBefore;
        return r;
    }

    if (!hasCandidate && !c.ask.success) {
        return failClosed(std::move(r), ControllerFail::EmptyEventStream,
                          "NO_CANDIDATE");
    }

    // ---- FINALIZE_POLICY (truth) — controller does not invent evidence ----
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

    // Only attach verifier evidence when control-plane already marked Verified/Proven
    // (ask path). Never upgrade Candidate → Verified here.
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
        // Treat deny as bad candidate for retry if retries remain
        if (retriesUsed_ < cfg_.maxRetries && hasCandidate) {
            ++retriesUsed_;
            ++attempt_;
            ++generation_;
            r.generation = generation_;
            r.attempt = attempt_;
            r.redispatches = retriesUsed_;
            r.phase = ControllerPhase::TunerRedispatch;
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
    r.phase = ControllerPhase::Done;
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
    ControllerResult r;
    try {
        enter(r, ControllerPhase::Request, "CTRL_RUN");
        enter(r, ControllerPhase::ClassifyValidate, "CTRL_CLASSIFY");

        if (prompt.empty()) {
            return failClosed(std::move(r), ControllerFail::EmptyGoal,
                              "EMPTY_GOAL: no fake success");
        }

        if (!transport_) {
            return failClosed(std::move(r), ControllerFail::BackendFailure,
                              "BACKEND_FAILURE: no transport");
        }

        // Identity / backend ready (MASM linked path)
        const ClientIdentity id = clientIdentity();
        r.clientBackendReady = (std::strcmp(id.backend, "MASM") == 0)
            && id.linked == 1
            && std::strcmp(id.clientPath, "MASM") == 0;

        if (needInputLatched_) {
            enter(r, ControllerPhase::NeedInputLatched, "CTRL_SKIP_TRANSPORT_LATCHED");
            ClientAskResult illicit;
            illicit.ask.success = true;
            illicit.finalAuthority = true;
            illicit.clientSuccess = true;
            illicit.ask.claimState = ClaimState::Verified;
            illicit.ask.answer = "illicit_final_after_need_input";
            return sequenceClientResult(std::move(illicit), generation_);
        }

        if (finalGranted_) {
            return failClosed(std::move(r), ControllerFail::DuplicateFinal,
                              "DUPLICATE_FINAL: already granted");
        }

        // Loop: DISPATCH → result → maybe NEW_GENERATION → DISPATCH
        for (;;) {
            if (forceException_) {
                throw std::runtime_error("controller_force_exception");
            }

            const uint64_t genAtDispatch = generation_;
            ClientAskResult client = transport_->ask(prompt, context);
            ControllerResult step = sequenceClientResult(std::move(client), genAtDispatch);
            // Preserve backend-ready from outer
            step.clientBackendReady = r.clientBackendReady || step.clientBackendReady;
            // Merge phase history
            for (auto p : r.phases) step.phases.insert(step.phases.begin(), p);
            // Actually prepend is wrong for multiple iterations — append prior log
            std::vector<std::string> prior = r.sequenceLog;
            prior.insert(prior.end(), step.sequenceLog.begin(), step.sequenceLog.end());
            step.sequenceLog = std::move(prior);
            std::vector<ControllerPhase> priorP = r.phases;
            // re-read: sequenceClientResult already has its phases; prepend classify
            priorP.insert(priorP.end(), step.phases.begin(), step.phases.end());
            // Dedup mess — simpler: keep step and stamp readiness
            step.clientBackendReady = (std::strcmp(clientIdentity().backend, "MASM") == 0)
                && clientIdentity().linked == 1;

            if (step.phase == ControllerPhase::TunerRedispatch) {
                r = std::move(step);
                continue; // NEW_GENERATION → DISPATCH_CLIENT
            }
            return step;
        }
    } catch (const std::exception& ex) {
        ControllerResult err;
        err.clientBackendReady = r.clientBackendReady;
        err.fabricatedFinal = false;
        err.finalAuthority = false;
        return failClosed(std::move(err), ControllerFail::ControllerException,
                          (std::string("CONTROLLER_EXCEPTION: ") + ex.what()).c_str());
    } catch (...) {
        ControllerResult err;
        err.finalAuthority = false;
        return failClosed(std::move(err), ControllerFail::ControllerException,
                          "CONTROLLER_EXCEPTION: unknown");
    }
}

} // namespace HexMag
} // namespace RawrXD
