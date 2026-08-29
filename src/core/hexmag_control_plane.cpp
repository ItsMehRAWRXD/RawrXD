// ============================================================================
// hexmag_control_plane.cpp — Policy gate + MASM HexMag swarm integration
// ============================================================================
#include "core/hexmag_control_plane.hpp"
#include "core/hexmag_oracle_binder.hpp"
#include "agentic/HexMagAction.hpp"

#include <cstring>
#include <mutex>
#include <sstream>
#include <vector>

namespace RawrXD {
namespace HexMag {
namespace {

std::mutex g_mu;
std::vector<Attempt> g_attempts;
bool g_inited = false;

uint64_t fnv1a64(const std::string& s) {
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

#ifdef RAWR_HAS_MASM
extern "C" {
    uint32_t HexMag_IsInitialized();
    uint32_t HexMag_Feedback(uint32_t fail_kind_or_zero);
}
#endif

struct DrainOutcome {
    std::string answer;
    bool needInput = false;
    bool emittedFinal = false;
    bool satisfiedEvt = false;
};

DrainOutcome drainEvents(std::string* eventLog) {
    DrainOutcome o;
    std::string lastCandidate;
#ifdef RAWR_HAS_MASM
    HxEvent ev{};
    while (HexMag_PollEvent(&ev)) {
        if (eventLog) {
            *eventLog += HxEventKindName(ev.kind);
            *eventLog += ": ";
            *eventLog += ev.payload;
            *eventLog += "\n";
        }
        if (ev.kind == HX_EVT_NEED_INPUT) {
            o.needInput = true;
            // Latch ASK_USER — later FINAL must not overwrite (constitution D2)
            o.answer = std::string("INSUFFICIENT_INFORMATION: ") + ev.payload;
        }
        if (ev.kind == HX_EVT_ANSWER_FINAL) {
            o.emittedFinal = true;
            if (!o.needInput) {
                o.answer = ev.payload;
                o.satisfiedEvt = true;
            }
        }
        if (ev.kind == HX_EVT_GOAL_SATISFIED) {
            o.satisfiedEvt = true;
            if (!o.needInput && o.answer.empty()) o.answer = ev.payload;
            else if (!o.needInput) o.answer = ev.payload;
        }
        if (ev.kind == HX_EVT_ANSWER_CANDIDATE || ev.kind == HX_EVT_ANSWER) {
            lastCandidate = ev.payload;
        }
        ev = {};
    }
#else
    (void)eventLog;
#endif
    if (o.answer.empty() && !o.needInput) {
        if (o.satisfiedEvt && !lastCandidate.empty()) o.answer = lastCandidate;
        else o.answer = lastCandidate;
    }
    return o;
}

uint64_t installMission(const std::string& prompt, const std::string& context) {
    auto& reg = globalDirectives();
    Directive mission;
    mission.authority = Authority::Mission;
    mission.source = "Operator";
    mission.instruction = prompt;
    if (!context.empty()) {
        mission.instruction += "\n[CONTEXT]\n";
        mission.instruction += context.substr(0, 2000);
    }
    mission.parentDirective = 10; // constitution
    mission.immutable = false;
    mission.verified = false;
    if (!reg.permits(mission)) {
        return 0;
    }
    return reg.add(std::move(mission));
}

Claim claimFromSwarmAnswer(const std::string& ans, bool satisfied) {
    Claim c;
    c.text = ans;
    if (ans.find("INSUFFICIENT_INFORMATION") != std::string::npos) {
        c.state = ClaimState::MissingInput;
        return c;
    }
    // MASM verify path emits #OK / goal.satisfied — treat as verifier evidence
    Evidence e;
    e.kind = "hexmag_verify";
    e.tool = "masm_control_plane";
    e.payload = ans;
    e.passesVerifier = satisfied
        || ans.find("#OK") != std::string::npos
        || ans.find("goal.satisfied") != std::string::npos
        || ans.find("llm.answer.final") != std::string::npos;
    c.evidence.push_back(e);
    if (e.passesVerifier) {
        c.state = ClaimState::Verified;
    } else {
        c.state = ClaimState::Candidate;
        c.confidence = 0.0; // irrelevant
    }
    return c;
}

} // namespace

bool ensureControlPlane() {
    std::lock_guard<std::mutex> lock(g_mu);
    globalDirectives().seedCore();
#ifdef RAWR_HAS_MASM
    if (g_inited && HexMag_IsInitialized()) return true;
    const uint64_t rc = HexMag_Init();
    if (rc != HX_OK && rc != HX_ERR_ALREADY_INIT) return false;
    g_inited = true;
    return true;
#else
    g_inited = false;
    return false;
#endif
}

bool tryLaunchService() {
    return ensureControlPlane();
}

bool healthCheck() {
#ifdef RAWR_HAS_MASM
    if (!ensureControlPlane()) return false;
    return HexMag_IsInitialized() != 0;
#else
    return false;
#endif
}

std::string resolveBaseUrl() {
#ifdef RAWR_HAS_MASM
    return "masm://hexmag-control-plane";
#else
    return "http://localhost:8765"; // Python reference only when MASM absent
#endif
}

bool noteAttempt(const Attempt& attempt) {
    std::lock_guard<std::mutex> lock(g_mu);
    if (!g_attempts.empty()) {
        if (rejectRepeatWithoutGain(g_attempts.back(), attempt)) {
            return false; // REJECT_REPEAT
        }
    }
    g_attempts.push_back(attempt);
    // Cap memory
    if (g_attempts.size() > 64) g_attempts.erase(g_attempts.begin());
    return true;
}

AskResult askWithAutoStart(const std::string& prompt, const std::string& context) {
    AskResult out;
    if (prompt.empty()) {
        out.error = "empty prompt";
        return out;
    }

    if (!ensureControlPlane()) {
        out.error = "HexMag MASM control plane unavailable (rebuild with RAWR_HAS_MASM / ml64)";
        return out;
    }

#ifdef RAWR_HAS_MASM
    // Apply current swarm width (Cursor multi-model style) before goal run
    (void)HexMag_GetParallelAgents();
#endif

    const uint64_t missionId = installMission(prompt, context);
    if (missionId == 0) {
        out.error = "mission rejected by constitution/core gate";
        out.claimState = ClaimState::FinalRejected;
        return out;
    }
    out.provenance = globalDirectives().explain(missionId);

#ifdef RAWR_HAS_MASM
    std::string goal = prompt;
    if (!context.empty()) {
        goal += "\n";
        goal += context.substr(0, 800);
    }

    // Strategy hash for repeat tuner / constitution §7
    Attempt att;
    att.problemStateHash = fnv1a64(goal);
    att.strategyHash = fnv1a64(std::to_string(HexMag_Tuner_Strategy()) + "|ask");
    att.evidenceHash = fnv1a64(context);
    att.role = HexMagRole::Generalist;
    if (!noteAttempt(att)) {
        out.error = "REJECT_REPEAT: same strategy without new evidence (constitution §7)";
        out.claimState = ClaimState::FinalRejected;
        return out;
    }

    const uint64_t gid = HexMag_SubmitGoal(goal.c_str(), static_cast<uint32_t>(goal.size()));
    if (gid == 0) {
        out.error = "SubmitGoal failed";
        return out;
    }
    out.goalId = gid;

    const uint64_t rc = HexMag_RunToSatisfied(64);
    std::string log;
    DrainOutcome drained = drainEvents(&log);
    std::string ans = drained.answer;

    out.agentsSpawned = HexMag_AgentsSpawned();
    out.tunerAttempt = HexMag_TunerAttempt();
    out.goalSatisfied = (rc == HX_OK) && !drained.needInput && drained.satisfiedEvt;
    out.needInput = drained.needInput;
    out.emittedFinal = drained.emittedFinal;
    out.eventLog = std::move(log);

    // NEED_INPUT latch: never invoke Oracle/Deep2; never resurrect FINAL
    if (drained.needInput) {
        out.success = false;
        out.error = ans.empty() ? "INSUFFICIENT_INFORMATION" : ans;
        out.answer = out.error;
        out.claimState = ClaimState::MissingInput;
        out.needInput = true;
        out.goalSatisfied = false;
        out.emittedFinal = drained.emittedFinal;
        out.oracleInvoked = false;
        out.deep2Invoked = false;
        out.candidateSource = "none";
        return out;
    }

    // Optional Oracle/Deep2 binder — candidates only; FINAL via existing gates
    {
        auto gens = oracleBinderGenerators();
        if (!gens.empty()) {
            BinderRequest br;
            br.prompt = prompt;
            br.context = context;
            br.needInputLatched = false; // already returned above if latched
            auto brOut = runOracleBinder(br, gens, oracleBinderVerifier());
            out.oracleInvoked = brOut.oracleInvoked;
            out.deep2Invoked = brOut.deep2Invoked;
            out.candidateSource = candidateSourceName(brOut.selected.source);
            out.selectedCandidate = brOut.selected.text;
            out.provenance += "oracle_binder: " + brOut.detail + "\n";
            if (!brOut.selectionEvidence.empty())
                out.provenance += brOut.selectionEvidence + "\n";

            if (brOut.success) {
                out.success = true;
                out.answer = brOut.claim.text;
                out.claimState = brOut.claim.state;
                out.goalSatisfied = true;
                // Binder does not emit MASM FINAL; gate decision is C++ only
                out.emittedFinal = false;
                out.provenance += "FINAL allowed by existing gates (oracle candidate + verifier)\n";
                return out;
            }

            // Binder active ⇒ MASM stub FINAL cannot override candidate rejection
            out.success = false;
            out.goalSatisfied = false;
            out.emittedFinal = false;
            out.error = brOut.error.empty()
                ? "FINAL_GATE: oracle candidate not verified"
                : brOut.error;
            out.answer = brOut.selected.text.empty() ? ans : brOut.selected.text;
            out.claimState = brOut.claim.state;
            return out;
        }
    }

    out.candidateSource = "masm";
    out.selectedCandidate = ans;

    Claim claim = claimFromSwarmAnswer(ans, out.goalSatisfied);
    claim.directiveId = missionId;
    claim.generationId = HexMag_Tuner_GenerationId();

    // Map ClaimState → HexMagAction finalize class (unsupported_claim_emission=FORBIDDEN)
    ClaimFinalizeClass fin = ClaimFinalizeClass::Unverified;
    if (claim.state == ClaimState::Proven) fin = ClaimFinalizeClass::Proven;
    else if (claim.state == ClaimState::Verified || claim.verified())
        fin = ClaimFinalizeClass::Verified;
    else if (claim.state == ClaimState::MissingInput || drained.needInput)
        fin = ClaimFinalizeClass::MissingInput;
    else if (claim.state == ClaimState::Contradicted) fin = ClaimFinalizeClass::Contradicted;
    else if (claim.state == ClaimState::FinalRejected) fin = ClaimFinalizeClass::Unknown;

    // FINAL GATE — confidence irrelevant; HexMagAction + allowFinal both required
    if (drained.needInput || !allowFinal(claim) || !isAllowedFinalClaim(fin)) {
        if (drained.needInput || claim.state == ClaimState::MissingInput
            || fin == ClaimFinalizeClass::MissingInput) {
            out.success = false;
            out.error = ans.empty() ? "INSUFFICIENT_INFORMATION" : ans;
            out.answer = out.error;
            out.claimState = ClaimState::MissingInput;
            out.needInput = true;
            // Refuse to treat any FINAL emission as success after ASK_USER
            out.emittedFinal = drained.emittedFinal;
            return out;
        }
        // Candidate without verifier evidence — do not fake success
        out.success = false;
        out.error = "FINAL_GATE: claim not verified (unsupported_claim_emission=FORBIDDEN)";
        out.answer = ans;
        out.claimState = ClaimState::Candidate;
        // Record failure for tuner
        Attempt fail = att;
        fail.failure = FailureClass::UnsupportedClaim;
        fail.strategyHash = fnv1a64(ans);
        noteAttempt(fail);
        return out;
    }

    out.success = true;
    out.answer = ans.empty() ? std::string("goal.satisfied") : ans;
    out.claimState = claim.state;
    out.provenance += "FINAL allowed by D1 (evidence verifier)\n";
    return out;
#else
    (void)missionId;
    out.error = "RAWR_HAS_MASM not defined";
    return out;
#endif
}

StreamResult streamAgentWithAutoStart(
    const std::string& prompt,
    std::function<void(const std::string&)> onToken,
    float /*timeoutSeconds*/)
{
    StreamResult out;
    auto ask = askWithAutoStart(prompt, {});
    if (onToken) {
        if (!ask.provenance.empty()) onToken(ask.provenance);
        if (!ask.answer.empty()) onToken(ask.answer);
        else if (!ask.error.empty()) onToken(ask.error);
    }
    out.success = ask.success;
    out.error = ask.error;
    out.goalSatisfied = ask.goalSatisfied;
    out.finalAnswer = ask.answer;
    return out;
}

FeedbackResult submitFeedback(bool correct, uint32_t failKindMask) {
    FeedbackResult r;
    if (!ensureControlPlane()) {
        r.detail = "control plane down";
        r.exhausted = true;
        return r;
    }
#ifdef RAWR_HAS_MASM
    const uint32_t code = HexMag_Feedback(correct ? 0u : failKindMask);
    if (code == 2) {
        r.finalized = true;
        r.detail = "finalized_by_feedback";
    } else if (code == 1) {
        r.scheduledRetry = true;
        r.detail = "tuner_retry_scheduled";
        HexMag_RunToSatisfied(32);
    } else {
        r.exhausted = true;
        r.detail = "INSUFFICIENT_INFORMATION";
    }
#else
    (void)failKindMask;
    r.exhausted = true;
    r.detail = "no MASM";
#endif
    return r;
}

uint32_t setSwarmAgentCount(uint32_t count) {
    if (!ensureControlPlane()) {
        if (count < 1) count = 1;
        if (count > 8) count = 8;
        return count;
    }
#ifdef RAWR_HAS_MASM
    return HexMag_SetParallelAgents(count);
#else
    if (count < 1) count = 1;
    if (count > 8) count = 8;
    return count;
#endif
}

uint32_t swarmAgentCount() {
#ifdef RAWR_HAS_MASM
    if (!ensureControlPlane()) return 1;
    return HexMag_GetParallelAgents();
#else
    return 1;
#endif
}

std::string defaultResponseGenAsk(const std::string& question) {
    auto r = askWithAutoStart(question, {});
    if (r.success) return r.answer;
    return std::string("[HexMag] ") + (r.error.empty() ? "failed" : r.error);
}

} // namespace HexMag
} // namespace RawrXD
