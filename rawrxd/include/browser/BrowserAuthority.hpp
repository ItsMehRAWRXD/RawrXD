// ============================================================================
// BrowserAuthority.hpp
//
// RAWRXD_BROWSER_AUTHORITY_001 / _ACTION_001 / _RECEIPT_001
//
// One implementation of browser actions and their evidence. The standalone
// probe and the shipping CLI are BOTH callers of this file. That is
// deliberate, and it is the direct result of a defect already found and fixed
// elsewhere in this repository: the BowRain receipt had one parser in the
// product and a second, different parser in the probe, so the product and the
// verifier disagreed about the SAME artifact. Two implementations of a proof
// system is two verdicts.
//
//   probe ──┐
//           ├──► BrowserAuthority ──► BrowserSession ──► CdpTransport ──► Edge
//   CLI  ──┘
//
// ---------------------------------------------------------------------------
// THE PROOF DISCIPLINE
// ---------------------------------------------------------------------------
//   BROWSER_OPENED       != PASS
//   PAGE_LOADED          != PASS
//   CLICK_RETURNED_OK    != PASS
//   MODEL_SAID_COMPLETE  != PASS
//
// A click passes when a trusted event reached the intended target AND the page
// state measurably changed. Not when CDP returned a result object.
//
// ---------------------------------------------------------------------------
// TARGET REVALIDATION IS STRUCTURAL
// ---------------------------------------------------------------------------
// The standalone probe failed its click for several iterations because the
// geometry was sampled, the DOM was mutated, and the stale coordinates were
// then dispatched. The browser accepted the command and delivered trusted
// events -- to <html>, not to the button.
//
// That was fixed in the probe by remembering to re-measure. A convention is not
// a guarantee. Here, `dispatchClick()` RE-RESOLVES the target inside the same
// call that dispatches, and there is no public path that dispatches against
// caller-supplied coordinates. The law is therefore a property of the API:
//
//   TARGET_DISCOVERY_TIME != ACTION_DISPATCH_TIME
//   ACTION_REQUIRES_TARGET_REVALIDATION = 1
// ============================================================================

#ifndef RAWRXD_BROWSER_BROWSER_AUTHORITY_HPP
#define RAWRXD_BROWSER_BROWSER_AUTHORITY_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "browser/BrowserSession.hpp"
#include "browser/CdpTransport.hpp"

namespace rawrxd::browser {

// FNV-1a over an observed state string.
//
// Exposed in the header so the receipt writer and any external driver hash
// identically. Two hashers would make "the state changed" mean two different
// things depending on who asked, which is the same divergence class the shared
// parser fix removed.
inline std::uint64_t hashStatePublic(const std::string& s) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

// ---------------------------------------------------------------------------
// One action, and the evidence that it happened.
//
// Every field is an OBSERVATION recorded by the authority itself. There is no
// setter for `verdict`, and `verdict` is not stored -- it is computed by
// deriveActionVerdict() from the observations below. A caller cannot assert that
// a click worked; it can only perform one and let the evidence fall out.
// ---------------------------------------------------------------------------
struct ActionEvidence {
    std::uint64_t sequence = 0;

    std::string action;              // CLICK / TYPE / NAVIGATE / FOCUS
    std::string target;              // selector the caller asked for

    // Target identity at the two moments that matter. Their EQUALITY is the
    // revalidation proof; their INEQUALITY is how a stale-target regression
    // becomes visible instead of silent.
    std::string targetIdAtDiscovery = "<none>";
    std::string targetIdAtDispatch  = "<none>";
    bool targetRevalidated = false;
    bool targetFound       = false;

    // Protocol layer: did the command reach the browser, and did the browser
    // answer? Both are necessary and neither is sufficient.
    bool commandSent            = false;
    bool protocolResponseRecvd  = false;
    std::string protocolError;         // non-empty => the browser REFUSED

    // Input layer: did a TRUSTED event actually reach the intended element?
    // Synthetic events dispatched from page script are excluded on purpose: a
    // page that clicks itself proves nothing about the runtime acting on it.
    bool trustedEventObserved = false;
    std::string eventsObserved;        // "mousedown:trusted,click:trusted"

    // Effect layer: did the page actually change?
    std::string stateBefore = "<none>";
    std::string stateAfter  = "<none>";
    bool stateChanged = false;
    std::string effectExpression;       // what was measured

    // Negative control. Recorded per action so "nothing happened" and "it
    // happened" are distinguishable without re-running.
    bool expectedChangeDeclared = false;

    // Which evidence THIS action class can actually produce.
    //
    // A single global rule -- "every action needs a trusted input event" -- was
    // the first version, and it was wrong in both directions: NAVIGATE produces
    // no input events at all, so navigation could never PASS, while a rule that
    // dropped the trusted-event requirement would let a click pass on protocol
    // success alone. Requirements are declared per action so each class is held
    // to the evidence it can genuinely produce, and no higher.
    bool requiresTrustedEvent = false;
    bool requiresTarget        = false;
};

enum class ActionVerdict { Fail, Unproven, Pass };

inline const char* actionVerdictName(ActionVerdict v) {
    switch (v) {
        case ActionVerdict::Fail:     return "FAIL";
        case ActionVerdict::Unproven: return "UNPROVEN";
        case ActionVerdict::Pass:     return "PASS";
    }
    return "?";
}

// DERIVED. Never stored, never settable.
//
// The ordering is deliberate and is the whole point:
//   a refused command is FAIL (the browser said no)
//   a command with no observed effect is UNPROVEN (it may or may not work)
//   only a trusted event AND a measured state change is PASS
static inline ActionVerdict deriveActionVerdict(const ActionEvidence& e) {
    if (!e.protocolError.empty()) return ActionVerdict::Fail;
    if (!e.commandSent)            return ActionVerdict::Fail;
    if (e.requiresTarget && !e.targetFound)      return ActionVerdict::Unproven;
    if (!e.protocolResponseRecvd)  return ActionVerdict::Unproven;
    if (e.requiresTrustedEvent && !e.trustedEventObserved)
                                           return ActionVerdict::Unproven;
    // The effect is the proof. A protocol success with no measured change is
    // UNPROVEN, never PASS.
    if (!e.stateChanged)           return ActionVerdict::Unproven;
    return ActionVerdict::Pass;
}

// ---------------------------------------------------------------------------
// The authority.
//
// Holds the session and the page connection, performs semantic actions, and
// keeps the action log. One instance per browser session.
// ---------------------------------------------------------------------------
class BrowserAuthority {
public:
    BrowserAuthority() = default;
    ~BrowserAuthority();
    BrowserAuthority(const BrowserAuthority&) = delete;
    BrowserAuthority& operator=(const BrowserAuthority&) = delete;

    // Launch conditions are the same four the session already measures.
    bool launch(const std::string& browserPath, const std::string& profileDir,
                bool headless, std::string& err);

    // Opens a page target and attaches a page-scoped connection to it.
    bool openPage(const std::string& url, std::string& err);

    bool ready() const noexcept { return session_.ready() && page_.connected(); }

    // ---- semantic actions ---------------------------------------------
    // Each returns its sequence number in `seqOut` (0 on failure).

    // Navigates and waits until `readyExpression` yields `readyValue`.
    // The wait is bounded; on expiry the action is recorded UNPROVEN with the
    // last observed value, because "it took too long" and "it showed the wrong
    // thing" are different failures.
    std::uint64_t navigate(const std::string& url,
                           const std::string& readyExpression,
                           const std::string& readyValue,
                           int timeoutMs, std::string& err);

    // Clicks `selector`, then measures `effectExpression` before and after.
    // Target resolution and revalidation happen INSIDE this call.
    std::uint64_t click(const std::string& selector,
                        const std::string& effectExpression,
                        const std::string& expectedValue,
                        int timeoutMs, std::string& err);

    // Focuses `selector` then types `text` into it, measuring `effectExpression`.
    std::uint64_t type(const std::string& selector, const std::string& text,
                       const std::string& effectExpression,
                       int timeoutMs, std::string& err);

    // ---- observation ---------------------------------------------------
    bool evaluate(const std::string& expression, std::string& value,
                  std::string& err);
    std::string screenshotApproxBytes(std::string& err);
    // Re-queries the browser and records the count as an OBSERVATION.
    //
    // Deliberately not called from renderReceipt(). A receipt must report the
    // state observed while the actions ran, not a value that can shift while the
    // receipt is being written.
    std::uint32_t observeTargetCount();
    std::uint32_t targetCountObserved() const noexcept {
        return targetsObserved_;
    }

    // ---- evidence ------------------------------------------------------
    const std::vector<ActionEvidence>& actions() const noexcept { return log_; }
    std::size_t actionsPassed() const;
    std::size_t actionsUnproven() const;
    std::size_t actionsFailed() const;
    ActionVerdict overallVerdict() const;

    // ---- receipt -------------------------------------------------------
    std::string renderReceipt() const;
    bool writeReceipt(const std::string& path) const;

    // Render BEFORE truncating is enforced by construction: the caller gets a
    // string first and decides separately whether to destroy a file. An earlier
    // BowRain version opened the file with trunc and then rendered, so a fault
    // in verification destroyed the artifact it was verifying.
    void close();

    CdpConnection& page() noexcept { return page_; }
    BrowserSession& session() noexcept { return session_; }
    const SessionLaunchEvidence& launchEvidence() const noexcept {
        return session_.evidence();
    }

private:
    BrowserSession session_;
    CdpConnection page_;
    std::vector<ActionEvidence> log_;
    std::uint64_t nextSeq_ = 1;
    std::uint32_t targetsObserved_ = 0;

    // Installs a listener that records trusted input events reaching `selector`.
    // Read back by readEventTrace().
    bool installEventTrace(const std::string& selector, std::string& err);
    std::string readEventTrace(std::string& err);

    // Resolves a selector to a live element AND its centre, and reports the
    // element the browser says is at that centre. Two ids are produced so a
    // caller can prove they agree.
    bool resolveTarget(const std::string& selector,
                       double& cx, double& cy,
                       std::string& idOut, std::string& err);

    bool waitForValue(const std::string& expression,
                      const std::string& want, int timeoutMs,
                      std::string& lastSeen);

    void finish(ActionEvidence& e);
};

} // namespace rawrxd::browser

#endif // RAWRXD_BROWSER_BROWSER_AUTHORITY_HPP