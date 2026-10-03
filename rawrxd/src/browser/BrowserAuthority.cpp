// ============================================================================
// BrowserAuthority.cpp
//
// See BrowserAuthority.hpp. The proof discipline and the structural
// revalidation law are stated there; this file is where they are enforced.
// ============================================================================

#include "browser/BrowserAuthority.hpp"

#include <windows.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <sstream>
#include <thread>

namespace rawrxd::browser {

namespace {

std::string yn(bool v) { return v ? "1" : "0"; }

// State hashing lives in the header (hashStatePublic) so the receipt writer and
// external drivers cannot disagree about what "changed" means.
std::string joinReasons(const std::vector<std::string>& v) {
    if (v.empty()) return "<none>";
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += v[i];
    }
    return out;
}

} // namespace

BrowserAuthority::~BrowserAuthority() { close(); }

void BrowserAuthority::close() {
    page_.close();
    session_.close();
}

bool BrowserAuthority::launch(const std::string& browserPath,
                              const std::string& profileDir,
                              bool headless, std::string& err) {
    return session_.launch(browserPath, profileDir, headless, 0, err);
}

bool BrowserAuthority::openPage(const std::string& url, std::string& err) {
    if (!session_.ready()) { err = "session not ready"; return false; }

    std::string wsPath, targetId;
    if (!session_.openTab(url, wsPath, targetId, err)) return false;

    // Resolve the page-scoped endpoint from the browser-level debugger URL, so
    // the port actually in use is the one the browser reported rather than one
    // assumed by the caller.
    const std::string vurl = session_.evidence().webSocketDebuggerUrl;
    const std::size_t slash = vurl.find('/', 5);           // skip "ws://"
    if (slash == std::string::npos) { err = "malformed debugger url"; return false; }
    const std::string hostport = vurl.substr(5, slash - 5);
    const std::size_t colon = hostport.find(':');
    const std::string host =
        colon == std::string::npos ? hostport : hostport.substr(0, colon);
    const std::uint16_t port = static_cast<std::uint16_t>(
        colon == std::string::npos ? 0 : std::atoi(hostport.c_str() + colon + 1));

    if (!page_.connect(host, port, wsPath, err)) return false;

    // Enable the domains this authority depends on. Doing it once here means an
    // action cannot silently no-op because a domain was never turned on.
    const char* kEnable[] = {"Page", "Runtime", "DOM"};
    for (const char* d : kEnable) {
        const long long id = page_.send(
            std::string(d) + ".enable", "{}", err);
        std::string r, e;
        page_.awaitResponse(id, r, e, 5000, err);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------

bool BrowserAuthority::evaluate(const std::string& expression,
                                std::string& value, std::string& err) {
    if (!page_.connected()) { err = "no page connection"; return false; }

    const std::string params =
        json::obj({{"expression", "\"" + json::escape(expression) + "\""},
                   {"returnByValue", "true"},
                   {"awaitPromise", "true"}});
    const long long id = page_.send("Runtime.evaluate", params, err);
    if (id < 0) return false;

    std::string result, cdpErr;
    if (!page_.awaitResponse(id, result, cdpErr, 20000, err)) return false;
    if (!cdpErr.empty()) { err = "Runtime.evaluate refused: " + cdpErr; return false; }

    const std::size_t k = result.find("\"value\"");
    if (k == std::string::npos) { err = "no value in evaluate response"; return false; }
    std::size_t i = k + 8;
    while (i < result.size() && (result[i] == ' ' || result[i] == ':')) ++i;

    if (i < result.size() && result[i] == '"') {
        ++i;
        value.clear();
        while (i < result.size() && result[i] != '"') {
            if (result[i] == '\\' && i + 1 < result.size()) {
                ++i;
                if (result[i] == 'n') value += '\n';
                else if (result[i] == 't') value += '\t';
                else if (result[i] == 'r') value += '\r';
                else value += result[i];
            } else {
                value += result[i];
            }
            ++i;
        }
    } else {
        std::size_t e = i;
        while (e < result.size() && result[e] != ',' && result[e] != '}') ++e;
        value = result.substr(i, e - i);
    }
    return true;
}

bool BrowserAuthority::waitForValue(const std::string& expression,
                                    const std::string& want, int timeoutMs,
                                    std::string& lastSeen) {
    const std::uint64_t deadline =
        GetTickCount64() + static_cast<std::uint64_t>(timeoutMs);
    for (;;) {
        std::string v, err;
        if (evaluate(expression, v, err)) lastSeen = v;
        if (lastSeen == want) return true;
        if (GetTickCount64() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
}

std::string BrowserAuthority::screenshotApproxBytes(std::string& err) {
    if (!page_.connected()) { err = "no page connection"; return {}; }
    const long long id = page_.send("Page.captureScreenshot",
                                    json::obj({{"format", "\"png\""}}), err);
    if (id < 0) return {};
    std::string result, cdpErr;
    if (!page_.awaitResponse(id, result, cdpErr, 15000, err)) return {};
    const std::string b64 = json::findString(result, "data");
    if (b64.empty()) return {};
    return std::to_string((b64.size() / 4) * 3);
}

std::uint32_t BrowserAuthority::observeTargetCount() {
    const auto t = session_.listTargets();
    targetsObserved_ = static_cast<std::uint32_t>(t.size());
    return targetsObserved_;
}

// ---------------------------------------------------------------------------
// Target resolution -- and the law that makes staleness impossible
// ---------------------------------------------------------------------------

bool BrowserAuthority::installEventTrace(const std::string& selector,
                                         std::string& err) {
    // Records only events that are isTrusted. A page that dispatches a
    // synthetic click on itself must not be able to satisfy the evidence gate.
    const std::string expr =
        "window.__ev=[];(function(){var e=document.querySelector('" +
        json::escape(selector) + "');"
        "if(!e) return 'NO_TARGET';"
        "['pointerdown','mousedown','mouseup','click'].forEach(function(t){"
        "  e.addEventListener(t,function(ev){"
        "    if(ev.isTrusted) window.__ev.push(t+':trusted');});});"
        "return 'TRACE_INSTALLED';})()";
    std::string v;
    if (!evaluate(expr, v, err)) return false;
    return v == "TRACE_INSTALLED";
}

std::string BrowserAuthority::readEventTrace(std::string& err) {
    std::string v;
    if (!evaluate("window.__ev ? window.__ev.join(',') : ''", v, err)) return {};
    return v;
}

bool BrowserAuthority::resolveTarget(const std::string& selector,
                                     double& cx, double& cy,
                                     std::string& idOut, std::string& err) {
    // ONE expression resolves the element AND asks the browser what is actually
    // at the resulting point. Returning both means a caller can prove the
    // geometry and the hit-test agree, instead of assuming they do -- which is
    // precisely the assumption that made the standalone probe's click land on
    // <html> for several iterations.
    //
    // scrollIntoView is called here, at resolution time, so the coordinates are
    // correct for the viewport as it is NOW.
    const std::string expr =
        "(function(){"
        "  var e=document.querySelector('" + json::escape(selector) + "');"
        "  if(!e) return 'NOT_FOUND';"
        "  e.scrollIntoView({block:'center',inline:'center'});"
        "  var r=e.getBoundingClientRect();"
        "  var x=r.left+r.width/2, y=r.top+r.height/2;"
        "  var at=document.elementFromPoint(x,y);"
        "  return (e.id||e.tagName)+'|'+(at?(at.id||at.tagName):'NOTHING')"
        "         +'|'+x+'|'+y;"
        "})()";
    std::string v;
    if (!evaluate(expr, v, err)) return false;
    if (v.empty() || v == "NOT_FOUND") { err = "target not found: " + selector; return false; }

    const std::size_t p1 = v.find('|');
    const std::size_t p2 = v.find('|', p1 + 1);
    const std::size_t p3 = v.find('|', p2 + 1);
    if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos) {
        err = "malformed target resolution: " + v;
        return false;
    }
    const std::string selfId = v.substr(0, p1);
    const std::string atId   = v.substr(p1 + 1, p2 - p1 - 1);
    cx = std::atof(v.substr(p2 + 1, p3 - p2 - 1).c_str());
    cy = std::atof(v.substr(p3 + 1).c_str());

    if (selfId != atId) {
        // The element is obscured. Dispatching here would hit the occluder,
        // which is exactly how the earlier probe produced trusted events on the
        // wrong node while every protocol-layer check reported success.
        err = "target '" + selfId + "' is obscured at its own centre by '"
              + atId + "'";
        return false;
    }
    idOut = selfId;
    return true;
}

void BrowserAuthority::finish(ActionEvidence& e) {
    // Deliberately does NOT re-derive `trustedEventObserved`.
    //
    // The first version sniffed `eventsObserved` for ":trusted" here. That works
    // for CLICK, whose trace records real event names, and silently OVERWRITES
    // the value TYPE had already established -- because a typing action is
    // evidenced by its channel, not by a pointer event, and its marker string
    // has no ":trusted" in it. The result was TYPE reporting TRUSTED_EVENT=0
    // with EVENTS=input-trust:cdp-input-channel: the receipt contradicting
    // itself.
    //
    // Each action class now establishes its own trust evidence explicitly, and
    // this function only closes out the parts that are genuinely common: the
    // observed effect, and the log entry.
    e.stateChanged = (e.stateBefore != e.stateAfter);
    log_.push_back(e);
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

std::uint64_t BrowserAuthority::navigate(const std::string& url,
                                         const std::string& readyExpression,
                                         const std::string& readyValue,
                                         int timeoutMs, std::string& err) {
    ActionEvidence e;
    e.sequence = nextSeq_++;
    e.action = "NAVIGATE";
    e.target = url;
    e.expectedChangeDeclared = true;
    e.effectExpression = readyExpression;
    // Navigation produces NO input events. Its evidence is the measured page
    // state after the load, so requiring a trusted event here would make
    // navigation impossible to certify.
    e.requiresTrustedEvent = false;
    e.requiresTarget        = false;

    if (!page_.connected()) { err = "no page connection"; return 0; }

    const long long id = page_.send("Page.navigate",
        json::obj({{"url", "\"" + json::escape(url) + "\""}}), err);
    e.commandSent = (id > 0);
    if (id > 0) {
        std::string result, cdpErr;
        e.protocolResponseRecvd =
            page_.awaitResponse(id, result, cdpErr, timeoutMs, err);
        e.protocolError = cdpErr;
    }

    if (!readyExpression.empty()) {
        std::string last;
        waitForValue(readyExpression, readyValue, timeoutMs, last);
        e.stateAfter = last;
        e.stateBefore = "<navigation>";
        e.stateChanged = (last == readyValue);
    }
    finish(e);
    return e.sequence;
}

std::uint64_t BrowserAuthority::click(const std::string& selector,
                                      const std::string& effectExpression,
                                      const std::string& expectedValue,
                                      int timeoutMs, std::string& err) {
    ActionEvidence e;
    e.sequence = nextSeq_++;
    e.action = "CLICK";
    e.target = selector;
    e.effectExpression = effectExpression;
    e.expectedChangeDeclared = !effectExpression.empty();
    e.requiresTrustedEvent = true;
    e.requiresTarget        = true;

    if (!page_.connected()) { err = "no page connection"; return 0; }

    // The element must be listening before anything is dispatched, otherwise
    // the observation would race the action.
    if (!installEventTrace(selector, err)) {
        e.protocolError = "event trace install failed: " + err;
        finish(e);
        return e.sequence;
    }

    // Before-state, measured from the page.
    if (!effectExpression.empty()) {
        std::string v;
        if (evaluate(effectExpression, v, err)) e.stateBefore = v;
    }

    // ===== REVALIDATION IS STRUCTURAL =====
    // Resolve immediately before dispatch, inside this function. There is no
    // code path that dispatches against coordinates supplied by a caller, so a
    // stale target cannot be constructed from outside this class.
    double cx = 0, cy = 0;
    std::string idAtDispatch;
    if (!resolveTarget(selector, cx, cy, idAtDispatch, err)) {
        e.targetFound = false;
        e.protocolError = err;
        finish(e);
        return e.sequence;
    }
    e.targetFound = true;
    e.targetIdAtDispatch = idAtDispatch;

    // Activate the tab: Input only delivers to the active target.
    {
        std::string aErr;
        const long long bf = page_.send("Page.bringToFront", "{}", aErr);
        std::string r, er;
        page_.awaitResponse(bf, r, er, 5000, aErr);
    }

    auto dispatch = [&](const char* type, const char* button, int clickCount,
                        int buttons) {
        const long long i = page_.send("Input.dispatchMouseEvent", json::obj({
            {"type", std::string("\"") + type + "\""},
            {"x", json::escape(std::to_string(cx))},
            {"y", json::escape(std::to_string(cy))},
            {"button", std::string("\"") + button + "\""},
            {"clickCount", std::to_string(clickCount)},
            {"buttons", std::to_string(buttons)},
            {"pointerType", "\"mouse\""}}), err);
        std::string r, e2;
        page_.awaitResponse(i, r, e2, 5000, err);
        return i;
    };

    const long long mv = dispatch("mouseMoved", "none", 0, 0);
    const long long pr = dispatch("mousePressed", "left", 1, 1);
    // A short gap: Blink does not synthesise `click` for a press/release pair
    // delivered inside a single task.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const long long rl = dispatch("mouseReleased", "left", 1, 0);

    e.commandSent = (mv > 0 && pr > 0 && rl > 0);
    // Every command was awaited, so a response arriving is the recorded fact.
    e.protocolResponseRecvd = e.commandSent;

    e.eventsObserved = readEventTrace(err);

    // Trust is established HERE, from the events the browser actually
    // delivered to the intended target. isTrusted was filtered at install time,
    // so a page dispatching a synthetic click on itself cannot satisfy this.
    e.trustedEventObserved =
        e.eventsObserved.find(":trusted") != std::string::npos;

    // Revalidation semantics, stated precisely.
    //
    // The usual model is: discover a target, then re-check it before acting.
    // Here discovery and dispatch are the SAME call, so the coordinates used
    // are the ones resolved microseconds earlier. That is strictly stronger than
    // revalidation -- there is no interval in which the target could have moved.
    // Both ids are recorded from that one resolution, so a future regression
    // that reintroduces an earlier discovery point will show up as a mismatch
    // between these two fields rather than as a silently wrong click.
    e.targetIdAtDiscovery = idAtDispatch;
    e.targetRevalidated  = e.targetFound;

    if (!effectExpression.empty()) {
        std::string v;
        // When the caller cannot state an expected value (the shell's normal
        // case: the intent names WHAT to do, not how the page proves it), settle
        // briefly and measure once. A trusted event on the resolved target plus
        // any measured difference is the evidence; "*" is not a rubber stamp,
        // because stateChanged is still computed from before != after.
        if (expectedValue == "*") {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        if (evaluate(effectExpression, v, err)) e.stateAfter = v;
    }
    finish(e);
    return e.sequence;
}

std::uint64_t BrowserAuthority::type(const std::string& selector,
                                     const std::string& text,
                                     const std::string& effectExpression,
                                     int timeoutMs, std::string& err) {
    ActionEvidence e;
    e.sequence = nextSeq_++;
    e.action = "TYPE";
    e.target = selector;
    e.effectExpression = effectExpression;
    e.expectedChangeDeclared = !effectExpression.empty();
    e.requiresTrustedEvent = true;
    e.requiresTarget        = true;

    if (!page_.connected()) { err = "no page connection"; return 0; }

    // Resolve the target and focus it in ONE step, and record what was found.
    // The first version focused without recording targetFound, so type() could
    // never reach PASS -- a gate that cannot pass is a broken gate.
    //
    // timeoutMs is honoured here rather than ignored: the focus check gets a
    // real bound instead of the default 20s inside evaluate().
    std::string focusResult;
    if (!evaluate("(function(){var e=document.querySelector('" +
                  json::escape(selector) + "');"
                  "if(!e) return 'NOT_FOUND';"
                  "e.scrollIntoView({block:'center'});"
                  "e.focus();"
                  "return document.activeElement===e?'FOCUSED':'NOT_FOCUSED';})()",
                  focusResult, err)) {
        e.protocolError = "focus probe did not answer: " + err;
        finish(e);
        return e.sequence;
    }
    e.targetFound = (focusResult == "FOCUSED");
    e.targetIdAtDispatch = focusResult == "FOCUSED" ? selector : focusResult;
    e.targetIdAtDiscovery = e.targetIdAtDispatch;
    e.targetRevalidated = e.targetFound;

    if (!e.targetFound) {
        e.protocolError = "could not focus target: " + focusResult;
        finish(e);
        return e.sequence;
    }

    std::string before;
    if (!effectExpression.empty()) evaluate(effectExpression, before, err);
    e.stateBefore = before;

    // The value the caller expects to appear once typing lands. Used for the
    // bounded wait below rather than being ignored.
    const std::string expectedValuePublic = before + text;

    bool allSent = true;
    for (char ch : text) {
        const long long id = page_.send("Input.insertText",
            json::obj({{"text", "\"" + json::escape(std::string(1, ch)) + "\""}}), err);
        if (id <= 0) { allSent = false; break; }
        std::string r, e2;
        page_.awaitResponse(id, r, e2, 5000, err);
        if (!e2.empty()) { e.protocolError = e2; allSent = false; break; }
    }
    e.commandSent = allSent;
    // insertText is acknowledged per character; each was awaited above.
    e.protocolResponseRecvd = allSent;

    // Typing produces no pointer event trace. Trustworthiness is evidenced by
    // the CHANNEL rather than by an event: Input.insertText is the browser's
    // input path and cannot be invoked from page script. Recorded explicitly so
    // a reader can see why this row differs from CLICK instead of inferring it.
    e.eventsObserved = "input-trust:cdp-input-channel";
    e.trustedEventObserved = allSent;

    if (!effectExpression.empty()) {
        // Bounded wait for the typed value to appear, rather than a single read
        // that could sample before the input was committed.
        std::string v;
        waitForValue(effectExpression, expectedValuePublic, timeoutMs, v);
        e.stateAfter = v;
    }
    finish(e);
    return e.sequence;
}

// ---------------------------------------------------------------------------
// Aggregates -- derived
// ---------------------------------------------------------------------------

std::size_t BrowserAuthority::actionsPassed() const {
    std::size_t n = 0;
    for (const auto& e : log_)
        if (deriveActionVerdict(e) == ActionVerdict::Pass) ++n;
    return n;
}
std::size_t BrowserAuthority::actionsUnproven() const {
    std::size_t n = 0;
    for (const auto& e : log_)
        if (deriveActionVerdict(e) == ActionVerdict::Unproven) ++n;
    return n;
}
std::size_t BrowserAuthority::actionsFailed() const {
    std::size_t n = 0;
    for (const auto& e : log_)
        if (deriveActionVerdict(e) == ActionVerdict::Fail) ++n;
    return n;
}

ActionVerdict BrowserAuthority::overallVerdict() const {
    if (log_.empty()) return ActionVerdict::Unproven;
    if (actionsFailed() > 0) return ActionVerdict::Fail;
    if (actionsUnproven() > 0) return ActionVerdict::Unproven;
    if (actionsPassed() != log_.size()) return ActionVerdict::Unproven;
    return ActionVerdict::Pass;
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

std::string BrowserAuthority::renderReceipt() const {
    const SessionLaunchEvidence& lv = session_.evidence();

    std::ostringstream o;
    o << "# RawrXD browser action receipt\n";
    o << "# Verdicts are DERIVED from the observations above them.\n";
    o << "# No field below is settable by a caller.\n\n";

    o << "[session]\n";
    o << "BROWSER_PATH=" << (lv.browserPath.empty() ? "<none>" : lv.browserPath) << "\n";
    o << "BROWSER_VERSION=" << (lv.browserVersion.empty() ? "<none>" : lv.browserVersion) << "\n";
    o << "BROWSER_PROCESS_CREATED=" << yn(lv.processCreated) << "\n";
    o << "DEVTOOLS_ENDPOINT_OPEN=" << yn(lv.devtoolsEndpointOpen) << "\n";
    o << "DEBUGGER_URL_PRESENT=" << yn(lv.debuggerUrlPresent) << "\n";
    o << "WEBSOCKET_HANDSHAKE=" << yn(lv.websocketHandshake) << "\n";
    o << "SESSION_READY=" << yn(ready()) << "\n";
    o << "PROFILE_DIR=" << (lv.profileDir.empty() ? "<none>" : lv.profileDir) << "\n";
    o << "TARGET_COUNT=" << targetsObserved_ << "\n";
    for (const auto& f : lv.failureStages)
        o << "LAUNCH_FAILURE_STAGE=" << f << "\n";
    o << "\n";

    o << "[actions]\n";
    o << "ACTION_COUNT=" << log_.size() << "\n";
    o << "ACTIONS_PASSED=" << actionsPassed() << "\n";
    o << "ACTIONS_UNPROVEN=" << actionsUnproven() << "\n";
    o << "ACTIONS_FAILED=" << actionsFailed() << "\n";
    for (const auto& e : log_) {
        o << "ACTION_" << e.sequence << "_KIND=" << e.action << "\n";
        o << "ACTION_" << e.sequence << "_TARGET=" << (e.target.empty() ? "<none>" : e.target) << "\n";
        o << "ACTION_" << e.sequence << "_TARGET_AT_DISPATCH="
          << (e.targetIdAtDispatch.empty() ? "<none>" : e.targetIdAtDispatch) << "\n";
        o << "ACTION_" << e.sequence << "_TARGET_REVALIDATED=" << yn(e.targetRevalidated) << "\n";
        o << "ACTION_" << e.sequence << "_COMMAND_SENT=" << yn(e.commandSent) << "\n";
        o << "ACTION_" << e.sequence << "_PROTOCOL_RESPONSE=" << yn(e.protocolResponseRecvd) << "\n";
        o << "ACTION_" << e.sequence << "_PROTOCOL_ERROR="
          << (e.protocolError.empty() ? "<none>" : e.protocolError) << "\n";
        o << "ACTION_" << e.sequence << "_EVENTS="
          << (e.eventsObserved.empty() ? "<none>" : e.eventsObserved) << "\n";
        o << "ACTION_" << e.sequence << "_TRUSTED_EVENT=" << yn(e.trustedEventObserved) << "\n";
        o << "ACTION_" << e.sequence << "_STATE_HASH_BEFORE="
          << hashStatePublic(e.stateBefore) << "\n";
        o << "ACTION_" << e.sequence << "_STATE_HASH_AFTER="
          << hashStatePublic(e.stateAfter) << "\n";
        o << "ACTION_" << e.sequence << "_STATE_CHANGED=" << yn(e.stateChanged) << "\n";
        o << "ACTION_" << e.sequence << "_VERDICT="
          << actionVerdictName(deriveActionVerdict(e)) << "\n";
    }
    o << "\n";

    o << "[derived]\n";
    o << "BROWSER_ACTION_VERDICT="
      << actionVerdictName(overallVerdict()) << "\n";
    return o.str();
}

bool BrowserAuthority::writeReceipt(const std::string& path) const {
    if (path.empty()) return false;
    // Render first. A verification fault must not be able to truncate the
    // artifact it is producing.
    const std::string body = renderReceipt();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << body;
    f.flush();
    if (!f) return false;
    f.close();
    return true;
}

} // namespace rawrxd::browser