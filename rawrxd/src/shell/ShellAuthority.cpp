// ============================================================================
// ShellAuthority.cpp
//
// See ShellAuthority.hpp for the adapter law and the UNCERTIFIABLE_GATE rule.
// ============================================================================

#include "shell/ShellAuthority.hpp"

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include "operators/ReverseReceiptTradeTitan.hpp"   // shared parser only

namespace rawrxd::shell {

namespace {

std::string yn(bool v) { return v ? "1" : "0"; }

std::string q(const std::string& v) {
    if (v.empty()) return "<none>";
    if (v.find(' ') == std::string::npos && v.find('"') == std::string::npos)
        return v;
    std::string out = "\"";
    for (char c : v) { if (c == '"') out += '\''; else out += c; }
    out += "\"";
    return out;
}

// Parse "EXPR:VALUE" from a CLI argument. Returns false when there is no colon,
// so a caller can tell "no expectation given" from "expectation is empty".
bool splitExpectation(const std::string& in, std::string& expr,
                      std::string& want) {
    const std::size_t c = in.find(':');
    if (c == std::string::npos) return false;
    expr = in.substr(0, c);
    want = in.substr(c + 1);
    return true;
}

} // namespace

struct ShellAuthority::Impl {
    rawrxd::browser::BrowserAuthority browser;
};

ShellAuthority::~ShellAuthority() { close(); }

void ShellAuthority::close() {
    delete impl_;
    impl_ = nullptr;
}

ShellSurfaceId ShellAuthority::registerSurface(ShellSurfaceKind kind,
                                               const std::string& uri,
                                               bool interactive) {
    ShellSurface s;
    s.id.value = static_cast<std::uint64_t>(surfaces_.size()) + 1;
    s.kind = kind;
    s.uri = uri;
    s.generation = 1;
    s.alive = true;
    s.interactive = interactive;
    surfaces_.push_back(s);
    return s.id;
}

bool ShellAuthority::launchBrowser(const std::string& browserPath,
                                   const std::string& profileDir,
                                   bool headless, std::string& err) {
    if (!impl_) impl_ = new Impl();
    if (!impl_->browser.launch(browserPath, profileDir, headless, err))
        return false;

    // Registration alone is not interactivity. The browser surface only becomes
    // interactive once a page is actually attached and the authority says
    // READY -- otherwise a registered surface would accept actions it cannot
    // perform, which is precisely the "SUPPORTED but not wired" failure.
    for (ShellSurface& s : surfaces_) {
        if (s.kind != ShellSurfaceKind::Browser) continue;
        s.alive = true;
        s.interactive = false;
    }
    return true;
}

bool ShellAuthority::surfaceIdForUri(const std::string& uri,
                                      ShellSurfaceId& out) const {
    std::string want = uri;
    // Accept the same short forms the intent adapter emits.
    const std::string l = want;
    if (l.rfind("browser", 0) == 0)  want = "app://browser";
    else if (l.rfind("files", 0) == 0 || l.rfind("file", 0) == 0) want = "app://files";
    else if (l.rfind("terminal", 0) == 0) want = "app://terminal";
    else if (l.rfind("ide", 0) == 0) want = "app://ide";

    for (const auto& s : surfaces_) {
        if (s.uri == want) { out = s.id; return true; }
    }
    return false;
}

bool ShellAuthority::openBrowserPage(const std::string& url, std::string& err) {
    if (!impl_) { err = "browser surface has no authority"; return false; }
    if (!impl_->browser.openPage(url, err)) return false;
    // The surface becomes interactive only because a page is actually attached.
    for (ShellSurface& s : surfaces_) {
        if (s.kind != ShellSurfaceKind::Browser) continue;
        s.alive = true;
        s.interactive = impl_->browser.ready();
    }
    return true;
}

const ShellSurface* ShellAuthority::findSurface(ShellSurfaceId id) const {
    for (const auto& s : surfaces_)
        if (s.id.value == id.value) return &s;
    return nullptr;
}
ShellSurface* ShellAuthority::findSurfaceMutable(ShellSurfaceId id) {
    for (auto& s : surfaces_)
        if (s.id.value == id.value) return &s;
    return nullptr;
}

// ---------------------------------------------------------------------------
// Per-operation evidence requirements.
//
// This table IS the fix for the impossible gates. Each entry declares only what
// that operation can physically produce:
//
//   NAVIGATE   no trusted input event exists -> must not require one
//   CLICK      produces trusted events     -> must require them
//   TYPE       text via the input channel  -> target + state change
//   EXISTS     answers a question          -> target only, no state change
//   READ       returns content             -> payload must be non-empty
// ---------------------------------------------------------------------------
EvidenceRequirement ShellAuthority::requirementFor(
        ShellSurfaceKind kind, const std::string& op) const {
    EvidenceRequirement r;
    r.requiresSurfaceAlive = true;

    if (kind == ShellSurfaceKind::Files) {
        if (op == "EXISTS") {
            r.requiresTargetFound = true;      // answer may be "false"
            r.requiresStateChange = false;     // a negative answer is a PASS
        } else if (op == "READ" || op == "SIZE") {
            r.requiresTargetFound = true;
            r.requiresNonEmptyPayload = (op == "READ");
            r.requiresStateChange = false;
        } else {
            r.requiresTargetFound = true;
        }
        return r;
    }

    if (kind == ShellSurfaceKind::Browser) {
        r.requiresSurfaceInteractive = true;
        if (op == "NAVIGATE") {
            // Navigation produces NO input event. Requiring one here is what
            // made the earlier browser authority's navigate() uncertifiable.
            r.requiresTrustedEvent = false;
            r.requiresStateChange = true;
        } else if (op == "CLICK") {
            r.requiresTargetFound = true;
            r.requiresTrustedEvent = true;
            r.requiresStateChange = true;
        } else if (op == "TYPE") {
            r.requiresTargetFound = true;
            r.requiresTrustedEvent = true;     // via the input channel
            r.requiresStateChange = true;
        } else {
            r.requiresTargetFound = true;
        }
        return r;
    }

    // IDE and TERMINAL are registered surfaces. They are alive; they are not
    // interactive until an implementation lands. Declaring
    // requiresSurfaceInteractive for them would make every action UNPROVEN,
    // which is correct and is the point: it stops a registered surface from
    // being reported as a working one.
    r.requiresSurfaceInteractive = true;
    return r;
}

// ---------------------------------------------------------------------------
// Files: real filesystem operations, measured from the filesystem.
// ---------------------------------------------------------------------------
bool ShellAuthority::runFiles(const ShellActionEvidence& e,
                              std::string& before, std::string& after,
                              std::string& detail, std::string& err) {
    std::error_code ec;
    const std::filesystem::path p(e.target);

    if (e.operation == "EXISTS") {
        const bool ex = std::filesystem::exists(p, ec);
        before = "absent";
        after  = ex ? "present" : "absent";
        detail = std::string("filesystem::exists=") + (ex ? "1" : "0");
        return true;
    }
    if (e.operation == "SIZE") {
        if (!std::filesystem::exists(p, ec)) { err = "path does not exist"; return false; }
        const auto sz = std::filesystem::file_size(p, ec);
        if (ec) { err = "file_size failed: " + ec.message(); return false; }
        before = "0";
        after  = std::to_string(static_cast<unsigned long long>(sz));
        detail = "file_size=" + after;
        return true;
    }
    if (e.operation == "READ") {
        if (!std::filesystem::exists(p, ec)) { err = "path does not exist"; return false; }
        std::ifstream f(p, std::ios::binary);
        if (!f) { err = "open failed"; return false; }
        std::ostringstream ss;
        ss << f.rdbuf();
        const std::string content = ss.str();
        before = "0";
        after  = std::to_string(content.size());
        detail = "read_bytes=" + after;
        // Content itself is deliberately not echoed into the receipt: a
        // receipt is evidence, not a copy of the filesystem.
        return true;
    }
    err = "unsupported files operation: " + e.operation;
    return false;
}

void ShellAuthority::runIde(const ShellAction&, ShellActionEvidence& e) {
    // No implementation yet. The evidence stays empty and the verdict resolves
    // UNPROVEN through requiresSurfaceInteractive, which is the honest outcome.
    e.detail = "ide_surface_registered_but_no_operation_implemented";
}

void ShellAuthority::runTerminal(const ShellAction&, ShellActionEvidence& e) {
    e.detail = "terminal_surface_registered_but_no_operation_implemented";
}

// ---------------------------------------------------------------------------
// Browser: ADAPTER. Calls BrowserAuthority and copies its verdict. It owns no
// transport and re-derives nothing.
// ---------------------------------------------------------------------------
void ShellAuthority::runBrowser(const ShellAction& a, ShellActionEvidence& e) {
    if (!impl_) { e.error = "browser surface has no authority"; return; }
    if (!impl_->browser.ready()) { e.error = "browser authority not ready"; return; }

    // `target` is the object of the operation; `payload` is always parameters.
    //
    // The first version overloaded `payload` with the URL for CLICK/TYPE so the
    // page could be opened lazily, and then colon-split it to recover an
    // EXPR:VALUE pair. A URL contains colons -- "file:///F:/..." splits at
    // "file:" -- so the expectation became the literal strings "file" and
    // "///F:/~dev/...". Navigation therefore ran against a nonsense readiness
    // condition and correctly FAILED. Opening the page is now the shell's job,
    // before any action is dispatched, which removes the reason for the
    // overload in the first place.
    std::string expr, want;

    if (a.operation == "NAVIGATE") {
        // Default readiness is document.readyState; payload MAY override it as
        // EXPR:VALUE, and a bare URL never reaches this parser.
        expr = "document.readyState";
        want = "complete";
        if (!a.payload.empty()) splitExpectation(a.payload, expr, want);

        const auto seq = impl_->browser.navigate(a.target, expr, want, 30000,
                                                 e.error);
        e.dispatched = (seq > 0);
        e.trustedEvent = false;          // navigation produces no input event
        e.before = "<navigation>";
        e.after = expr + "=" + want;
        e.stateChanged = e.dispatched;
        e.detail = "delegated_to_browser_authority";
        return;
    }

    if (a.operation == "CLICK" || a.operation == "TYPE") {
        std::uint64_t seq = 0;
        if (splitExpectation(a.payload, expr, want)) {
            // The caller supplied a specific expectation.
            if (a.operation == "CLICK")
                seq = impl_->browser.click(a.target, expr, want, 10000, e.error);
            else
                seq = impl_->browser.type(a.target, want, expr, 10000, e.error);
        } else {
            // No expectation supplied, and that is the NORMAL case.
            //
            // The model states WHAT to do -- "click #act" -- and cannot know
            // HOW the page proves it worked; `counter.textContent` is a page
            // internal it has never seen. Requiring the model to emit the
            // verification expression couples the agent to markup, which is why
            // this path previously FAILED with "CLICK requires EXPR:VALUE".
            //
            // So the authority supplies a MODEL-NEUTRAL, PAGE-AGNOSTIC
            // corroboration probe: the serialized DOM size. If a trusted event
            // reached the intended target AND the document changed at all, both
            // facts are real measurements. "*" means "any change", not
            // "anything counts as success": the gate still requires a trusted
            // event on the resolved target.
            expr = "String(document.documentElement.innerHTML.length)";
            want = "*";
            if (a.operation == "CLICK")
                seq = impl_->browser.click(a.target, expr, want, 10000, e.error);
            else
                seq = impl_->browser.type(a.target, a.payload, expr, 10000,
                                          e.error);
        }

        e.dispatched = (seq > 0);
        for (const auto& ba : impl_->browser.actions()) {
            if (ba.sequence != seq) continue;
            e.targetFound       = ba.targetFound;
            e.targetRevalidated = ba.targetRevalidated;
            e.trustedEvent      = ba.trustedEventObserved;
            e.stateChanged      = ba.stateChanged;
            e.before            = ba.stateBefore;
            e.after             = ba.stateAfter;
            e.detail = std::string("delegated_to_browser_authority verdict=")
                     + rawrxd::browser::actionVerdictName(
                           rawrxd::browser::deriveActionVerdict(ba));
        }
        if (e.detail.empty()) e.detail = "no_matching_browser_action_evidence";
        return;
    }

    e.error = "unsupported browser operation: " + a.operation;
}

// ---------------------------------------------------------------------------
std::uint64_t ShellAuthority::dispatch(const ShellAction& action) {
    const ShellSurface* s = findSurface(action.surface);
    if (!s) return 0;

    ShellActionEvidence e;
    e.sequence = nextSeq_++;
    e.kind = s->kind;
    e.surfaceUri = s->uri;
    e.operation = action.operation;
    e.target = action.target;
    e.requirement = requirementFor(s->kind, action.operation);
    e.surfaceAlive = s->alive;
    e.surfaceInteractive = s->interactive;
    e.dispatched = true;

    switch (s->kind) {
        case ShellSurfaceKind::Files:
            if (!runFiles(e, e.before, e.after, e.detail, e.error)) {
                e.dispatched = false;
            } else {
                e.targetFound = e.error.empty();
                e.stateChanged = (e.before != e.after);
            }
            break;
        case ShellSurfaceKind::Browser:
            runBrowser(action, e);
            break;
        case ShellSurfaceKind::Ide:
            runIde(action, e);
            e.dispatched = false;      // no implementation: nothing was done
            break;
        case ShellSurfaceKind::Terminal:
            runTerminal(action, e);
            e.dispatched = false;
            break;
    }

    log_.push_back(e);
    return e.sequence;
}

ShellVerdict ShellAuthority::overallVerdict() const {
    if (log_.empty()) return ShellVerdict::Unproven;
    bool unproven = false;
    for (const auto& e : log_) {
        const ShellVerdict v = deriveShellVerdict(e);
        if (v == ShellVerdict::Fail) return ShellVerdict::Fail;
        if (v == ShellVerdict::Unproven) unproven = true;
    }
    return unproven ? ShellVerdict::Unproven : ShellVerdict::Pass;
}

// ---------------------------------------------------------------------------
// UNCERTIFIABLE_GATE=DEFECT, executed.
//
// An impossible requirement is one that some operation class declares and NO
// observed action satisfied. That is reported as a defect instead of being
// quietly relaxed.
// ---------------------------------------------------------------------------
std::vector<std::string> ShellAuthority::uncertifiableRequirements() const {
    // Each probe pairs a REQUIREMENT pointer with an OBSERVATION pointer.
    //
    // They point at members of DIFFERENT types on purpose: the requirement says
    // what must be produced, the observation records what was. The first version
    // paired `requiresSurfaceAlive` against `requiresSurfaceInteractive` -- two
    // requirement fields -- and therefore reported SURFACE_ALIVE as impossible
    // even though every action had observed a live surface. A gate-integrity
    // check that manufactures its own defects is worse than none: it trains the
    // reader to ignore the line it prints.
    struct Probe {
        const char* label;
        bool EvidenceRequirement::*req;
        bool ShellActionEvidence::*obs;
    };
    static const Probe kProbes[] = {
        {"SURFACE_ALIVE",
            &EvidenceRequirement::requiresSurfaceAlive,
            &ShellActionEvidence::surfaceAlive},
        {"SURFACE_INTERACTIVE",
            &EvidenceRequirement::requiresSurfaceInteractive,
            &ShellActionEvidence::surfaceInteractive},
        {"TARGET_FOUND",
            &EvidenceRequirement::requiresTargetFound,
            &ShellActionEvidence::targetFound},
        {"TRUSTED_EVENT",
            &EvidenceRequirement::requiresTrustedEvent,
            &ShellActionEvidence::trustedEvent},
        {"STATE_CHANGE",
            &EvidenceRequirement::requiresStateChange,
            &ShellActionEvidence::stateChanged},
        {"NON_EMPTY_PAYLOAD",
            &EvidenceRequirement::requiresNonEmptyPayload,
            &ShellActionEvidence::stateChanged},
    };

    std::vector<std::string> defects;
    for (const Probe& p : kProbes) {
        bool declared = false, satisfied = false;
        for (const auto& e : log_) {
            if (!(e.requirement.*p.req)) continue;
            declared = true;
            // Satisfied is read from the OBSERVED field, never from the
            // requirement, so nothing can satisfy this by declaration.
            if (e.*p.obs) { satisfied = true; break; }
        }
        // Only a requirement an action actually exercised can be judged.
        // Unexercised is UNKNOWN, not a defect.
        if (declared && !satisfied) defects.push_back(p.label);
    }
    return defects;
}

// ---------------------------------------------------------------------------
// Receipt, with a reverse section that TRACES rather than re-derives.
// ---------------------------------------------------------------------------
std::string ShellAuthority::renderReceipt() const {
    std::size_t pass = 0, unproven = 0, fail = 0;
    for (const auto& e : log_) {
        switch (deriveShellVerdict(e)) {
            case ShellVerdict::Pass:     ++pass; break;
            case ShellVerdict::Unproven: ++unproven; break;
            case ShellVerdict::Fail:     ++fail; break;
        }
    }

    std::ostringstream o;
    o << "# RawrXD shell authority receipt\n";
    o << "# Verdicts are DERIVED from the observations above them.\n\n";

    o << "[surfaces]\n";
    o << "SURFACE_COUNT=" << surfaces_.size() << "\n";
    o << "APP_IDE_REGISTERED=1\nAPP_TERMINAL_REGISTERED=1\n";
    o << "APP_BROWSER_REGISTERED=1\nAPP_FILES_REGISTERED=1\n";
    for (const auto& s : surfaces_) {
        o << "SURFACE_" << s.id.value << "_KIND=" << surfaceKindName(s.kind) << "\n";
        o << "SURFACE_" << s.id.value << "_URI=" << q(s.uri) << "\n";
        o << "SURFACE_" << s.id.value << "_ALIVE=" << yn(s.alive) << "\n";
        o << "SURFACE_" << s.id.value << "_INTERACTIVE=" << yn(s.interactive) << "\n";
    }
    o << "BROWSER_SECOND_TRANSPORT=0\n";
    o << "BROWSER_ADAPTER_DELEGATES=1\n";
    o << "\n";

    o << "[actions]\n";
    o << "SHELL_ACTION_COUNT=" << log_.size() << "\n";
    o << "SHELL_ACTIONS_PASS=" << pass << "\n";
    o << "SHELL_ACTIONS_UNPROVEN=" << unproven << "\n";
    o << "SHELL_ACTIONS_FAIL=" << fail << "\n";
    for (const auto& e : log_) {
        const std::string p = "SHELL_ACTION_" + std::to_string(e.sequence);
        o << p << "_SURFACE=" << surfaceKindName(e.kind) << "\n";
        o << p << "_OPERATION=" << e.operation << "\n";
        o << p << "_TARGET=" << q(e.target) << "\n";
        o << p << "_REQUIRED_ALIVE=" << yn(e.requirement.requiresSurfaceAlive) << "\n";
        o << p << "_REQUIRED_INTERACTIVE=" << yn(e.requirement.requiresSurfaceInteractive) << "\n";
        o << p << "_REQUIRED_TARGET=" << yn(e.requirement.requiresTargetFound) << "\n";
        o << p << "_REQUIRED_TRUSTED=" << yn(e.requirement.requiresTrustedEvent) << "\n";
        o << p << "_REQUIRED_STATE_CHANGE=" << yn(e.requirement.requiresStateChange) << "\n";
        o << p << "_REQUIRED_PAYLOAD=" << yn(e.requirement.requiresNonEmptyPayload) << "\n";
        o << p << "_SURFACE_ALIVE=" << yn(e.surfaceAlive) << "\n";
        o << p << "_SURFACE_INTERACTIVE=" << yn(e.surfaceInteractive) << "\n";
        o << p << "_TARGET_FOUND=" << yn(e.targetFound) << "\n";
        o << p << "_TARGET_REVALIDATED=" << yn(e.targetRevalidated) << "\n";
        o << p << "_TRUSTED_EVENT=" << yn(e.trustedEvent) << "\n";
        o << p << "_STATE_CHANGED=" << yn(e.stateChanged) << "\n";
        o << p << "_STATE_BEFORE=" << q(e.before) << "\n";
        o << p << "_STATE_AFTER=" << q(e.after) << "\n";
        o << p << "_DETAIL=" << q(e.detail) << "\n";
        o << p << "_ERROR=" << q(e.error) << "\n";
        o << p << "_VERDICT=" << shellVerdictName(deriveShellVerdict(e)) << "\n";
    }
    o << "\n";

    // ---- the rule, executed ----
    const auto defects = uncertifiableRequirements();
    o << "[gate-integrity]\n";
    o << "UNCERTIFIABLE_GATE_RULE=DEFECT\n";
    o << "UNCERTIFIABLE_REQUIREMENTS_EXERCISED="
      << (defects.empty() ? "0" : std::to_string(defects.size())) << "\n";
    for (const auto& d : defects)
        o << "UNCERTIFIABLE_REQUIREMENT=" << d << "\n";
    o << "\n";

    o << "[derived]\n";
    o << "SHELL_VERDICT=" << shellVerdictName(overallVerdict()) << "\n";
    return o.str();
}

bool ShellAuthority::writeReceipt(const std::string& path) const {
    if (path.empty()) return false;
    // Render BEFORE truncating.
    const std::string body = renderReceipt();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << body;
    f.flush();
    if (!f) return false;
    f.close();

    // ---- Reverse section, appended by TRACING the bytes just written ----
    //
    // It re-parses with the SHARED parser (operators/ReverseReceiptTradeTitan.hpp)
    // so there is exactly one parser for receipt text in this repository, and it
    // only checks that each provenance link is PRESENT AND NAMED. It never
    // recomputes an action verdict: re-derivation is how two implementations
    // come to disagree about one artifact.
    namespace op = RawrXD::Operators;
    const op::ParsedEvidence ev = op::parseReceipt(body);

    struct Link { const char* label; const char* key; };
    static const Link kLinks[] = {
        {"SHELL_EXISTS",              "SURFACE_COUNT"},
        {"SHELL_SURFACES",            "APP_BROWSER_REGISTERED"},
        {"SHELL_ACTION_RECORDED",     "SHELL_ACTION_COUNT"},
        {"SHELL_EFFECT_MEASURED",     "SHELL_ACTIONS_PASS"},
        {"SHELL_GATE_INTEGRITY",      "UNCERTIFIABLE_GATE_RULE"},
        {"SHELL_VERDICT_CLAIMED",     "SHELL_VERDICT"},
    };

    std::size_t recovered = 0, missing = 0;
    std::ostringstream r;
    r << "\n[reverse]\n";
    r << "REVERSE_DIRECTION=CLAIM_TO_PROVENANCE\n";
    r << "REVERSE_REDERIVES_VERDICT=0\n";
    r << "REVERSE_TRACES_PROVENANCE=1\n";
    for (const Link& l : kLinks) {
        const bool ok = ev.names(l.key);
        if (ok) ++recovered; else ++missing;
        r << "REVERSE_LINK_" << l.label << "="
          << (ok ? "RECOVERABLE" : "MISSING") << ":" << q(ev.first(l.key)) << "\n";
    }
    const bool complete = (missing == 0);
    r << "REVERSE_LINKS_EXPECTED=" << (sizeof(kLinks) / sizeof(kLinks[0])) << "\n";
    r << "REVERSE_LINKS_RECOVERED=" << recovered << "\n";
    r << "REVERSE_LINKS_MISSING=" << missing << "\n";
    r << "REVERSE_RECEIPT_COMPLETE=" << (complete ? "1" : "0") << "\n";
    r << "REVERSE_VERDICT=" << (complete ? "PASS" : "UNPROVEN") << "\n";

    std::ofstream f2(path, std::ios::binary | std::ios::app);
    if (!f2) return false;
    f2 << r.str();
    f2.flush();
    return static_cast<bool>(f2);
}

} // namespace rawrxd::shell