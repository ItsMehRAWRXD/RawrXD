// ============================================================================
// ShellAuthority.hpp
//
// RAWRXD_SHELL_AUTHORITY_001
//
// One action envelope over four surfaces. The browser stops being a special
// case and becomes one shell surface among peers.
//
//   app://ide       -> Ide       (surface registry + workspace binding)
//   app://terminal  -> Terminal  (process authority)
//   app://browser   -> Browser   -> BrowserAuthority   (ADAPTER ONLY)
//   app://files     -> Files     (filesystem authority)
//
// ---------------------------------------------------------------------------
// THE RULE THAT SHAPED THIS FILE
// ---------------------------------------------------------------------------
// Three separate "gate that cannot pass" defects appeared while building the
// browser authority, all the same shape:
//
//     REQUIREMENT
//        ↓
//     implemented as a UNIVERSAL predicate
//        ↓
//     some valid action can never satisfy it
//        ↓
//     gate reads as strict
//        ↓
//     is actually impossible
//
// Concretely: a single `requiresTrustedEvent` applied to every action made
// NAVIGATION uncertifiable, because navigation produces no input events; and a
// type() action that never set `targetFound` could never reach PASS.
//
// So here the rule is executable, not a comment:
//
//     UNCERTIFIABLE_GATE = DEFECT
//
// Every operation declares, per operation class, WHICH evidence it must
// produce. `certifiableOperations()` then asserts that each declared
// requirement set is physically reachable -- that at least one operation in
// this binary CAN satisfy it. A requirement no operation can meet is reported
// as a DEFECT in the receipt rather than silently weakening the gate.
//
// ---------------------------------------------------------------------------
// ADAPTER LAW
// ---------------------------------------------------------------------------
//     SHELL_BROWSER_SECOND_TRANSPORT = 0
//
// The browser surface holds a BrowserAuthority and calls it. It does not own a
// socket, does not speak CDP, and does not re-derive a browser verdict. The
// five pre-existing browser stubs in this tree (AgenticBrowserLayer.cpp,
// Win32IDE_AgenticBrowser.cpp, AutonomousPuppeteer.hpp, PuppeteerAPI.hpp,
// websocket_hub.cpp) are 1-11 line placeholders with no transport between them;
// the correct fate for each is adapter/facade onto this authority, never a
// fresh implementation.
//
//     REVERSE_RECEIPT_REDERIVES_VERDICT = 0
//     REVERSE_RECEIPT_TRACES_PROVENANCE  = 1
//
// The reverse section walks evidence that was already recorded. It never
// recomputes an action verdict, because a second computation of the same
// question is how two parsers came to disagree about one artifact earlier in
// this repository.
// ============================================================================

#ifndef RAWRXD_SHELL_SHELLAUTHORITY_HPP
#define RAWRXD_SHELL_SHELLAUTHORITY_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "browser/BrowserAuthority.hpp"

namespace rawrxd::shell {

enum class ShellSurfaceKind { Ide, Terminal, Browser, Files };

inline const char* surfaceKindName(ShellSurfaceKind k) {
    switch (k) {
        case ShellSurfaceKind::Ide:      return "IDE";
        case ShellSurfaceKind::Terminal: return "TERMINAL";
        case ShellSurfaceKind::Browser:  return "BROWSER";
        case ShellSurfaceKind::Files:    return "FILES";
    }
    return "?";
}

struct ShellSurfaceId {
    std::uint64_t value = 0;
    bool operator==(const ShellSurfaceId& o) const noexcept {
        return value == o.value;
    }
};

struct ShellSurface {
    ShellSurfaceId    id;
    ShellSurfaceKind  kind = ShellSurfaceKind::Ide;
    std::string       uri;
    std::uint64_t     generation = 0;
    bool              alive = false;
    // "interactive" means the surface can accept an action and return an
    // observation. A registered-but-inert surface is alive and NOT
    // interactive, and those two states must not be conflated.
    bool              interactive = false;
};

// One envelope. Every surface takes the same shape.
struct ShellAction {
    ShellSurfaceId surface;
    std::string    operation;    // NAVIGATE / CLICK / TYPE / EXISTS / READ / SIZE
    std::string    target;       // selector, path, uri...
    std::string    payload;      // text to type, expected value...
    std::uint64_t  sequence = 0;
};

// What an operation class must produce before it may PASS.
struct EvidenceRequirement {
    bool requiresSurfaceAlive    = false;
    bool requiresSurfaceInteractive = false;
    bool requiresTargetFound     = false;
    bool requiresTrustedEvent    = false;
    bool requiresStateChange     = false;
    bool requiresNonEmptyPayload = false;   // e.g. a file that actually has bytes
};

struct ShellActionEvidence {
    std::uint64_t sequence = 0;
    ShellSurfaceKind kind = ShellSurfaceKind::Ide;
    std::string surfaceUri;
    std::string operation;
    std::string target;

    EvidenceRequirement requirement;

    bool surfaceAlive       = false;
    bool surfaceInteractive = false;
    bool targetFound        = false;
    bool targetRevalidated  = false;
    bool trustedEvent       = false;
    bool stateChanged       = false;

    std::string before;
    std::string after;
    std::string detail;           // per-surface measured detail

    bool dispatched = false;
    std::string error;
};

enum class ShellVerdict { Fail, Unproven, Pass };

inline const char* shellVerdictName(ShellVerdict v) {
    switch (v) {
        case ShellVerdict::Fail:     return "FAIL";
        case ShellVerdict::Unproven: return "UNPROVEN";
        case ShellVerdict::Pass:     return "PASS";
    }
    return "?";
}

// DERIVED per operation class, never stored, never settable.
//
// Each clause is gated on whether THIS operation declared it. That is the
// direct fix for the three impossible gates: a universal predicate is exactly
// what made navigation uncertifiable and typing unreachable.
inline ShellVerdict deriveShellVerdict(const ShellActionEvidence& e) {
    if (!e.error.empty())                   return ShellVerdict::Fail;
    if (!e.dispatched)                      return ShellVerdict::Fail;
    if (e.requirement.requiresSurfaceAlive && !e.surfaceAlive)
                                               return ShellVerdict::Unproven;
    if (e.requirement.requiresSurfaceInteractive && !e.surfaceInteractive)
                                               return ShellVerdict::Unproven;
    if (e.requirement.requiresTargetFound && !e.targetFound)
                                               return ShellVerdict::Unproven;
    if (e.requirement.requiresTrustedEvent && !e.trustedEvent)
                                               return ShellVerdict::Unproven;
    if (e.requirement.requiresNonEmptyPayload && e.after.empty())
                                               return ShellVerdict::Unproven;
    if (e.requirement.requiresStateChange && !e.stateChanged)
                                               return ShellVerdict::Unproven;
    return ShellVerdict::Pass;
}

// ---------------------------------------------------------------------------
// The authority
// ---------------------------------------------------------------------------
class ShellAuthority {
public:
    ShellAuthority() = default;
    ~ShellAuthority();
    ShellAuthority(const ShellAuthority&) = delete;
    ShellAuthority& operator=(const ShellAuthority&) = delete;

    // Registers a surface. Registration alone does NOT make a surface
    // interactive: an inert surface is a registered surface, and saying
    // otherwise is how "SUPPORTED" claims arise.
    ShellSurfaceId registerSurface(ShellSurfaceKind kind,
                                   const std::string& uri,
                                   bool interactive);

    // Brings the browser surface up by delegating to BrowserAuthority.
    bool launchBrowser(const std::string& browserPath,
                       const std::string& profileDir,
                       bool headless, std::string& err);

    // Attaches a page to the already-launched browser and, only on success,
    // marks the browser surface interactive. Called BEFORE any browser action
    // is dispatched, so an action never has to smuggle a URL through its
    // parameter field.
    bool openBrowserPage(const std::string& url, std::string& err);

    bool surfacesReady() const { return !surfaces_.empty(); }
    std::size_t surfaceCount() const { return surfaces_.size(); }
    const std::vector<ShellSurface>& surfaces() const { return surfaces_; }

    // Resolves a URI to a registered surface id. Returns false for an
    // unregistered URI rather than defaulting to surface 0 -- a bridge that
    // defaulted would let an intent naming nothing reach surface zero.
    bool surfaceIdForUri(const std::string& uri, ShellSurfaceId& out) const;

    // Dispatches one action and records its evidence. Returns the sequence, or
    // 0 when the surface is unknown.
    std::uint64_t dispatch(const ShellAction& action);

    const std::vector<ShellActionEvidence>& log() const { return log_; }
    ShellVerdict overallVerdict() const;

    std::string renderReceipt() const;
    bool writeReceipt(const std::string& path) const;

    // UNCERTIFIABLE_GATE=DEFECT, executed.
    //
    // Returns the requirements declared by any operation in this binary that no
    // operation class can satisfy. A non-empty result means the gate contains an
    // impossible predicate and the receipt reports it as a DEFECT rather than
    // quietly lowering the bar.
    std::vector<std::string> uncertifiableRequirements() const;

    void close();

private:
    struct Impl;
    Impl* impl_ = nullptr;                 // owns the browser authority

    std::vector<ShellSurface> surfaces_;
    std::vector<ShellActionEvidence> log_;
    std::uint64_t nextSeq_ = 1;

    const ShellSurface* findSurface(ShellSurfaceId id) const;
    ShellSurface* findSurfaceMutable(ShellSurfaceId id);

    EvidenceRequirement requirementFor(ShellSurfaceKind kind,
                                       const std::string& operation) const;

    bool runFiles(const ShellActionEvidence& e, std::string& before,
                  std::string& after, std::string& detail, std::string& err);
    void runBrowser(const ShellAction& a, ShellActionEvidence& e);
    void runIde(const ShellAction& a, ShellActionEvidence& e);
    void runTerminal(const ShellAction& a, ShellActionEvidence& e);
};

} // namespace rawrxd::shell

#endif // RAWRXD_SHELL_SHELLAUTHORITY_HPP